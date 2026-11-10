"""Offline collection from a 389-ds id2entry.db database file.

Every record in id2entry.db is an LDIF-style text blob that carries the full
entry (the ``dsEntryDN`` attribute holds the complete DN, so the entryrdn
hierarchy is not needed). This module parses those records into the same
shape a live LDAP search produces and classifies entries into the buckets
declared by ``LDAPPathConfig.PATHS`` (all its filters are plain
``(objectClass=X)``, which maps directly onto a set membership test).

The resulting ``DBCollector.results`` has the same structure as
``LDAPCollector.results`` ({type_name: [entries]}), so ``main`` can feed it
into the unmodified ``dump_ldap_to_json`` pipeline.
"""

import base64
import logging
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from ipahound.lib.bdb_reader import BdbBtreeReader, BdbError
from ipahound.main import LDAPPathConfig

# 389-ds replication subtypes (adcsn-<csn>, vucsn-<csn>, ...) are internal
# bookkeeping, not real LDAP attribute options: strip them while keeping
# semantic options such as binary / read_keys / write_keys intact.
CSN_OPTION_RE = re.compile(r"^[a-zA-Z]+csn-")

# ldap3 converts integer-syntax attributes to int; krbTicketFlags is used in
# bitwise checks downstream (consts.process_attributes) and must not stay a
# string, the rest are converted for parity with a live dump.
INT_ATTRIBUTES = {"krbTicketFlags", "uidNumber", "gidNumber", "krbLoginFailedCount"}

OBJECTCLASS_FILTER_RE = re.compile(r"^\(\s*objectClass\s*=\s*([^()=*]+?)\s*\)$", re.IGNORECASE)

AttributeValues = List[Union[str, bytes]]


def _unfold_ldif_lines(raw: bytes) -> List[bytes]:
    """Split a record into logical LDIF lines, joining folded continuations."""
    logical: List[bytes] = []
    for raw_line in raw.split(b"\n"):
        if raw_line.startswith(b" "):
            if logical:
                logical[-1] += raw_line[1:]
            continue
        logical.append(raw_line)
    return logical


def _normalize_attribute_name(name: str) -> Optional[str]:
    """Strip CSN subtypes from an attribute name.

    Returns None for tombstone lines (``attr;...;deletedattribute;deleted:``)
    which carry deleted values invisible to a live LDAP search.
    """
    parts = name.split(";")
    base = parts[0]
    options = []
    for option in parts[1:]:
        if option.strip().lower() in ("deletedattribute", "deleted"):
            return None
        if CSN_OPTION_RE.match(option.strip()):
            continue
        options.append(option.strip())

    if not options:
        return base
    return base + ";" + ";".join(options)


def _decode_value(name: str, encoded: bool, value: str) -> Union[str, bytes]:
    if encoded:
        try:
            decoded = base64.b64decode(value, validate=False)
        except Exception:
            return value
        # id2entry uses "::" for any LDIF-unsafe value, not only binary ones
        # (e.g. ipaAnchorUUID starting with ':'): keep text as text the way
        # ldap3 would return it, leave real binary blobs (keys, hashes,
        # certificates) as bytes.
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded

    if name in INT_ATTRIBUTES and value.isascii() and value.isdigit():
        return int(value)

    return value


def parse_entry_record(raw: bytes) -> Dict[str, AttributeValues]:
    """Parse one id2entry.db record into {attribute: [values]}.

    ``rdn`` is an id2entry-internal attribute and is dropped; ``dsEntryDN``
    is kept (the caller uses it as the entry DN and removes it afterwards).
    """
    attributes: Dict[str, AttributeValues] = {}

    for raw_line in _unfold_ldif_lines(raw.rstrip(b"\x00")):
        if not raw_line.strip():
            continue

        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError:
            logging.debug("Skipping non-UTF-8 line in database record")
            continue

        separator = line.find(":")
        if separator <= 0:
            logging.debug(f"Skipping malformed database record line: {line[:40]}")
            continue

        name = _normalize_attribute_name(line[:separator])
        if name is None or name.lower() == "rdn":
            continue

        rest = line[separator + 1:]
        encoded = rest.startswith(":")
        if encoded:
            rest = rest[1:]
        value = rest[1:] if rest.startswith(" ") else rest

        attributes.setdefault(name, []).append(
            _decode_value(name, encoded, value.strip("\r"))
        )

    return attributes


class DbAttribute:

    def __init__(self, values: AttributeValues):
        self.values = values

    @property
    def value(self):
        # Mirrors ldap3's Attribute.value: single value, full list when
        # multi-valued, None when the attribute is empty.
        if not self.values:
            return None
        return self.values[0] if len(self.values) == 1 else self.values


class DbEntry:
    """Minimal ldap3-entry shim so _process_entry_attributes works unmodified."""

    def __init__(self, dn: str, attributes: Dict[str, AttributeValues]):
        self.entry_dn = dn
        self.entry_attributes = list(attributes.keys())
        self._attributes = attributes

    def __getitem__(self, name: str) -> DbAttribute:
        return DbAttribute(self._attributes[name])


def split_dn(dn: str) -> List[str]:
    """Split a DN into components honouring backslash-escaped commas."""
    parts: List[str] = []
    current: List[str] = []
    escaped = False

    for char in dn:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)

    parts.append("".join(current))
    return parts


def dn_matches(dn: str, search_base: str, scope: str) -> bool:
    dn_parts = [part.lower() for part in split_dn(dn)]
    base_parts = [part.lower() for part in split_dn(search_base)]

    if scope == "BASE":
        return dn_parts == base_parts
    if len(dn_parts) < len(base_parts):
        return False
    return dn_parts[-len(base_parts):] == base_parts


def objectclass_from_filter(ldap_filter: str) -> Optional[str]:
    match = OBJECTCLASS_FILTER_RE.match(ldap_filter.strip())
    return match.group(1) if match else None


def collect_entries(
    values: Iterable[bytes]
) -> Tuple[List[Tuple[str, Dict[str, AttributeValues], Set[str]]], Optional[str]]:
    """Parse raw records into (dn, attributes, objectclasses) tuples.

    Returns the tuples along with the detected base DN (entry with
    objectClass=domain, shortest DN wins) or None when no domain entry
    exists - in that case the file is not a FreeIPA database.
    """
    entries: List[Tuple[str, Dict[str, AttributeValues], Set[str]]] = []

    for raw in values:
        attributes = parse_entry_record(raw)
        object_classes = {
            value.lower()
            for value in attributes.get("objectClass", [])
            if isinstance(value, str)
        }
        if "nstombstone" in object_classes:
            logging.debug("Skipping tombstone database record")
            continue

        dn_values = attributes.get("dsEntryDN", [])
        if not dn_values or not isinstance(dn_values[0], str):
            logging.debug("Skipping database record without dsEntryDN")
            continue

        entries.append((dn_values[0], attributes, object_classes))

    domain_dns = [
        dn for dn, _, classes in entries
        if "domain" in classes and "dc=" in dn.lower()
    ]
    base_dn = min(domain_dns, key=len) if domain_dns else None

    return entries, base_dn


class DBCollector:
    """Duck-typed counterpart of LDAPCollector reading from id2entry.db."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.results: Dict[str, List[DbEntry]] = {}
        self.ldap_paths = LDAPPathConfig.PATHS

    def dump_db_data(self) -> bool:
        if not os.path.isfile(self.db_path):
            logging.error(f"Database file not found: {self.db_path}")
            return False

        try:
            reader = BdbBtreeReader(self.db_path)
            entries, base_dn = collect_entries(value for _, value in reader.items())
        except (BdbError, OSError) as err:
            logging.error(f"Failed to read database file {self.db_path}: {err}")
            return False

        if not entries:
            logging.error(f"No usable entries found in {self.db_path}")
            return False

        if base_dn is None:
            logging.error(
                "No domain entry found in the database, "
                "this does not look like a FreeIPA id2entry.db file"
            )
            return False

        logging.debug(f"Offline base DN: {base_dn}")
        self._classify(entries, base_dn)

        classified = sum(len(bucket) for bucket in self.results.values())
        logging.info(
            f"Parsed {len(entries)} database entries, "
            f"{classified} matched known collection paths"
        )
        return True

    def _classify(
        self,
        entries: List[Tuple[str, Dict[str, AttributeValues], Set[str]]],
        base_dn: str
    ) -> None:
        rules = []
        for dump_type, config in self.ldap_paths.items():
            required_class = objectclass_from_filter(config["filter"])
            if required_class is None:
                logging.warning(
                    f"Cannot parse filter '{config['filter']}' for offline "
                    f"collection, matching by DN only: {dump_type}"
                )
            rules.append((
                config["path"].format(base_dn),
                config.get("search_scope", "SUBTREE"),
                required_class,
                config["type"]
            ))

        seen = set()
        for dn, attributes, object_classes in entries:
            for search_base, scope, required_class, type_name in rules:
                if not dn_matches(dn, search_base, scope):
                    continue
                if required_class is not None and required_class.lower() not in object_classes:
                    continue

                marker = (type_name, dn)
                if marker in seen:
                    continue
                seen.add(marker)

                entry_attributes = {
                    name: values for name, values in attributes.items()
                    if name != "dsEntryDN"
                }
                self.results.setdefault(type_name, []).append(
                    DbEntry(dn, entry_attributes)
                )
