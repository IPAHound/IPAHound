import base64
import json
import logging
import os
import sys

import pytest

from ipahound.lib.args_parser import get_parser, post_parsing_arguments
from ipahound.lib.db_collector import (
    DBCollector,
    DbAttribute,
    DbEntry,
    collect_entries,
    dn_matches,
    objectclass_from_filter,
    parse_entry_record,
    split_dn,
)
from ipahound.main import _process_entry_attributes, dump_ldap_to_json

SAMPLE_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "id2entry.db"
)

requires_sample_db = pytest.mark.skipif(
    not os.path.isfile(SAMPLE_DB),
    reason="sample id2entry.db is not present in the repository root",
)

BASE_DN = "dc=ipa,dc=local"


class TestParseEntryRecord:

    def test_basic_record(self):
        record = (
            b"rdn: uid=alice\n"
            b"uid: alice\n"
            b"cn: Alice\n"
            b"objectClass: person\n"
            b"dsEntryDN: uid=alice,cn=users,cn=accounts,dc=ipa,dc=local\n"
            b"\x00"
        )
        attrs = parse_entry_record(record)
        assert attrs["uid"] == ["alice"]
        assert attrs["cn"] == ["Alice"]
        assert attrs["objectClass"] == ["person"]
        assert attrs["dsEntryDN"] == ["uid=alice,cn=users,cn=accounts,dc=ipa,dc=local"]
        # rdn is an id2entry-internal attribute, LDAP never returns it
        assert "rdn" not in attrs

    def test_line_unfolding_joins_without_space(self):
        record = (
            b"uid: very\n"
            b" long\n"
            b" name\n"
            b"dsEntryDN: uid=verylongname,cn=users," + BASE_DN.encode() + b"\n\x00"
        )
        attrs = parse_entry_record(record)
        assert attrs["uid"] == ["verylongname"]

    def test_base64_binary_value_stays_bytes(self):
        blob = b"\x01\x02\x03\x04\xff\xfe"
        encoded = base64.b64encode(blob).decode()
        record = f"krbPrincipalKey:: {encoded}\n\x00".encode()
        attrs = parse_entry_record(record)
        assert attrs["krbPrincipalKey"] == [blob]

    def test_base64_text_value_becomes_string(self):
        # id2entry uses "::" for values starting with ':' as well - ldap3
        # would return those as strings, so the parser must too
        text = ":SID:S-1-5-21-1234567890-1001"
        encoded = base64.b64encode(text.encode()).decode()
        record = f"ipaAnchorUUID:: {encoded}\n\x00".encode()
        attrs = parse_entry_record(record)
        assert attrs["ipaAnchorUUID"] == [text]

    def test_base64_value_with_folding(self):
        blob = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d"
        encoded = base64.b64encode(blob).decode()
        record = (
            f"krbMKey:: {encoded[:8]}\n".encode()
            + f" {encoded[8:]}\n".encode()
            + b"\x00"
        )
        attrs = parse_entry_record(record)
        assert attrs["krbMKey"] == [blob]

    def test_csn_subtypes_are_stripped(self):
        record = (
            b"objectClass;vdcsn-6ae206e5000000020000: ipausergroup\n"
            b"uid;vucsn-abc;mdcsn-def;adcsn-xyz: alice\n"
            b"\x00"
        )
        attrs = parse_entry_record(record)
        assert attrs["objectClass"] == ["ipausergroup"]
        assert attrs["uid"] == ["alice"]

    def test_semantic_options_are_kept(self):
        record = b"ipaAllowedToPerform;read_keys: dc1.ipa.local\n\x00"
        attrs = parse_entry_record(record)
        assert "ipaAllowedToPerform;read_keys" in attrs

    def test_deleted_attribute_lines_are_skipped(self):
        record = (
            b"krbTicketFlags;vucsn-abc;deletedattribute;deleted:\n"
            b"uid: alice\n"
            b"\x00"
        )
        attrs = parse_entry_record(record)
        assert "krbTicketFlags" not in attrs
        assert attrs["uid"] == ["alice"]

    def test_multivalued_attributes_accumulate(self):
        record = (
            b"objectClass: top\n"
            b"objectClass: person\n"
            b"objectClass: inetOrgPerson\n"
            b"member: uid=a," + BASE_DN.encode() + b"\n"
            b"member: uid=b," + BASE_DN.encode() + b"\n"
            b"\x00"
        )
        attrs = parse_entry_record(record)
        assert attrs["objectClass"] == ["top", "person", "inetOrgPerson"]
        assert attrs["member"] == [
            f"uid=a,{BASE_DN}",
            f"uid=b,{BASE_DN}",
        ]

    def test_integer_attributes_are_converted(self):
        record = b"krbTicketFlags: 8388608\nuidNumber: 1115400004\n\x00"
        attrs = parse_entry_record(record)
        assert attrs["krbTicketFlags"] == [8388608]
        assert attrs["uidNumber"] == [1115400004]

    def test_non_integer_values_are_untouched(self):
        record = b"uid: 123abc\ndc: positive\n\x00"
        attrs = parse_entry_record(record)
        assert attrs["uid"] == ["123abc"]
        assert attrs["dc"] == ["positive"]


class TestDbEntry:

    def test_value_empty_multi_single(self):
        assert DbAttribute([]).value is None
        assert DbAttribute(["only"]).value == "only"
        assert DbAttribute(["a", "b"]).value == ["a", "b"]

    def test_entry_attributes(self):
        entry = DbEntry("uid=a," + BASE_DN, {"uid": ["a"], "cn": ["A", "B"]})
        assert entry.entry_dn == f"uid=a,{BASE_DN}"
        assert entry.entry_attributes == ["uid", "cn"]
        assert entry["uid"].value == "a"
        assert entry["cn"].value == ["A", "B"]

    def test_works_with_process_entry_attributes(self):
        entry = DbEntry(
            "uid=alice,cn=users,cn=accounts," + BASE_DN,
            {
                "uid": ["alice"],
                "krbPrincipalName": ["alice@IPA.LOCAL"],
                "member": ["uid=a," + BASE_DN, "uid=b," + BASE_DN],
                "managedBy": ["uid=admin," + BASE_DN],
                "cn": ["Alice"],
            },
        )
        attributes = _process_entry_attributes(entry)

        # multi-valued LIST_ATTRIBUTES stay full lists (ldap3 .value semantics)
        assert attributes["member"] == [f"uid=a,{BASE_DN}", f"uid=b,{BASE_DN}"]
        # single-valued LIST_ATTRIBUTES are wrapped into a list
        assert attributes["managedBy"] == [f"uid=admin,{BASE_DN}"]
        # non-list scalar attributes stay scalars
        assert attributes["cn"] == "Alice"
        # objectid falls back to the DN, dn key is always set
        assert attributes["objectid"] == entry.entry_dn
        assert attributes["dn"] == entry.entry_dn

    def test_objectid_uses_sid_when_present(self):
        entry = DbEntry(
            "uid=alice," + BASE_DN,
            {"uid": ["alice"], "ipaNTSecurityIdentifier": ["S-1-5-21-1-2-3"]},
        )
        attributes = _process_entry_attributes(entry)
        assert attributes["objectid"] == "S-1-5-21-1-2-3"


class TestDnHelpers:

    def test_split_dn_plain(self):
        assert split_dn("uid=a,cn=users,dc=x,dc=y") == ["uid=a", "cn=users", "dc=x", "dc=y"]

    def test_split_dn_escaped_comma(self):
        assert split_dn("cn=a\\,b,cn=groups,dc=x") == ["cn=a\\,b", "cn=groups", "dc=x"]

    def test_dn_matches_subtree(self):
        assert dn_matches(f"uid=a,cn=users,cn=accounts,{BASE_DN}", f"cn=users,cn=accounts,{BASE_DN}", "SUBTREE")
        assert dn_matches(BASE_DN, BASE_DN, "SUBTREE")

    def test_dn_matches_base_scope_is_exact(self):
        assert dn_matches(BASE_DN, BASE_DN, "BASE")
        assert not dn_matches(f"cn=users,{BASE_DN}", BASE_DN, "BASE")

    def test_dn_matches_component_boundary(self):
        assert not dn_matches(
            f"cn=users2,cn=accounts,{BASE_DN}", f"cn=users,cn=accounts,{BASE_DN}", "SUBTREE"
        )
        assert not dn_matches(f"cn=users,cn=accounts,dc=ipa,dc=other", f"cn=users,cn=accounts,{BASE_DN}", "SUBTREE")

    def test_dn_matches_case_insensitive(self):
        assert dn_matches(f"UID=a,CN=users,cn=accounts,DC=ipa,DC=local", f"cn=users,cn=accounts,{BASE_DN}", "SUBTREE")

    def test_objectclass_from_filter(self):
        assert objectclass_from_filter("(objectClass=person)") == "person"
        assert objectclass_from_filter("(objectClass=GroupOfNames)") == "GroupOfNames"
        assert objectclass_from_filter("(objectClass=*)") is None
        assert objectclass_from_filter("(&(objectClass=a)(objectClass=b))") is None


class TestCollectEntries:

    def test_base_dn_from_domain_entry(self):
        records = [
            b"objectClass: domain\ndc: ipa\ndsEntryDN: " + BASE_DN.encode() + b"\n\x00",
            b"objectClass: top\ndc: other\ndsEntryDN: dc=other,dc=ipa,dc=local\n\x00",
        ]
        entries, base_dn = collect_entries(records)
        assert base_dn == BASE_DN
        assert len(entries) == 2

    def test_shortest_domain_dn_wins(self):
        records = [
            b"objectClass: domain\ndsEntryDN: cn=sub,dc=ipa,dc=local\n\x00",
            b"objectClass: domain\ndsEntryDN: dc=ipa,dc=local\n\x00",
        ]
        _, base_dn = collect_entries(records)
        assert base_dn == "dc=ipa,dc=local"

    def test_no_domain_entry(self):
        records = [b"objectClass: person\ndsEntryDN: uid=a," + BASE_DN.encode() + b"\n\x00"]
        _, base_dn = collect_entries(records)
        assert base_dn is None

    def test_tombstones_and_dnless_records_are_skipped(self):
        records = [
            b"objectClass: nsTombstone\ndsEntryDN: nsuniqueid=abc," + BASE_DN.encode() + b"\n\x00",
            b"objectClass: top\n\x00",
            b"objectClass: person\ndsEntryDN: uid=a,cn=users,cn=accounts," + BASE_DN.encode() + b"\n\x00",
        ]
        entries, _ = collect_entries(records)
        assert len(entries) == 1
        assert entries[0][0] == f"uid=a,cn=users,cn=accounts,{BASE_DN}"


class TestDBCollectorClassification:

    @staticmethod
    def make_collector():
        collector = object.__new__(DBCollector)
        collector.results = {}
        collector.ldap_paths = DBCollector("", ).ldap_paths
        return collector

    @staticmethod
    def entry(dn, object_classes, extra=None):
        attributes = {"objectClass": object_classes}
        attributes.update(extra or {})
        classes = {cls.lower() for cls in object_classes}
        return (dn, attributes, classes)

    def test_classification_of_all_bucket_types(self):
        collector = self.make_collector()
        entries = [
            self.entry(BASE_DN, ["domain", "top"]),
            self.entry(
                f"uid=alice,cn=users,cn=accounts,{BASE_DN}",
                ["top", "person", "inetOrgPerson"],
            ),
            self.entry(
                f"cn=admins,cn=groups,cn=accounts,{BASE_DN}",
                ["top", "groupOfNames"],
            ),
            self.entry(
                f"cn=servers,cn=hostgroups,cn=accounts,{BASE_DN}",
                ["top", "groupOfNames"],
            ),
            self.entry(
                f"fqdn=dc01.{BASE_DN.replace('dc=', '').replace(',dc=', '.')},cn=computers,cn=accounts,{BASE_DN}",
                ["top", "ipaHost"],
            ),
            self.entry(
                f"krbprincipalname=ldap/dc01@IPA.LOCAL,cn=services,cn=accounts,{BASE_DN}",
                ["top", "ipaService"],
            ),
            self.entry(
                f"cn=System: Read Things,cn=permissions,cn=pbac,{BASE_DN}",
                ["top", "ipapermission"],
            ),
            self.entry(
                f"cn=User Management,cn=privileges,cn=pbac,{BASE_DN}",
                ["top", "groupofnames"],
            ),
            self.entry(
                f"cn=admins,cn=sudorules,cn=sudo,{BASE_DN}",
                ["top", "ipasudorule"],
            ),
        ]
        collector._classify(entries, BASE_DN)

        dns = {bucket: {entry.entry_dn for entry in entries}
               for bucket, entries in collector.results.items()}
        assert BASE_DN in dns["IPADomain"]
        assert f"uid=alice,cn=users,cn=accounts,{BASE_DN}" in dns["IPAUser"]
        assert f"cn=admins,cn=groups,cn=accounts,{BASE_DN}" in dns["IPAGroup"]
        assert f"cn=servers,cn=hostgroups,cn=accounts,{BASE_DN}" in dns["IPAGroup"]
        assert any(dn.startswith("fqdn=dc01") for dn in dns["IPAComputer"])
        assert f"cn=System: Read Things,cn=permissions,cn=pbac,{BASE_DN}" in dns["IPAPermission"]
        assert f"cn=User Management,cn=privileges,cn=pbac,{BASE_DN}" in dns["IPAGroup"]
        assert f"cn=admins,cn=sudorules,cn=sudo,{BASE_DN}" in dns["sudo_rule"]

    def test_filter_excludes_non_matching_entries_in_same_subtree(self):
        collector = self.make_collector()
        entries = [
            # cosTemplate lives under cn=computers but is not an ipaHost
            self.entry(
                f"cn=cosTemplate,cn=computers,cn=accounts,{BASE_DN}",
                ["top", "cosTemplate"],
            ),
            # private groups under cn=groups are posixgroup, not groupOfNames
            self.entry(
                f"cn=alice,cn=groups,cn=accounts,{BASE_DN}",
                ["top", "posixgroup"],
            ),
        ]
        collector._classify(entries, BASE_DN)
        assert "IPAComputer" not in collector.results
        assert "IPAGroup" not in collector.results

    def test_hbac_services_do_not_leak_into_hbac_rules(self):
        collector = self.make_collector()
        entries = [
            self.entry(
                f"cn=sshd,cn=hbacservices,cn=hbac,{BASE_DN}",
                ["top", "ipahbacservice"],
            ),
            self.entry(
                f"cn=allow_all,cn=hbac,{BASE_DN}",
                ["top", "ipahbacrule"],
            ),
        ]
        collector._classify(entries, BASE_DN)
        assert {e.entry_dn for e in collector.results["hbac_service"]} == {
            f"cn=sshd,cn=hbacservices,cn=hbac,{BASE_DN}"
        }
        assert {e.entry_dn for e in collector.results["hbac_rule"]} == {
            f"cn=allow_all,cn=hbac,{BASE_DN}"
        }

    def test_entries_outside_paths_are_ignored(self):
        collector = self.make_collector()
        entries = [
            self.entry(f"idnsname=ipa,cn=dns,{BASE_DN}", ["top", "idnszone"]),
            self.entry(f"cn=masters,cn=ipa,cn=etc,{BASE_DN}", ["top", "nscontainer"]),
        ]
        collector._classify(entries, BASE_DN)
        assert collector.results == {}

    def test_dsentrydn_is_not_exposed_as_attribute(self):
        collector = self.make_collector()
        entries = [
            self.entry(
                f"uid=alice,cn=users,cn=accounts,{BASE_DN}",
                ["top", "person"],
                {"dsEntryDN": [f"uid=alice,cn=users,cn=accounts,{BASE_DN}"]},
            ),
        ]
        collector._classify(entries, BASE_DN)
        user = collector.results["IPAUser"][0]
        assert "dsEntryDN" not in user.entry_attributes


class TestArgs:

    def test_short_flag(self):
        args = get_parser(["all"]).parse_args(["-f", "x.db"])
        assert args.offlain == "x.db"

    def test_long_flag(self):
        args = get_parser(["all"]).parse_args(["--offlain", "x.db"])
        assert args.offlain == "x.db"

    def test_offlain_skips_ldap_validation(self):
        parser = get_parser(["all"])
        args = parser.parse_args(["-f", "x.db", "-a", "out.json"])
        assert post_parsing_arguments(args, logging.getLogger("test"))

    def test_missing_file_fails_gracefully(self, tmp_path):
        collector = DBCollector(str(tmp_path / "missing.db"))
        assert collector.dump_db_data() is False
        assert collector.results == {}


@requires_sample_db
class TestDBCollectorSample:

    def test_dump_db_data(self):
        collector = DBCollector(SAMPLE_DB)
        assert collector.dump_db_data() is True
        buckets = set(collector.results)
        assert {"IPADomain", "IPAUser", "IPAGroup", "IPAPermission", "IPAComputer"} <= buckets

    def test_raw_dump_structure_and_domain(self):
        collector = DBCollector(SAMPLE_DB)
        assert collector.dump_db_data() is True

        dump = dump_ldap_to_json(collector.results, None)
        types = {item["meta"]["type"]: item for item in dump}
        assert types["IPADomain"]["meta"]["count"] == 1
        assert types["IPADomain"]["meta"]["methods"] == 0
        assert types["IPADomain"]["meta"]["version"] == 4

        domain = next(iter(types["IPADomain"]["data"].values()))
        assert domain["associatedDomain"] == "positive.ipa"
        assert domain["dn"] == "dc=positive,dc=ipa"

    def test_user_entry_semantics(self):
        collector = DBCollector(SAMPLE_DB)
        assert collector.dump_db_data() is True

        users = collector.results["IPAUser"]
        mikhail = next(
            e for e in users if e.entry_dn.startswith("uid=mikhail,")
        )
        attributes = _process_entry_attributes(mikhail)
        assert attributes["uid"] == "mikhail"
        assert attributes["krbPrincipalName"] == ["mikhail@POSITIVE.IPA"]
        assert attributes["objectid"] == "S-1-5-21-3064109350-544161276-2356360860-1004"

    def test_end_to_end_apoc_output(self, tmp_path, monkeypatch, capsys):
        output = tmp_path / "apoc.json"
        monkeypatch.setattr(
            sys, "argv", ["ipahound", "-f", SAMPLE_DB, "-a", str(output)]
        )
        from ipahound.main import main
        main()

        assert output.is_file()
        nodes = 0
        for line in output.read_text().splitlines():
            record = json.loads(line)
            if record.get("type") == "node":
                nodes += 1
        assert nodes > 100
