import json
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

from rich.console import Console

from ipahound.lib.consts import *
from ipahound.lib.object_processor import PostProcessing


console = Console()

class OpenGraphPostProcessing(PostProcessing):
    """PostProcessing subclass that outputs BloodHound CE OpenGraph format."""

    OG_NODE_KINDS = {
        "IPADomain": ["IPA_Domain"],
        "IPAUser": ["IPA_User"],
        "IPAGroup": ["IPA_Group"],
        "IPAComputer": ["IPA_Computer"],
        "IPAService": ["IPA_Service"],
        "IPAPermission": ["IPA_Permission"],
        "IPARole": ["IPA_Role"],
        "IPACA": ["IPA_CA"],
        "IPACertificateTemplate": ["IPA_CertificateTemplate"],
        "IPASeLinux": ["IPA_SELinux"],
        "Base": ["Base"],
    }

    OG_EDGE_KINDS = {
        "MemberOf": "IPA_MemberOf",
        "AddMember": "IPA_AddMember",
        "ForceChangePassword": "IPA_ForceChangePassword",
        "ReadKerberosKey": "IPA_ReadKerberosKey",
        "Owns": "IPA_Owns",
        "AllowedToDelegate": "IPA_AllowedToDelegate",
        "Enroll": "IPA_Enroll",
        "AddRBCD": "IPA_AddRBCD",
        "DCSync": "IPA_DSync",
        "TrustedBy": "IPA_TrustedBy",
        "CanSUDO": "IPA_CanSUDO",
        "CanSSH": "IPA_CanSSH",
    }

    def __init__(self, input_raw_file, output_file, apoc_output_file, logger,
                 json_data=None, add_hbac_node=False, save_all_hbac=False):
        self.logger = logger
        self.input_raw_file = input_raw_file
        self.json_data = json_data
        self.add_hbac_node = add_hbac_node
        self.save_all_hbac = save_all_hbac

        if apoc_output_file:
            self.output_filepath = Path(apoc_output_file).with_suffix(".json")
        elif output_file:
            self.output_filepath = Path(output_file).with_suffix(".json")
        else:
            self.output_filepath = Path("opengraph_output.json")

        self.prepare_for_apoc = False
        self.line_ending = '\n'

        self.domain = ""
        self.next_object_id = 0
        self.relationship_id = 0
        self.objects = {}
        self.relationships = {}
        self.permissions_and_privileges = {}
        self.sudo_hbac_access = {}
        self.lost_objects = {}
        self.file_descriptor = None
        self.object_processor = None

        self.og_nodes = []
        self.og_edges = []

        self._load_objects()
        self._process_data()

    def _process_data(self):
        domain_obj = next(iter(self.objects.get("IPADomain", {}).values()))
        self.domain = domain_obj["associatedDomain"].upper()
        self.object_processor = ObjectProcessor(self.domain)

        if "objectid" not in domain_obj:
            if "ipaNTSecurityIdentifier" in domain_obj:
                domain_obj["objectid"] = domain_obj["ipaNTSecurityIdentifier"]
            else:
                domain_obj["objectid"] = domain_obj.get("dn", "")
        self._og_environment_id = self._og_node_id(domain_obj.get("objectid", ""))

        self.logger.info(f"Processing domain: {self.domain}")

        with console.status("Processing objects...", spinner="aesthetic") as status:
            self._og_collect_nodes(status)
            self._og_collect_relationships(status)

        output = {
            "metadata": {
                "source_kind": "IPAHound"
            },
            "graph": {
                "nodes": self.og_nodes,
                "edges": self.og_edges,
            }
        }

        with open(self.output_filepath, 'w') as f:
            json.dump(output, f, cls=ExtendedEncoder, indent=2)

        self.logger.info(f"Done! Your output file is: {self.output_filepath}")

    def _og_collect_nodes(self, status):
        for obj_type in self.objects:
            if obj_type in EDGE_TYPES:
                continue

            status.update(f"Processing {obj_type}...")

            for entry in self.objects[obj_type].values():
                if is_account_locked(entry):
                    continue

                self._save_object_entry(entry, obj_type)
                self.next_object_id += 1

    def _og_collect_relationships(self, status):
        status.update("Processing group relationships...")

        if "IPAGroup" in self.objects:
            for entry in self.objects["IPAGroup"].values():
                for attr_name in EDGE_ATTRIBUTES:
                    self._process_member_attribute(entry, attr_name)

        for obj_type in self.objects:
            if obj_type in EDGE_TYPES or obj_type == "IPAGroup":
                continue

            for entry in self.objects[obj_type].values():
                for attr_name in EDGE_ATTRIBUTES:
                    self._process_member_attribute(entry, attr_name)

        status.update("Processing HBAC rules...")
        if self.add_hbac_node:
            self._process_hbac_rules_mini()
        else:
            self._process_full_hbac_rules()

        status.update("Processing SUDO rules...")
        self._process_sudo_rules()

        status.update("Processing CA ACLs...")
        self._process_ca_acls()

        status.update("Processing S4U2Proxy...")
        self._process_s4u2proxy()

        status.update("Processing RBCD...")
        self._process_RBCD()

        status.update("Processing trusts...")
        self._process_trusts()

        status.update("Processing domain relationships...")
        self._process_domain_relationships()

    def _save_object_entry(self, entry, label):
        entry["type"] = label
        entry["id"] = self.next_object_id
        entry["domain"] = self.domain
        entry["name"] = self.object_processor.get_object_name(entry)

        self._add_type_specific_properties(entry, label)

        for attr_name in LIST_ATTRIBUTES:
            if attr_name in entry and isinstance(entry[attr_name], str):
                entry[attr_name] = [entry[attr_name]]

        processed = self.object_processor.process_attributes(entry)

        properties = {
            "name": entry.get("name", ""),
            "distinguishedname": entry.get("dn", ""),
            "environmentid": self._og_environment_id,
        }
        if label == "IPADomain":
            properties["collected"] = True
        for key, value in processed.items():
            if key in ("objectid", "dn", "type", "id", "name"):
                continue
            if isinstance(value, (str, int, float, bool)):
                properties[key] = value
            elif value is None:
                continue
            elif isinstance(value, list):
                properties[key] = value
            elif isinstance(value, bytes):
                properties[key] = str(value)
            elif isinstance(value, datetime.datetime):
                properties[key] = value.strftime('%H:%M:%S %d.%m.%Y')

        if "objectid" not in entry:
            if "ipaNTSecurityIdentifier" in entry:
                entry["objectid"] = entry["ipaNTSecurityIdentifier"]
            else:
                entry["objectid"] = entry.get("dn", str(self.next_object_id))

        node_id = self._og_node_id(entry.get("objectid", entry.get("dn", "")))
        kinds = list(self.OG_NODE_KINDS.get(label, ["Base"]))

        if label == "IPAGroup":
            obj_class = entry.get("objectClass", [])
            if "ipanisnetgroup" in obj_class:
                kinds.append("IPA_NetGroup")
            if "ipahbacrule" in obj_class:
                kinds.append("IPA_HBACRule")

        self.og_nodes.append({
            "id": node_id,
            "kinds": kinds,
            "properties": properties or None,
        })

    def _create_member_relationship(self, entry, end_object, end_type, attr_name):
        attr_lower = attr_name.lower()
        og_kind = "IPA_MemberOf"

        if attr_lower == "memberof":
            if self._check_duplicate_relationship(entry["dn"], end_object["dn"]):
                return
            start_obj, end_obj = entry, end_object
        elif attr_lower in ["member", "memberuser", "memberhost"]:
            if self._check_duplicate_relationship(end_object["dn"], entry["dn"]):
                return
            start_obj, end_obj = end_object, entry
        elif attr_lower == "ipaexternalmember":
            start_obj, end_obj = end_object, entry
        elif attr_lower == "membermanager":
            start_obj, end_obj = end_object, entry
            og_kind = "IPA_AddMember"
        elif attr_lower in ["owns", "managedby"] and end_object["id"] != entry["id"]:
            start_obj, end_obj = end_object, entry
            og_kind = "IPA_Owns"
        elif "ipaallowedtoperform" in attr_lower and end_object["id"] != entry["id"]:
            start_obj, end_obj = end_object, entry
            if attr_lower == "ipaallowedtoperform;write_keys":
                og_kind = "IPA_ForceChangePassword"
            elif attr_lower == "ipaallowedtoperform;read_keys":
                og_kind = "IPA_ReadKerberosKey"
            elif attr_lower == "ipaallowedtoperform;write_delegation":
                og_kind = "IPA_AddRBCD"
            else:
                return
        else:
            return

        start_id = self._og_node_id(start_obj.get("objectid", start_obj.get("dn", "")))
        end_id = self._og_node_id(end_obj.get("objectid", end_obj.get("dn", "")))

        edge = {
            "start": {"match_by": "id", "value": start_id},
            "end": {"match_by": "id", "value": end_id},
            "kind": og_kind,
        }
        self.og_edges.append(edge)

    def _add_rule_relationship(self, start_spec, end_spec, relationship,
                               add_to_sudo_access=False, check_sudo_access=False,
                               save_relationship=True, ignore_exception=False):
        start_objects = self._get_objects_for_spec(start_spec, ignore_exception=ignore_exception)
        end_objects = self._get_objects_for_spec(end_spec, ignore_exception=ignore_exception)

        if not start_objects or not end_objects:
            return

        og_kind = self.OG_EDGE_KINDS.get(relationship.get("label", ""), relationship.get("label", ""))

        for start_obj in start_objects:
            for end_obj in end_objects:
                access_key = f'{start_obj["dn"]}+{end_obj["dn"]}'

                if add_to_sudo_access:
                    self.sudo_hbac_access[access_key] = True
                    self.add_sudo_hbac_access(start_obj, end_obj)

                if check_sudo_access and not self.check_hbac_access(access_key, start_obj, end_obj):
                    continue

                if not save_relationship:
                    continue

                start_id = self._og_node_id(start_obj.get("objectid", start_obj.get("dn", "")))
                end_id = self._og_node_id(end_obj.get("objectid", end_obj.get("dn", "")))

                edge = {
                    "start": {"match_by": "id", "value": start_id},
                    "end": {"match_by": "id", "value": end_id},
                    "kind": og_kind,
                }
                if og_kind == "IPA_CanSUDO" and relationship.get("properties"):
                    edge["properties"] = extract_sudo_rule_metadata(relationship["properties"])
                self.og_edges.append(edge)

    def _create_mini_hbac_relationship(self, user_dn, host_dn, service="SSH", memberof=False, rule=None):
        if service == "*":
            service = "ALL"
        elif service[:3] == "cn=":
            service = service[3:service.find(",")]

        if memberof:
            og_kind = "IPA_MemberOf"
        else:
            og_kind = f"IPA_Can{service}"

        _, user_object = self._search_object(user_dn, ignore_exception=True)
        _, host_object = self._search_object(host_dn, ignore_exception=True)

        if not user_object or not host_object:
            return

        start_id = self._og_node_id(user_object.get("objectid", user_object.get("dn", "")))
        end_id = self._og_node_id(host_object.get("objectid", host_object.get("dn", "")))

        edge = {
            "start": {"match_by": "id", "value": start_id},
            "end": {"match_by": "id", "value": end_id},
            "kind": og_kind,
        }
        if not memberof and rule:
            edge["properties"] = extract_hbac_rule_metadata(rule)
        self.og_edges.append(edge)

    def _create_hbac_relationship(self, user_dn, host_dn, service="SSH", rule=None):
        if service == "*":
            service = "ALL"
        elif service[:3] == "cn=":
            service = service[3:service.find(",")]

        _, user_object = self._search_object(user_dn)
        _, host_object = self._search_object(host_dn)

        if not user_object or not host_object:
            return

        start_id = self._og_node_id(user_object.get("objectid", user_object.get("dn", "")))
        end_id = self._og_node_id(host_object.get("objectid", host_object.get("dn", "")))

        edge = {
            "start": {"match_by": "id", "value": start_id},
            "end": {"match_by": "id", "value": end_id},
            "kind": f"IPA_Can{service}",
        }
        if rule:
            edge["properties"] = extract_hbac_rule_metadata(rule)
        self.og_edges.append(edge)

    def _process_trusts(self):
        if "IPATrust" not in self.objects:
            return

        domain_dn = next(iter(self.objects["IPADomain"].values()))["dn"]

        for trust in self.objects["IPATrust"].values():
            start_id = trust.get("ipaNTTrustedDomainSID", trust.get("dn", ""))
            end_id = self._og_node_id(
                next(iter(self.objects["IPADomain"].values())).get("objectid", domain_dn)
            )

            self.og_edges.append({
                "start": {"match_by": "id", "value": start_id},
                "end": {"match_by": "id", "value": end_id},
                "kind": "IPA_TrustedBy",
            })

            if 'ipaNTTrustType' in trust and trust['ipaNTTrustType'] == 2:
                self.og_edges.append({
                    "start": {"match_by": "id", "value": end_id},
                    "end": {"match_by": "id", "value": start_id},
                    "kind": "IPA_TrustedBy",
                })

    def _process_domain_relationships(self):
        domain_obj = next(iter(self.objects["IPADomain"].values()))

        for dn, perm in self.permissions_and_privileges.items():
            name = perm["name"].split('@')[0]

            if name in REPLICATION_PERMISSIONS:
                rel_type = "IPA_DSync"
            else:
                continue

            start_id = self._og_node_id(perm.get("objectid", perm.get("dn", "")))
            end_id = self._og_node_id(domain_obj.get("objectid", domain_obj.get("dn", "")))

            self.og_edges.append({
                "start": {"match_by": "id", "value": start_id},
                "end": {"match_by": "id", "value": end_id},
                "kind": rel_type,
            })

    def _process_s4u2proxy(self):
        if "S4U2Proxy" not in self.objects:
            return

        for obj in self.objects["S4U2Proxy"].values():
            if "ipaKrb5DelegationACL" not in obj.get("objectClass", []):
                continue

            if "memberPrincipal" not in obj or "ipaAllowedTarget" not in obj:
                continue

            sources = []
            for principal in obj["memberPrincipal"]:
                source_obj = self._search_principal(principal)
                if source_obj:
                    sources.append(source_obj)

            targets = []
            for group_dn in obj["ipaAllowedTarget"]:
                if group_dn not in self.objects.get("S4U2Proxy", {}):
                    continue

                target_group = self.objects["S4U2Proxy"][group_dn]
                for principal in target_group.get("memberPrincipal", []):
                    target_obj = self._search_principal(principal)
                    if target_obj:
                        targets.append(target_obj)

            for source in sources:
                for target in targets:
                    self.og_edges.append({
                        "start": {"match_by": "id", "value": self._og_node_id(source.get("objectid", source.get("dn", "")))},
                        "end": {"match_by": "id", "value": self._og_node_id(target.get("objectid", target.get("dn", "")))},
                        "kind": "IPA_AllowedToDelegate",
                    })

    def _process_RBCD(self):
        computers = self.objects.get("IPAComputer", {})
        services = self.objects.get("IPAService", {})
        if not computers and not services:
            return

        for obj in list(computers.values()) + list(services.values()):
            if "memberPrincipal" not in obj:
                continue

            sources = []
            for principal in obj["memberPrincipal"]:
                source_obj = self._search_principal(principal)
                if source_obj:
                    sources.append(source_obj)

            target = obj
            for source in sources:
                self.og_edges.append({
                    "start": {"match_by": "id", "value": self._og_node_id(source.get("objectid", source.get("dn", "")))},
                    "end": {"match_by": "id", "value": self._og_node_id(target.get("objectid", target.get("dn", "")))},
                    "kind": "IPA_AllowedToDelegate",
                })

    def _create_missing_object(self, dn):
        if not "=" in dn or dn[:5] == "S-1-5":
            name = dn
        else:
            name = dn.split('=')[1].split(',')[0].upper()

        new_obj = {
            "id": self.next_object_id,
            "type": "Base",
            "domain": self.domain,
            "name": name,
            "dn": dn,
            "objectid": dn
        }

        if "cn=privileges,cn=pbac" in dn:
            obj_type = "IPAGroup"
            new_obj["type"] = "privileges"
            self.permissions_and_privileges[dn] = new_obj
        elif "cn=permissions,cn=pbac" in dn:
            obj_type = "IPAPermission"
            new_obj["type"] = "permissions"
            self.permissions_and_privileges[dn] = new_obj
        elif "cn=roles,cn=accounts" in dn:
            obj_type = "IPARole"
            new_obj["type"] = "role"
            self.permissions_and_privileges[dn] = new_obj
        elif "cn=replication managers,cn=sysaccounts,cn=etc" in dn:
            obj_type = "IPAGroup"
            new_obj["type"] = "sysaccount"
            self.permissions_and_privileges[dn] = new_obj
        else:
            obj_type = "Base"
            self.lost_objects[dn] = new_obj

        node_id = self._og_node_id(dn)
        kinds = list(self.OG_NODE_KINDS.get(obj_type, ["Base"]))
        self.og_nodes.append({
            "id": node_id,
            "kinds": kinds,
            "properties": {
                "name": name,
                "domain": self.domain,
                "distinguishedname": dn,
                "environmentid": self._og_environment_id,
            },
        })

        self.next_object_id += 1
        return obj_type, new_obj

    def _og_node_id(self, objectid):
        if objectid:
            return str(objectid).replace(":", "_")
        return ""
