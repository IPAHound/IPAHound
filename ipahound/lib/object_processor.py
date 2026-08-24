import json
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

from rich.console import Console

from ipahound.lib.consts import *
from ipahound.lib.json_encoder import ExtendedEncoder

console = Console()


class PostProcessing:

    def __init__(
            self,
            input_raw_file: Optional[str],
            output_file: Optional[str],
            apoc_output_file: Optional[str],
            logger: logging.Logger,
            json_data: Optional[List] = None,
            add_hbac_node=False,
            save_all_hbac = False
    ):
        self.logger = logger
        self.input_raw_file = input_raw_file
        self.json_data = json_data
        self.add_hbac_node = add_hbac_node
        self.save_all_hbac = save_all_hbac

        if apoc_output_file:
            self.output_filepath = Path(apoc_output_file).with_suffix(".json")
            self.prepare_for_apoc = True
            self.line_ending = '\n'
        else:
            self.output_filepath = Path(output_file).with_suffix(".json")
            self.prepare_for_apoc = False
            self.line_ending = ',\n'

        self.domain = ""
        self.next_object_id = 0
        self.relationship_id = 0
        self.objects: Dict[str, Dict] = {}
        self.relationships: Dict[str, bool] = {}
        self.permissions_and_privileges: Dict[str, Dict] = {}
        self.sudo_hbac_access: Dict[str, bool] = {}
        self.lost_objects: Dict[str, Dict] = {}
        self.file_descriptor = None
        self.object_processor = None

        self._load_objects()
        self._process_data()

    def _load_objects(self) -> None:
        if self.json_data:
            for item in self.json_data:
                self.objects[item["meta"]["type"]] = item["data"]
        elif self.input_raw_file:
            with open(self.input_raw_file, 'r') as f:
                data = json.load(f)
                for item in data:
                    self.objects[item["meta"]["type"]] = item["data"]

    def _generate_node_json(
            self,
            node_id: int,
            label: str,
            properties: Optional[Dict] = None
    ) -> Dict:
        return {
            "type": "node",
            "id": node_id,
            "labels": [label, "Base"],
            "properties": properties or {}
        }

    def _generate_relationship_json(
            self,
            rel_id: int,
            label: str,
            start_node: Dict,
            end_node: Dict,
            properties: Optional[Dict] = None
    ) -> Dict:
        return {
            "id": rel_id,
            "type": "relationship",
            "label": label,
            "properties": properties or {},
            "start": start_node,
            "end": end_node
        }

    def _save_object_entry(self, entry: Dict, label: str) -> None:
        entry["type"] = label
        entry["id"] = self.next_object_id
        entry["domain"] = self.domain
        entry["name"] = self.object_processor.get_object_name(entry)

        self._add_type_specific_properties(entry, label)

        for attr_name in LIST_ATTRIBUTES:
            if attr_name in entry and isinstance(entry[attr_name], str):
                entry[attr_name] = [entry[attr_name]]

        processed = self.object_processor.process_attributes(entry)
        node_json = self._generate_node_json(entry["id"], label, processed)
        self.file_descriptor.write(
            json.dumps(node_json, cls=ExtendedEncoder) + self.line_ending
        )

    def _add_type_specific_properties(self, entry: Dict, label: str) -> None:
        if label == "IPACertificateTemplate":
            entry["Enabled"] = True

        elif label == "IPAUser":
            if "ipaUserAuthType" not in entry or "password" in entry.get("ipaUserAuthType", []):
                entry["PasswordAuthAllow"] = True
            else:
                entry["PasswordAuthAllow"] = False

            if "usercertificate" in entry or "usercertificate;binary" in entry:
                entry["HaveCert"] = True

        elif label == "IPADomain":
            entry["highvalue"] = True

        elif label == "IPAGroup":
            if entry.get("cn") in HIGH_VALUE_GROUPS:
                entry["highvalue"] = True

            if "cn=sysaccounts,cn=etc," in entry["dn"]:
                entry["highvalue"] = True

            if "ipanisnetgroup" in entry.get("objectClass", []):
                entry["NetGroup"] = True
                entry["name"] = "Net Group: " + entry["name"]

            if "ipahbacrule" in entry.get("objectClass", []):
                entry["NetGroup"] = True
                entry["name"] = "HBAC: " + entry["name"]

    def _search_object(
            self,
            dn: str,
            substr: bool = False,
            ignore_exception: bool = False
    ) -> Tuple[Optional[str], Optional[Dict]]:
        if not ignore_exception and any(skip in dn for skip in [",cn=hbac", ",cn=sudorules", ",cn=sudocmds,"]):
            return None, None

        for obj_type in self.objects:
            if substr:
                for obj_dn in self.objects[obj_type]:
                    if dn.lower() in obj_dn.lower():
                        return obj_type, self.objects[obj_type][obj_dn]
            elif dn in self.objects[obj_type]:
                obj = self.objects[obj_type][dn]
                if "cn=privileges,cn=pbac" in dn or "cn=permissions,cn=pbac" in dn:
                    if dn not in self.permissions_and_privileges:
                        self.permissions_and_privileges[dn] = obj
                return obj_type, obj

        for obj_type in self.objects:
            result = search_dict_case_insensitive(self.objects[obj_type], dn)
            if result:
                return obj_type, result

        if dn in self.permissions_and_privileges:
            return "IPAGroup", self.permissions_and_privileges[dn]

        if dn in self.lost_objects:
            obj = self.lost_objects[dn]
            return obj["type"], obj

        return self._create_missing_object(dn)

    def _search_principal(self, principal: str) -> Optional[Dict]:
        principal_lower = principal.lower()
        for obj_type in ("IPAService", "IPAComputer"):
            for obj in self.objects.get(obj_type, {}).values():
                krb_names = obj.get("krbPrincipalName", [])
                if isinstance(krb_names, str):
                    krb_names = [krb_names]
                if any(k.lower() == principal_lower for k in krb_names):
                    return obj
        return None

    def _create_missing_object(self, dn: str) -> Tuple[str, Dict]:
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

        node_json = self._generate_node_json(self.next_object_id, obj_type, new_obj)
        self.file_descriptor.write(json.dumps(node_json, cls=ExtendedEncoder) + self.line_ending)
        self.next_object_id += 1

        return obj_type, new_obj

    def _process_member_attribute(self, entry: Dict, attr_name: str) -> None:
        if attr_name not in entry or is_account_locked(entry):
            return

        if type(entry[attr_name]) is str:
            entry[attr_name] = [entry[attr_name]]

        for member_dn in entry[attr_name]:
            obj_type, end_object = self._search_object(member_dn)

            if not obj_type or obj_type in EDGE_TYPES:
                continue

            if is_account_locked(end_object):
                continue

            self._create_member_relationship(entry, end_object, obj_type, attr_name)

    def _create_member_relationship(
            self,
            entry: Dict,
            end_object: Dict,
            end_type: str,
            attr_name: str
    ) -> None:
        attr_lower = attr_name.lower()

        if attr_lower == "memberof":
            if self._check_duplicate_relationship(entry["dn"], end_object["dn"]):
                return
            rel_type = "MemberOf"
            start = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}
            end = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            properties = {"isacl": False}

        elif attr_lower in ["member", "memberuser", "memberhost"]:
            if self._check_duplicate_relationship(end_object["dn"], entry["dn"]):
                return
            rel_type = "MemberOf"
            start = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            end = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}
            properties = {"isacl": False}

        elif attr_lower == "ipaexternalmember":
            rel_type = "MemberOf"
            start = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            end = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}
            properties = {"isacl": False}

        elif attr_lower == "membermanager":
            rel_type = "AddMember"
            start = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            end = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}
            properties = {"isacl": True}

        elif attr_lower in ["owns", "managedby"] and end_object["id"] != entry["id"]:
            rel_type = "Owns"
            start = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            end = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}
            properties = {
                "isacl": True,
                "description": "End has managedBy attribute with start principal. "
                               "You can get keytab for end if you obtain start."
            }

        elif "ipaallowedtoperform" in attr_lower and end_object["id"] != entry["id"]:
            start = {"id": end_object["id"], "labels": [end_type], "properties": {"objectid": end_object["objectid"]}}
            end = {"id": entry["id"], "labels": [entry["type"]], "properties": {"objectid": entry["objectid"]}}

            if attr_lower == "ipaallowedtoperform;write_keys":
                rel_type = "ForceChangePassword"
            elif attr_lower == "ipaallowedtoperform;read_keys":
                rel_type = "ReadKerberosKey"
            elif attr_lower == "ipaallowedtoperform;write_delegation":
                rel_type = "AddRBCD"
            else:
                return

            properties = {
                "isacl": True,
                "description": "End has ipaAllowedToPerform attribute with start principal."
            }
        else:
            return

        relationship = self._generate_relationship_json(
            self.relationship_id, rel_type, start, end, properties
        )
        self.file_descriptor.write(json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending)
        self.relationship_id += 1

    def _check_duplicate_relationship(self, dn1: str, dn2: str) -> bool:
        if dn1 == dn2:
            return True

        key = dn1 + dn2
        if key in self.relationships:
            return True

        self.relationships[key] = True
        return False

    def _process_hbac_rules_mini(self) -> None:
        if "hbac_rule" not in self.objects:
            return

        for rule in self.objects["hbac_rule"].values():
            if not is_enabled(rule):
                continue

            self._save_object_entry(rule, "IPAGroup")

            users = self._get_rule_targets(rule, "user")
            if users == ["*"]:
                users = self.objects["IPAUser"].keys()
            hosts = self._get_rule_targets(rule, "host")
            if hosts == ["*"]:
                hosts = self.objects["IPAComputer"].keys()
            services = self._get_rule_targets(rule, "service")

            for user in users:
                for service in services:
                    if self._is_ssh_service(service):
                        self._create_mini_hbac_relationship(user, rule["dn"], memberof=True, rule=rule)
                    if self._is_sudo_service(service):
                        self._mark_sudo_access(user, rule["dn"])
                    if self.save_all_hbac:
                        self._create_mini_hbac_relationship(user, rule["dn"], service, memberof=True, rule=rule)

            for host in hosts:
                for service in services:
                    if self._is_ssh_service(service):
                        self._create_mini_hbac_relationship(rule["dn"], host, rule=rule)
                    if self._is_sudo_service(service):
                        self._mark_sudo_access(rule["dn"], host)
                    if self.save_all_hbac:
                        self._create_mini_hbac_relationship(rule["dn"], host, service, rule=rule)

    def _create_mini_hbac_relationship(self, user_dn: str, host_dn: str, service: str = "SSH", memberof=False, rule: Dict = None) -> None:
        if service == "*":
            service = "ALL"
        elif service[:3] == "cn=":
            service = service[3:service.find(",")]

        if memberof:
            label = "MemberOf"
            properties = {}
        else:
            label = f"Can{service}"
            properties = {"type": f"Can{service}"}
            if rule:
                properties.update(extract_hbac_rule_metadata(rule))

        relationship = {
            "id": self.relationship_id,
            "type": "relationship",
            "label": label,
            "properties": properties,
            "start": "",
            "end": ""
        }

        _, user_object = self._search_object(user_dn, ignore_exception=True)
        _, host_object = self._search_object(host_dn, ignore_exception=True)

        self._add_rule_relationship(
            {"type": "IPAUser", "name": user_dn, "properties": {"objectid": user_object["objectid"]}},
            {"type": "IPAComputer", "name": host_dn, "properties": {"objectid": host_object["objectid"]}},
            relationship,
            ignore_exception=True
        )

    def _process_full_hbac_rules(self) -> None:
        if "hbac_rule" not in self.objects:
            return

        for rule in self.objects["hbac_rule"].values():
            if not is_enabled(rule):
                continue

            users = self._get_rule_targets(rule, "user")
            if users == ["*"]:
                users = self.objects["IPAUser"].keys()
            hosts = self._get_rule_targets(rule, "host")
            if hosts == ["*"]:
                hosts = self.objects["IPAComputer"].keys()
            services = self._get_rule_targets(rule, "service")

            for user in users:
                for host in hosts:
                    for service in services:
                        if self._is_ssh_service(service):
                            self._create_hbac_relationship(user, host, rule=rule)
                        if self._is_sudo_service(service):
                            self._mark_sudo_access(user, host)
                        if self.save_all_hbac:
                            self._create_hbac_relationship(user, host, service, rule=rule)

    def _get_rule_targets(self, rule: Dict, target_type: str) -> List[str]:
        category_key = f"{target_type}Category"
        member_key = f"member{target_type.capitalize()}"

        if rule.get(category_key) == "all":
            return ['*']

        return rule.get(member_key, [])

    def _is_ssh_service(self, service_dn: str) -> bool:
        return service_dn == '*' or "cn=sshd,cn=hbacservices,cn=hbac" in service_dn

    def _is_sudo_service(self, service_dn: str) -> bool:
        return service_dn == '*' or "cn=Sudo,cn=hbacservicegroups,cn=hbac" in service_dn

    def _create_hbac_relationship(self, user_dn: str, host_dn: str, service: str = "SSH", rule: Dict = None) -> None:
        if service == "*":
            service = "ALL"
        elif service[:3] == "cn=":
            service = service[3:service.find(",")]

        properties = {"type": f"Can{service}"}
        if rule:
            properties.update(extract_hbac_rule_metadata(rule))

        relationship = {
            "id": self.relationship_id,
            "type": "relationship",
            "label": f"Can{service}",
            "properties": properties,
            "start": "",
            "end": ""
        }

        _, user_object = self._search_object(user_dn)
        _, host_object = self._search_object(host_dn)

        self._add_rule_relationship(
            {"type": "IPAUser", "name": user_dn, "properties": {"objectid": user_object["objectid"]}},
            {"type": "IPAComputer", "name": host_dn, "properties": {"objectid": host_object["objectid"]}},
            relationship
        )

    def _mark_sudo_access(self, user_dn: str, host_dn: str) -> None:
        self._add_rule_relationship(
            {"type": "IPAUser", "name": user_dn},
            {"type": "IPAComputer", "name": host_dn},
            {},
            add_to_sudo_access=True,
            save_relationship=False
        )

    def _process_sudo_rules(self) -> None:
        for rule in self.objects.get("sudo_rule", {}).values():
            if not is_enabled(rule):
                continue

            users = self._get_rule_targets(rule, "user")
            hosts = self._get_rule_targets(rule, "host")

            rule['Allow cmd'] = set()
            rule['Deny cmd'] = set()
            for allow_cmd in rule.get("memberAllowCmd", []):
                if "cn=sudocmdgroups,cn=sudo," in allow_cmd:
                    cmds = self.objects.get("sudo_cmd_rule", {}).get(allow_cmd, {}).get("member", [])
                else:
                    cmds = [allow_cmd]
                for cmd in cmds:
                    finaly_cmd = self.objects.get("sudo_cmd", {cmd: {'sudoCmd': cmd}})[cmd]['sudoCmd']
                    rule['Allow cmd'].add(finaly_cmd)

            for deny_cmd in rule.get("memberDenyCmd", []):
                if "cn=sudocmdgroups,cn=sudo," in deny_cmd:
                    cmds = self.objects.get("sudo_cmd_rule", {deny_cmd: {'member': [deny_cmd]}})[deny_cmd]["member"]
                else:
                    cmds = [deny_cmd]
                for cmd in cmds:
                    finaly_cmd = self.objects.get("sudo_cmd", {cmd: {'sudoCmd': cmd}})[cmd]['sudoCmd']
                    rule['Deny cmd'].add(finaly_cmd)
                    rule['Allow cmd'] -= set([finaly_cmd])

            rule['Allow cmd'] = list(rule['Allow cmd'])
            rule['Deny cmd'] = list(rule['Deny cmd'])

            for user in users:
                for host in hosts:
                    relationship = {
                        "id": self.relationship_id,
                        "type": "relationship",
                        "label": "CanSUDO",
                        "properties": dict(rule),
                        "start": "",
                        "end": ""
                    }

                    if "ipaUniqueID" in rule:
                        relationship["properties"]["objectid"] = rule["ipaUniqueID"]

                    _, user_object = self._search_object(user)
                    _, host_object = self._search_object(host)

                    self._add_rule_relationship(
                        {"type": "IPAUser", "name": user, "properties": {"objectid": user_object["objectid"]}},
                        {"type": "IPAComputer", "name": host, "properties": {"objectid": host_object["objectid"]}},
                        relationship,
                        check_sudo_access=True
                    )

    def check_hbac_access(self, access_key, start_obj, end_obj):
        if access_key in self.sudo_hbac_access:
            return True

        if "member" in end_obj:
            for group in end_obj["member"]:
                if f'{start_obj["dn"]}+{group}' in self.sudo_hbac_access:
                    return True
                if "member" in start_obj:
                    for start_group in start_obj["member"]:
                        if f'{start_group}+{group}' in self.sudo_hbac_access:
                            return True
        return False

    def add_sudo_hbac_access(self, start_obj, end_obj):
        if "member" in end_obj:
            for group in end_obj["member"]:
                self.sudo_hbac_access[f'{start_obj["dn"]}+{group}'] = True
                if "member" in start_obj:
                    for start_group in start_obj["member"]:
                        self.sudo_hbac_access[f'{start_group}+{group}'] = True

    def _add_rule_relationship(
            self,
            start_spec: Dict,
            end_spec: Dict,
            relationship: Dict,
            add_to_sudo_access: bool = False,
            check_sudo_access: bool = False,
            save_relationship: bool = True,
            ignore_exception: bool = False
    ) -> None:
        start_objects = self._get_objects_for_spec(start_spec, ignore_exception=ignore_exception)
        end_objects = self._get_objects_for_spec(end_spec, ignore_exception=ignore_exception)

        if not start_objects or not end_objects:
            return

        for start_obj in start_objects:
            relationship["start"] = self._generate_node_json(
                start_obj["id"], start_obj["type"], properties=start_spec.get("properties", {})
            )

            for end_obj in end_objects:
                access_key = f'{start_obj["dn"]}+{end_obj["dn"]}'

                if add_to_sudo_access:
                    self.sudo_hbac_access[access_key] = True
                    self.add_sudo_hbac_access(start_obj, end_obj)

                if check_sudo_access and not self.check_hbac_access(access_key, start_obj, end_obj):
                    continue

                if not save_relationship:
                    continue

                relationship["end"] = self._generate_node_json(
                    end_obj["id"], end_obj["type"], properties=end_spec.get("properties", {})
                )
                relationship["id"] = self.relationship_id

                self.file_descriptor.write(
                    json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending
                )
                self.relationship_id += 1

    def _get_objects_for_spec(self, spec: Dict, ignore_exception=False) -> List[Dict]:
        if spec["name"] == '*':
            objects = []
            for obj in self.objects.get(spec["type"], {}).values():
                if spec["type"] == "IPAUser":
                    if is_account_locked(obj):
                        continue
                    if "person" not in obj.get("objectClass", []):
                        continue
                objects.append(obj)
            return objects

        _, obj = self._search_object(spec["name"], ignore_exception=ignore_exception)
        if obj:
            if spec["type"] == "IPAUser" and is_account_locked(obj):
                return []
            return [obj]
        return []

    def _process_data(self) -> None:
        domain_obj = next(iter(self.objects.get("IPADomain", {}).values()))
        self.domain = domain_obj["associatedDomain"].upper()
        self.object_processor = ObjectProcessor(self.domain)

        self.logger.info(f"Processing domain: {self.domain}")

        trusts_exists = False
        with open(self.output_filepath, 'w') as self.file_descriptor:
            if not self.prepare_for_apoc:
                self.file_descriptor.write('{"data":[')

            with console.status("Processing objects...", spinner="aesthetic") as status:
                self._process_nodes(status)
                self._process_relationships(status)
                self._process_rules(status)
                trusts_exists = self._process_additional_relationships(status)

            if not self.prepare_for_apoc:
                total_count = self.relationship_id + self.next_object_id
                self.file_descriptor.write(
                    '{"type":"null"}],'
                    f'"meta":{{"methods":0,"type":"freeipa",'
                    f'"count":{total_count},"version":5}}}}'
                )

        if trusts_exists and self.prepare_for_apoc:
            msg = f"Your output files are: {self.output_filepath}, {self.output_filepath.stem}_trusts.json"
        else:
            msg = f"Your output file is: {self.output_filepath}"

        self.logger.info(f"Done! {msg}")

    def _process_nodes(self, status) -> None:
        for obj_type in self.objects:
            if obj_type in EDGE_TYPES:
                continue

            status.update(f"Processing {obj_type}...")

            for entry in self.objects[obj_type].values():
                if is_account_locked(entry):
                    continue

                self._save_object_entry(entry, obj_type)
                self.next_object_id += 1

    def _process_relationships(self, status) -> None:
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

    def _process_rules(self, status) -> None:
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

    def _process_additional_relationships(self, status) -> bool:
        status.update("Processing trusts...")
        trusts_exists = self._process_trusts()

        status.update("Processing domain relationships...")
        self._process_domain_relationships()

        return trusts_exists

    def _process_ca_acls(self) -> None:
        if "ca_acl" not in self.objects:
            return

        for rule in self.objects["ca_acl"].values():
            if not is_enabled(rule):
                continue

            users = self._get_rule_targets(rule, "user")
            if users == ["*"]:
                users = self.objects["IPAUser"].keys()
            hosts = self._get_rule_targets(rule, "host")
            if hosts == ["*"]:
                hosts = self.objects["IPAComputer"].keys()
            services = self._get_rule_targets(rule, "service")
            if services == ["*"]:
                services = self.objects["IPAService"].keys()
            profiles = rule.get("ipaMemberCertProfile", [])

            for profile in profiles:
                for user in users:
                    self._create_enrollment_relationship("IPAUser", user, profile)

                for host in hosts:
                    self._create_enrollment_relationship("IPAComputer", host, profile)

                for service in services:
                    self._create_enrollment_relationship("IPAService", service, profile)

    def _create_enrollment_relationship(
            self,
            source_type: str,
            source_name: str,
            profile_dn: str
    ) -> None:
        relationship = {
            "id": self.relationship_id,
            "type": "relationship",
            "label": "Enroll",
            "properties": {"isacl": True},
            "start": "",
            "end": ""
        }

        _, source_obj = self._search_object(source_name)
        _, profile_obj = self._search_object(profile_dn)

        self._add_rule_relationship(
            {"type": source_type, "name": source_name, "properties": {"objectid": source_obj["objectid"]}},
            {"type": "IPACertificateTemplate", "name": profile_dn, "properties": {"objectid": profile_obj["objectid"]}},
            relationship
        )

    def _process_s4u2proxy(self) -> None:
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
                    relationship = self._generate_relationship_json(
                        self.relationship_id,
                        "IPA_AllowedToDelegate",
                        {"id": source["id"], "labels": [source["type"]], "properties": {"objectid": source["objectid"]}},
                        {"id": target["id"], "labels": [target["type"]], "properties": {"objectid": target["objectid"]}},
                        {"isacl": True}
                    )
                    self.file_descriptor.write(json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending)
                    self.relationship_id += 1

    def _process_trusts(self) -> bool:
        if "IPATrust" not in self.objects:
            return False

        domain_dn = next(iter(self.objects["IPADomain"].values()))["dn"]

        for trust in self.objects["IPATrust"].values():
            relationship = {
                "id": self.relationship_id,
                "type": "trust_relationship",
                "label": "TrustedBy",
                "start": {
                    "objectid": trust["ipaNTTrustedDomainSID"],
                    "type": "Domain"
                },
                "end": {
                    "objectid": domain_dn,
                    "type": "IPADomain"
                }
            }

            if self.prepare_for_apoc:
                with open(f"{self.output_filepath.stem}_trusts.json", "w") as f:
                    f.write('{"data":[')
                    f.write(json.dumps(relationship, cls=ExtendedEncoder) + ',')
                    if 'ipaNTTrustType' in trust and trust['ipaNTTrustType'] == 2:
                        relationship["start"], relationship["end"] = \
                            relationship["end"], relationship["start"]
                        f.write(json.dumps(relationship, cls=ExtendedEncoder))
                    f.write('],"meta":{"methods":0,"type":"freeipa","count":2,"version":5}}')
                return True

            self.file_descriptor.write(json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending)
            self.relationship_id += 1

            if 'ipaNTTrustType' in trust and trust['ipaNTTrustType'] == 2:
                relationship["id"] = self.relationship_id
                relationship["start"], relationship["end"] = \
                    relationship["end"], relationship["start"]
                self.file_descriptor.write(
                    json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending
                )
                self.relationship_id += 1

            return True

    def _process_domain_relationships(self) -> None:
        domain_obj = next(iter(self.objects["IPADomain"].values()))

        for dn, perm in self.permissions_and_privileges.items():
            name = perm["name"].split('@')[0]

            if name in REPLICATION_PERMISSIONS:
                rel_type = "DCSync"
            else:
                continue

            relationship = self._generate_relationship_json(
                self.relationship_id,
                rel_type,
                {"id": perm["id"], "labels": ["Base"], "properties": {"objectid": perm["objectid"]}},
                self._generate_node_json(domain_obj["id"], "Base", properties={"objectid": domain_obj["objectid"]}),
                {"isacl": True}
            )

            self.file_descriptor.write(
                json.dumps(relationship, cls=ExtendedEncoder) + self.line_ending
            )
            self.relationship_id += 1

    def _process_RBCD(self):
        if "IPAComputer" not in self.objects and "IPAService" not in self.objects:
            return

        for obj in list(self.objects["IPAComputer"].values()) + list(self.objects["IPAService"].values()):
            if "memberPrincipal" not in obj:
                continue

            sources = []
            for principal in obj["memberPrincipal"]:
                source_obj = self._search_principal(principal)
                if source_obj:
                    sources.append(source_obj)

            target = obj

            for source in sources:
                relationship = self._generate_relationship_json(
                    self.relationship_id,
                    "IPA_AllowedToDelegate",
                    {"id": source["id"], "labels": ["Base"], "properties": {"objectid": source["objectid"]}},
                    {"id": target["id"], "labels": ["Base"], "properties": {"objectid": target["objectid"]}},
                    {"isacl": True}
                )


    def _write_to_file(self, part_for_save, relationship=False):
        self.file_descriptor.write(json.dumps(part_for_save, cls=ExtendedEncoder) + self.line_ending)
        self.relationship_id += 1
