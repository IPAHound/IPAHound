import io
import json

import pytest

from ipahound.lib.consts import ObjectProcessor, PRIVILEGE_EDGES, REPLICATION_PERMISSIONS
from tests.conftest import make_post_processing_bare


# --- _generate_node_json ---

class TestGenerateNodeJson:

    def test_basic_structure(self):
        pp = make_post_processing_bare()
        node = pp._generate_node_json(42, "IPAUser", {"name": "alice"})
        assert node == {
            "type": "node",
            "id": 42,
            "labels": ["IPAUser", "Base"],
            "properties": {"name": "alice"},
        }

    def test_default_properties(self):
        pp = make_post_processing_bare()
        node = pp._generate_node_json(0, "Base")
        assert node["properties"] == {}

    def test_empty_label(self):
        pp = make_post_processing_bare()
        node = pp._generate_node_json(1, "Custom")
        assert node["labels"] == ["Custom", "Base"]


# --- _generate_relationship_json ---

class TestGenerateRelationshipJson:

    def test_basic_structure(self):
        pp = make_post_processing_bare()
        start = {"id": 1, "labels": ["A"], "properties": {}}
        end = {"id": 2, "labels": ["B"], "properties": {}}
        rel = pp._generate_relationship_json(10, "MemberOf", start, end, {"isacl": False})
        assert rel == {
            "id": 10,
            "type": "relationship",
            "label": "MemberOf",
            "properties": {"isacl": False},
            "start": start,
            "end": end,
        }

    def test_default_properties(self):
        pp = make_post_processing_bare()
        rel = pp._generate_relationship_json(0, "Owns", {}, {})
        assert rel["properties"] == {}


# --- _check_duplicate_relationship ---

class TestCheckDuplicateRelationship:

    def test_same_dn(self):
        pp = make_post_processing_bare()
        assert pp._check_duplicate_relationship("dn1", "dn1") is True

    def test_first_time_pair(self):
        pp = make_post_processing_bare()
        assert pp._check_duplicate_relationship("dn1", "dn2") is False

    def test_second_time_same_pair(self):
        pp = make_post_processing_bare()
        pp._check_duplicate_relationship("dn1", "dn2")
        assert pp._check_duplicate_relationship("dn1", "dn2") is True

    def test_reversed_pair_not_deduplicated(self):
        pp = make_post_processing_bare()
        pp._check_duplicate_relationship("dn1", "dn2")
        # Reversed pair uses different key, so not a duplicate
        assert pp._check_duplicate_relationship("dn2", "dn1") is False


# --- _get_rule_targets ---

class TestGetRuleTargets:

    def test_category_all(self):
        pp = make_post_processing_bare()
        rule = {"userCategory": "all"}
        assert pp._get_rule_targets(rule, "user") == ["*"]

    def test_has_members(self):
        pp = make_post_processing_bare()
        rule = {"memberUser": ["uid=alice", "uid=bob"]}
        assert pp._get_rule_targets(rule, "user") == ["uid=alice", "uid=bob"]

    def test_no_members(self):
        pp = make_post_processing_bare()
        rule = {}
        assert pp._get_rule_targets(rule, "user") == []

    def test_empty_rule(self):
        pp = make_post_processing_bare()
        assert pp._get_rule_targets({}, "host") == []

    def test_host_category_all(self):
        pp = make_post_processing_bare()
        rule = {"hostCategory": "all"}
        assert pp._get_rule_targets(rule, "host") == ["*"]


# --- _is_ssh_service ---

class TestIsSshService:

    def test_wildcard(self):
        pp = make_post_processing_bare()
        assert pp._is_ssh_service("*") is True

    def test_sshd_dn(self):
        pp = make_post_processing_bare()
        dn = "cn=sshd,cn=hbacservices,cn=hbac,cn=etc,dc=ipa,dc=local"
        assert pp._is_ssh_service(dn) is True

    def test_other_service(self):
        pp = make_post_processing_bare()
        assert pp._is_ssh_service("cn=ftp,cn=hbacservices,cn=hbac") is False


# --- _is_sudo_service ---

class TestIsSudoService:

    def test_wildcard(self):
        pp = make_post_processing_bare()
        assert pp._is_sudo_service("*") is True

    def test_sudo_dn(self):
        pp = make_post_processing_bare()
        dn = "cn=Sudo,cn=hbacservicegroups,cn=hbac,cn=etc,dc=ipa,dc=local"
        assert pp._is_sudo_service(dn) is True

    def test_other_service(self):
        pp = make_post_processing_bare()
        assert pp._is_sudo_service("cn=ftp,cn=hbacservices,cn=hbac") is False


# --- _create_member_relationship ---

class TestCreateMemberRelationship:

    def _make_entry_and_end(self):
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "id": 1,
            "type": "IPAUser",
            "objectid": "S-1-5-1001",
        }
        end_object = {
            "dn": "cn=admins,cn=groups,dc=ipa,dc=local",
            "id": 2,
            "type": "IPAGroup",
            "objectid": "S-1-5-2001",
        }
        return entry, end_object

    def test_memberof(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAGroup", "memberof")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "MemberOf"' in written

    def test_member(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAGroup", "member")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "MemberOf"' in written

    def test_member_manager(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAGroup", "memberManager")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "AddMember"' in written

    def test_managed_by(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAService", "managedBy")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "Owns"' in written

    def test_managed_by_self_reference(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "id": 1,
            "type": "IPAUser",
            "objectid": "S-1-5-1001",
        }
        end_object = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "id": 1,
            "type": "IPAUser",
            "objectid": "S-1-5-1001",
        }
        pp._create_member_relationship(entry, end_object, "IPAUser", "managedBy")
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_ipa_allowed_write_keys(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;write_keys")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "ForceChangePassword"' in written

    def test_ipa_allowed_read_keys(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;read_keys")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "ReadKerberosKey"' in written

    def test_ipa_allowed_write_delegation(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;write_delegation")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "AddRBCD"' in written

    def test_ipa_allowed_unknown_variant(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;foo")
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_unknown_attribute(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAUser", "someRandomAttr")
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_ipa_external_member(self):
        pp = make_post_processing_bare()
        entry, end_object = self._make_entry_and_end()
        pp._create_member_relationship(entry, end_object, "IPAGroup", "ipaExternalMember")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert '"label": "MemberOf"' in written


# --- _create_missing_object ---

class TestCreateMissingObject:

    def test_dn_no_equals(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        obj_type, obj = pp._create_missing_object("some-random-string")
        assert obj["name"] == "some-random-string"
        assert obj_type == "Base"

    def test_dn_sid(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        obj_type, obj = pp._create_missing_object("S-1-5-21-12345")
        assert obj["name"] == "S-1-5-21-12345"
        assert obj_type == "Base"

    def test_privilege_dn(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        dn = "cn=System: Add Users,cn=privileges,cn=pbac,dc=ipa,dc=local"
        obj_type, obj = pp._create_missing_object(dn)
        assert obj_type == "IPAGroup"
        assert dn in pp.permissions_and_privileges

    def test_permission_dn(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        dn = "cn=System: Add Users,cn=permissions,cn=pbac,dc=ipa,dc=local"
        obj_type, obj = pp._create_missing_object(dn)
        assert obj_type == "IPAPermission"
        assert dn in pp.permissions_and_privileges

    def test_role_dn(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        dn = "cn=IT Security Specialist,cn=roles,cn=accounts,dc=ipa,dc=local"
        obj_type, obj = pp._create_missing_object(dn)
        assert obj_type == "IPARole"
        assert dn in pp.permissions_and_privileges

    def test_standard_dn(self):
        pp = make_post_processing_bare(file_descriptor=io.StringIO())
        dn = "uid=alice,cn=users,cn=accounts,dc=ipa,dc=local"
        obj_type, obj = pp._create_missing_object(dn)
        assert obj_type == "Base"
        assert obj["name"] == "ALICE"
        assert dn in pp.lost_objects


# --- _add_type_specific_properties ---

class TestAddTypeSpecificProperties:

    def test_certificate_template(self):
        pp = make_post_processing_bare()
        entry = {"dn": "cn=TestTemplate"}
        pp._add_type_specific_properties(entry, "IPACertificateTemplate")
        assert entry["Enabled"] is True

    def test_user_no_auth_type(self):
        pp = make_post_processing_bare()
        entry = {"dn": "uid=alice"}
        pp._add_type_specific_properties(entry, "IPAUser")
        assert entry["PasswordAuthAllow"] is True

    def test_user_auth_type_without_password(self):
        pp = make_post_processing_bare()
        entry = {"dn": "uid=alice", "ipaUserAuthType": ["otp"]}
        pp._add_type_specific_properties(entry, "IPAUser")
        assert entry["PasswordAuthAllow"] is False

    def test_user_auth_type_with_password(self):
        pp = make_post_processing_bare()
        entry = {"dn": "uid=alice", "ipaUserAuthType": ["password", "otp"]}
        pp._add_type_specific_properties(entry, "IPAUser")
        assert entry["PasswordAuthAllow"] is True

    def test_user_with_certificate(self):
        pp = make_post_processing_bare()
        entry = {"dn": "uid=alice", "usercertificate": b"cert-data"}
        pp._add_type_specific_properties(entry, "IPAUser")
        assert entry["HaveCert"] is True

    def test_domain_highvalue(self):
        pp = make_post_processing_bare()
        entry = {"dn": "dc=ipa,dc=local"}
        pp._add_type_specific_properties(entry, "IPADomain")
        assert entry["highvalue"] is True

    def test_admins_group_highvalue(self):
        pp = make_post_processing_bare()
        entry = {"dn": "cn=admins,cn=groups,dc=ipa,dc=local", "cn": "admins"}
        pp._add_type_specific_properties(entry, "IPAGroup")
        assert entry["highvalue"] is True

    def test_trust_admins_group_highvalue(self):
        pp = make_post_processing_bare()
        entry = {"dn": "cn=trust admins,cn=groups,dc=ipa,dc=local", "cn": "trust admins"}
        pp._add_type_specific_properties(entry, "IPAGroup")
        assert entry["highvalue"] is True

    def test_sysaccounts_group_highvalue(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "cn=sysaccount,cn=sysaccounts,cn=etc,dc=ipa,dc=local",
            "cn": "sysaccount",
        }
        pp._add_type_specific_properties(entry, "IPAGroup")
        assert entry["highvalue"] is True

    def test_netgroup(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "cn=myng,cn=ng,cn=alt,dc=ipa,dc=local",
            "cn": "myng",
            "name": "myng@IPA.LOCAL",
            "objectClass": ["ipanisnetgroup"],
        }
        pp._add_type_specific_properties(entry, "IPAGroup")
        assert entry["NetGroup"] is True
        assert entry["name"].startswith("Net Group: ")

    def test_hbac_rule_group(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "cn=myhbac,cn=hbac,dc=ipa,dc=local",
            "cn": "myhbac",
            "name": "myhbac@IPA.LOCAL",
            "objectClass": ["ipahbacrule"],
        }
        pp._add_type_specific_properties(entry, "IPAGroup")
        assert entry["NetGroup"] is True
        assert entry["name"].startswith("HBAC: ")


# --- check_hbac_access ---

class TestCheckHbacAccess:

    def test_direct_key(self):
        pp = make_post_processing_bare()
        pp.sudo_hbac_access["dn1+dn2"] = True
        assert pp.check_hbac_access("dn1+dn2", {"dn": "dn1"}, {"dn": "dn2"}) is True

    def test_via_member_group(self):
        pp = make_post_processing_bare()
        pp.sudo_hbac_access["dn1+cn=group"] = True
        end_obj = {"dn": "dn2", "member": ["cn=group"]}
        assert pp.check_hbac_access("dn1+dn2", {"dn": "dn1"}, end_obj) is True

    def test_via_start_member_group(self):
        pp = make_post_processing_bare()
        pp.sudo_hbac_access["cn=startgroup+cn=endgroup"] = True
        start_obj = {"dn": "dn1", "member": ["cn=startgroup"]}
        end_obj = {"dn": "dn2", "member": ["cn=endgroup"]}
        assert pp.check_hbac_access("dn1+dn2", start_obj, end_obj) is True

    def test_no_match(self):
        pp = make_post_processing_bare()
        assert pp.check_hbac_access("dn1+dn2", {"dn": "dn1"}, {"dn": "dn2"}) is False

    def test_no_match_with_members(self):
        pp = make_post_processing_bare()
        start_obj = {"dn": "dn1", "member": ["cn=startgroup"]}
        end_obj = {"dn": "dn2", "member": ["cn=endgroup"]}
        assert pp.check_hbac_access("dn1+dn2", start_obj, end_obj) is False


# --- add_sudo_hbac_access ---

class TestAddSudoHbacAccess:

    def test_populates_keys(self):
        pp = make_post_processing_bare()
        start_obj = {"dn": "dn1"}
        end_obj = {"dn": "dn2", "member": ["cn=group"]}
        pp.add_sudo_hbac_access(start_obj, end_obj)
        assert "dn1+cn=group" in pp.sudo_hbac_access

    def test_populates_with_start_member(self):
        pp = make_post_processing_bare()
        start_obj = {"dn": "dn1", "member": ["cn=startgroup"]}
        end_obj = {"dn": "dn2", "member": ["cn=endgroup"]}
        pp.add_sudo_hbac_access(start_obj, end_obj)
        assert "dn1+cn=endgroup" in pp.sudo_hbac_access
        assert "cn=startgroup+cn=endgroup" in pp.sudo_hbac_access

    def test_missing_member_key(self):
        pp = make_post_processing_bare()
        start_obj = {"dn": "dn1"}
        end_obj = {"dn": "dn2"}
        # Should not raise
        pp.add_sudo_hbac_access(start_obj, end_obj)
        assert len(pp.sudo_hbac_access) == 0


# --- _process_member_attribute ---

class TestProcessMemberAttribute:

    def test_skips_missing_attribute(self):
        pp = make_post_processing_bare()
        entry = {"dn": "cn=group,dc=ipa", "id": 1, "type": "IPAGroup", "objectid": "S-1-1"}
        pp._process_member_attribute(entry, "member")
        assert pp.relationship_id == 0

    def test_skips_locked_account(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "cn=group,dc=ipa",
            "id": 1,
            "type": "IPAGroup",
            "objectid": "S-1-1",
            "member": ["uid=alice,cn=users,dc=ipa,dc=local"],
            "nsaccountlock": True,
        }
        pp._process_member_attribute(entry, "member")
        assert pp.relationship_id == 0

    def test_processes_members(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAUser": {
                "uid=alice,cn=users,dc=ipa,dc=local": {
                    "dn": "uid=alice,cn=users,dc=ipa,dc=local",
                    "id": 10,
                    "type": "IPAUser",
                    "objectid": "S-1-5-1001",
                }
            }
        }
        entry = {
            "dn": "cn=admins,cn=groups,dc=ipa,dc=local",
            "id": 1,
            "type": "IPAGroup",
            "objectid": "S-1-5-2001",
            "member": ["uid=alice,cn=users,dc=ipa,dc=local"],
        }
        pp._process_member_attribute(entry, "member")
        assert pp.relationship_id == 1
        written = pp.file_descriptor.getvalue()
        assert "MemberOf" in written


# --- _save_object_entry ---

class TestSaveObjectEntry:

    def test_writes_node_to_file(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAUser": {
                "uid=alice,cn=users,dc=ipa,dc=local": {
                    "dn": "uid=alice,cn=users,dc=ipa,dc=local",
                    "cn": "alice",
                    "krbPrincipalName": ["alice@IPA.LOCAL"],
                }
            }
        }
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "cn": "alice",
            "krbPrincipalName": ["alice@IPA.LOCAL"],
        }
        pp._save_object_entry(entry, "IPAUser")
        written = pp.file_descriptor.getvalue()
        assert written  # something was written
        assert '"type": "node"' in written

    def test_coerces_list_attributes(self):
        pp = make_post_processing_bare()
        entry = {
            "dn": "cn=group,dc=ipa",
            "cn": "group",
            "krbPrincipalName": "single@REALM",  # string, not list
        }
        pp._save_object_entry(entry, "IPAGroup")
        assert isinstance(entry["krbPrincipalName"], list)


# --- _process_domain_relationships ---

class TestProcessDomainRelationships:

    def setup_method(self):
        self.pp = make_post_processing_bare()
        self.pp.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5", "id": 0}},
        }

    def _add_permission(self, name):
        perm_dn = f"cn={name},cn=permissions,cn=pbac,dc=ipa"
        self.pp.permissions_and_privileges[perm_dn] = {
            "id": 10,
            "type": "permissions",
            "name": f"{name}@IPA.LOCAL",
            "objectid": "S-1-5-perm",
            "dn": perm_dn,
        }
        return perm_dn

    @pytest.mark.parametrize("perm_name", REPLICATION_PERMISSIONS)
    def test_replication_permission_writes_dcsync_edge(self, perm_name):
        self._add_permission(perm_name)
        self.pp._process_domain_relationships()
        written = self.pp.file_descriptor.getvalue()
        assert '"label": "DCSync"' in written
        assert '"isacl": true' in written
        assert self.pp.relationship_id == 1

    def test_edge_connects_permission_to_domain(self):
        self._add_permission("REPLICATION MANAGERS")
        self.pp._process_domain_relationships()
        relationship = json.loads(self.pp.file_descriptor.getvalue())
        assert relationship["start"]["properties"]["objectid"] == "S-1-5-perm"
        assert relationship["end"]["properties"]["objectid"] == "S-1-5"

    def test_description_from_spec_in_properties(self):
        self._add_permission("REPLICATION MANAGERS")
        self.pp._process_domain_relationships()
        relationship = json.loads(self.pp.file_descriptor.getvalue())
        assert relationship["properties"]["description"] == \
            "DCSync rights inferred from replication manager permissions"

    def test_non_matching_permission_skipped(self):
        self._add_permission("Some Other Perm")
        self.pp._process_domain_relationships()
        assert self.pp.file_descriptor.getvalue() == ""
        assert self.pp.relationship_id == 0

    @pytest.mark.parametrize("spec", PRIVILEGE_EDGES, ids=lambda spec: spec.label)
    def test_registry_spec_label_emitted(self, spec):
        self._add_permission(spec.permission_names[0])
        self.pp._process_domain_relationships()
        written = self.pp.file_descriptor.getvalue()
        assert f'"label": "{spec.label}"' in written


# --- _process_RBCD ---

class TestProcessRBCD:

    def test_no_computers_or_services(self):
        pp = make_post_processing_bare()
        pp.objects = {}
        pp._process_RBCD()
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_object_without_member_principal(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAComputer": {
                "fqdn=dc01": {"dn": "fqdn=dc01", "id": 1, "objectid": "S-1"}
            }
        }
        pp._process_RBCD()
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_unresolvable_principal_skipped(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAComputer": {
                "fqdn=dc01": {
                    "dn": "fqdn=dc01",
                    "id": 1,
                    "objectid": "S-1-5-2001",
                    "type": "IPAComputer",
                    "memberPrincipal": ["ghost/unknown@IPA.LOCAL"],
                }
            }
        }
        pp._process_RBCD()
        assert pp.relationship_id == 0
        assert pp.file_descriptor.getvalue() == ""

    def test_valid_principal_writes_edge(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAComputer": {
                "fqdn=dc01": {
                    "dn": "fqdn=dc01",
                    "id": 1,
                    "objectid": "S-1-5-2001",
                    "type": "IPAComputer",
                    "memberPrincipal": ["host/dc01@IPA.LOCAL"],
                }
            },
            "IPAService": {
                "krbprincipalname=host/dc01@IPA.LOCAL,cn=services,cn=accounts,dc=ipa": {
                    "dn": "krbprincipalname=host/dc01@IPA.LOCAL,cn=services,cn=accounts,dc=ipa",
                    "id": 2,
                    "objectid": "S-1-5-1001",
                    "type": "IPAService",
                    "krbPrincipalName": ["host/dc01@IPA.LOCAL"],
                }
            },
        }
        pp._process_RBCD()
        assert pp.relationship_id == 1
        relationship = json.loads(pp.file_descriptor.getvalue())
        assert relationship["label"] == "AllowedToDelegate"
        assert relationship["start"]["properties"]["objectid"] == "S-1-5-1001"
        assert relationship["end"]["properties"]["objectid"] == "S-1-5-2001"
        assert relationship["properties"] == {"isacl": True}

    def test_only_services_no_computers_no_keyerror(self):
        pp = make_post_processing_bare()
        pp.objects = {
            "IPAService": {
                "krbprincipalname=web/ipa.local@IPA.LOCAL,cn=services,cn=accounts,dc=ipa": {
                    "dn": "krbprincipalname=web/ipa.local@IPA.LOCAL,cn=services,cn=accounts,dc=ipa",
                    "id": 2,
                    "objectid": "S-1-5-1001",
                    "type": "IPAService",
                    "krbPrincipalName": ["web/ipa.local@IPA.LOCAL"],
                },
                "krbprincipalname=ldap/ipa.local@IPA.LOCAL,cn=services,cn=accounts,dc=ipa": {
                    "dn": "krbprincipalname=ldap/ipa.local@IPA.LOCAL,cn=services,cn=accounts,dc=ipa",
                    "id": 3,
                    "objectid": "S-1-5-1002",
                    "type": "IPAService",
                    "krbPrincipalName": ["ldap/ipa.local@IPA.LOCAL"],
                    "memberPrincipal": ["web/ipa.local@IPA.LOCAL"],
                },
            }
        }
        pp._process_RBCD()
        assert pp.relationship_id == 1
        relationship = json.loads(pp.file_descriptor.getvalue())
        assert relationship["label"] == "AllowedToDelegate"
        assert relationship["start"]["properties"]["objectid"] == "S-1-5-1001"
        assert relationship["end"]["properties"]["objectid"] == "S-1-5-1002"
