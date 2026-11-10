import pytest

from ipahound.lib.ce_object_processor import OpenGraphPostProcessing
from ipahound.lib.consts import ObjectProcessor, PRIVILEGE_EDGES, REPLICATION_PERMISSIONS
from tests.conftest import make_og_processing_bare


# --- _og_node_id ---

class TestOgNodeId:

    def test_colons_replaced(self):
        og = make_og_processing_bare()
        assert og._og_node_id("abc:def") == "abc_def"

    def test_no_colons(self):
        og = make_og_processing_bare()
        assert og._og_node_id("S-1-5-21") == "S-1-5-21"

    def test_empty_string(self):
        og = make_og_processing_bare()
        assert og._og_node_id("") == ""

    def test_none(self):
        og = make_og_processing_bare()
        assert og._og_node_id(None) == ""

    def test_numeric(self):
        og = make_og_processing_bare()
        assert og._og_node_id(12345) == "12345"

    def test_multiple_colons(self):
        og = make_og_processing_bare()
        assert og._og_node_id("a:b:c") == "a_b_c"


# --- _create_member_relationship ---

class TestCeCreateMemberRelationship:

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
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAGroup", "memberof")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_MemberOf"

    def test_member(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAGroup", "member")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_MemberOf"

    def test_member_manager(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAGroup", "memberManager")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_AddMember"

    def test_managed_by(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAService", "managedBy")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_Owns"

    def test_managed_by_self_reference(self):
        og = make_og_processing_bare()
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
        og._create_member_relationship(entry, end_object, "IPAUser", "managedBy")
        assert len(og.og_edges) == 0

    def test_ipa_allowed_write_keys(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;write_keys")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_ForceChangePassword"

    def test_ipa_allowed_read_keys(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;read_keys")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_ReadKerberosKey"

    def test_ipa_allowed_write_delegation(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;write_delegation")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_AddRBCD"

    def test_ipa_allowed_unknown_variant(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAUser", "ipaAllowedToPerform;foo")
        assert len(og.og_edges) == 0

    def test_unknown_attribute(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAUser", "someRandomAttr")
        assert len(og.og_edges) == 0

    def test_duplicate_relationship_skipped(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAGroup", "memberof")
        og._create_member_relationship(entry, end_object, "IPAGroup", "memberof")
        assert len(og.og_edges) == 1

    def test_ipa_external_member(self):
        og = make_og_processing_bare()
        entry, end_object = self._make_entry_and_end()
        og._create_member_relationship(entry, end_object, "IPAGroup", "ipaExternalMember")
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_MemberOf"


# --- _create_mini_hbac_relationship ---

class TestCeCreateMiniHbacRelationship:

    def _setup_objects(self, og):
        og.objects = {
            "IPAUser": {
                "uid=alice,cn=users,dc=ipa,dc=local": {
                    "dn": "uid=alice,cn=users,dc=ipa,dc=local",
                    "id": 1,
                    "type": "IPAUser",
                    "objectid": "S-1-5-1001",
                }
            },
            "IPAComputer": {
                "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local": {
                    "dn": "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
                    "id": 2,
                    "type": "IPAComputer",
                    "objectid": "S-1-5-2001",
                }
            },
        }

    def test_wildcard_service(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        og._create_mini_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            service="*",
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_CanALL"

    def test_cn_service(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        og._create_mini_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            service="cn=sshd,cn=hbacservices,cn=hbac",
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_Cansshd"

    def test_memberof(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        og._create_mini_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            memberof=True,
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_MemberOf"

    def test_user_not_found_creates_missing_object(self):
        og = make_og_processing_bare()
        og.objects = {"IPAComputer": {}}
        og._create_mini_hbac_relationship("uid=nonexistent", "fqdn=dc01", service="SSH")
        # _search_object creates missing objects, so edge is still created
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 1  # missing object node was created

    def test_host_not_found_creates_missing_object(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1"}
            }
        }
        og._create_mini_hbac_relationship("uid=alice", "fqdn=nonexistent", service="SSH")
        # _search_object creates missing objects, so edge is still created
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 1  # missing object node was created

    def test_rule_metadata_in_properties(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        rule = {"cn": "test_rule", "description": "A test rule"}
        og._create_mini_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            memberof=False,
            rule=rule,
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0].get("properties", {}).get("rule_name") == "test_rule"


# --- _create_hbac_relationship ---

class TestCeCreateHbacRelationship:

    def _setup_objects(self, og):
        og.objects = {
            "IPAUser": {
                "uid=alice,cn=users,dc=ipa,dc=local": {
                    "dn": "uid=alice,cn=users,dc=ipa,dc=local",
                    "id": 1,
                    "type": "IPAUser",
                    "objectid": "S-1-5-1001",
                }
            },
            "IPAComputer": {
                "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local": {
                    "dn": "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
                    "id": 2,
                    "type": "IPAComputer",
                    "objectid": "S-1-5-2001",
                }
            },
        }

    def test_wildcard_service(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        og._create_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            service="*",
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_CanALL"

    def test_cn_service(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        og._create_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            service="cn=sshd,cn=hbacservices,cn=hbac",
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_Cansshd"

    def test_rule_provided(self):
        og = make_og_processing_bare()
        self._setup_objects(og)
        rule = {"cn": "test_rule", "description": "desc", "accessRuleType": "allow"}
        og._create_hbac_relationship(
            "uid=alice,cn=users,dc=ipa,dc=local",
            "fqdn=dc01.ipa.local,cn=computers,dc=ipa,dc=local",
            rule=rule,
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0].get("properties", {}).get("rule_name") == "test_rule"

    def test_user_not_found_creates_missing_object(self):
        og = make_og_processing_bare()
        og.objects = {"IPAComputer": {}}
        og._create_hbac_relationship("uid=nonexistent", "fqdn=dc01")
        # _search_object creates missing objects, so edge is still created
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 1

    def test_host_not_found_creates_missing_object(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1"}
            }
        }
        og._create_hbac_relationship("uid=alice", "fqdn=nonexistent")
        # _search_object creates missing objects, so edge is still created
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 1


# --- _create_missing_object ---

class TestCeCreateMissingObject:

    def test_privilege_dn(self):
        og = make_og_processing_bare()
        dn = "cn=System: Add Users,cn=privileges,cn=pbac,dc=ipa,dc=local"
        obj_type, obj = og._create_missing_object(dn)
        assert obj_type == "IPAGroup"
        assert dn in og.permissions_and_privileges
        assert len(og.og_nodes) == 1
        assert og.og_nodes[0]["kinds"] == ["IPA_Group"]

    def test_permission_dn(self):
        og = make_og_processing_bare()
        dn = "cn=System: Add Users,cn=permissions,cn=pbac,dc=ipa,dc=local"
        obj_type, obj = og._create_missing_object(dn)
        assert obj_type == "IPAPermission"
        assert dn in og.permissions_and_privileges
        assert len(og.og_nodes) == 1
        assert og.og_nodes[0]["kinds"] == ["IPA_Permission"]

    def test_role_dn(self):
        og = make_og_processing_bare()
        dn = "cn=IT Security Specialist,cn=roles,cn=accounts,dc=ipa,dc=local"
        obj_type, obj = og._create_missing_object(dn)
        assert obj_type == "IPARole"
        assert dn in og.permissions_and_privileges
        assert len(og.og_nodes) == 1
        assert og.og_nodes[0]["kinds"] == ["IPA_Role"]

    def test_sid_dn(self):
        og = make_og_processing_bare()
        obj_type, obj = og._create_missing_object("S-1-5-21-12345")
        assert obj_type == "Base"
        assert obj["name"] == "S-1-5-21-12345"
        assert len(og.og_nodes) == 1

    def test_standard_dn(self):
        og = make_og_processing_bare()
        dn = "uid=alice,cn=users,cn=accounts,dc=ipa,dc=local"
        obj_type, obj = og._create_missing_object(dn)
        assert obj_type == "Base"
        assert obj["name"] == "ALICE"
        assert dn in og.lost_objects
        assert len(og.og_nodes) == 1

    def test_next_object_id_increments(self):
        og = make_og_processing_bare()
        assert og.next_object_id == 0
        og._create_missing_object("uid=alice,cn=users,dc=ipa,dc=local")
        assert og.next_object_id == 1


# --- _save_object_entry ---

class TestCeSaveObjectEntry:

    def test_ipadomain_collected(self):
        og = make_og_processing_bare()
        entry = {
            "dn": "dc=ipa,dc=local",
            "associatedDomain": "ipa.local",
            "objectid": "S-1-5-21",
        }
        og._save_object_entry(entry, "IPADomain")
        assert len(og.og_nodes) == 1
        assert og.og_nodes[0]["properties"].get("collected") is True

    def test_ipagroup_netgroup_kind(self):
        og = make_og_processing_bare()
        entry = {
            "dn": "cn=myng,cn=ng,dc=ipa,dc=local",
            "cn": "myng",
            "objectClass": ["ipanisnetgroup"],
        }
        og._save_object_entry(entry, "IPAGroup")
        assert len(og.og_nodes) == 1
        kinds = og.og_nodes[0]["kinds"]
        assert "IPA_Group" in kinds
        assert "IPA_NetGroup" in kinds

    def test_ipagroup_hbac_rule_kind(self):
        og = make_og_processing_bare()
        entry = {
            "dn": "cn=myhbac,cn=hbac,dc=ipa,dc=local",
            "cn": "myhbac",
            "objectClass": ["ipahbacrule"],
        }
        og._save_object_entry(entry, "IPAGroup")
        assert len(og.og_nodes) == 1
        kinds = og.og_nodes[0]["kinds"]
        assert "IPA_Group" in kinds
        assert "IPA_HBACRule" in kinds

    def test_objectid_fallback_to_sid(self):
        og = make_og_processing_bare()
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "cn": "alice",
            "ipaNTSecurityIdentifier": "S-1-5-21-12345",
        }
        og._save_object_entry(entry, "IPAUser")
        assert entry["objectid"] == "S-1-5-21-12345"

    def test_objectid_fallback_to_dn(self):
        og = make_og_processing_bare()
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "cn": "alice",
        }
        og._save_object_entry(entry, "IPAUser")
        assert entry["objectid"] == "uid=alice,cn=users,dc=ipa,dc=local"

    def test_datetime_formatted(self):
        import datetime
        og = make_og_processing_bare()
        entry = {
            "dn": "uid=alice,cn=users,dc=ipa,dc=local",
            "cn": "alice",
            "krbLastPwdChange": datetime.datetime(2024, 1, 15, 10, 30, 0),
        }
        og._save_object_entry(entry, "IPAUser")
        assert len(og.og_nodes) == 1
        props = og.og_nodes[0]["properties"]
        assert props.get("krbLastPwdChange") == "10:30:00 15.01.2024"


# --- _add_rule_relationship ---

class TestCeAddRuleRelationship:

    def test_missing_objects_still_create_edge(self):
        # _search_object creates missing objects via _create_missing_object,
        # so even "missing" DNs result in objects and edges
        og = make_og_processing_bare()
        og.objects = {}
        og._add_rule_relationship(
            {"type": "IPAUser", "name": "uid=nonexistent"},
            {"type": "IPAComputer", "name": "fqdn=dc01"},
            {"label": "MemberOf"},
        )
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 2  # both missing objects created

    def test_one_existing_one_missing(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1"}
            },
        }
        og._add_rule_relationship(
            {"type": "IPAUser", "name": "uid=alice"},
            {"type": "IPAComputer", "name": "fqdn=nonexistent"},
            {"label": "MemberOf"},
        )
        assert len(og.og_edges) == 1
        assert len(og.og_nodes) >= 1  # missing end object created

    def test_add_to_sudo_access(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1", "type": "IPAUser"}
            },
            "IPAComputer": {
                "fqdn=dc01": {"dn": "fqdn=dc01", "id": 2, "objectid": "S-2", "type": "IPAComputer"}
            },
        }
        og._add_rule_relationship(
            {"type": "IPAUser", "name": "uid=alice"},
            {"type": "IPAComputer", "name": "fqdn=dc01"},
            {"label": "MemberOf"},
            add_to_sudo_access=True,
        )
        assert "uid=alice+fqdn=dc01" in og.sudo_hbac_access

    def test_check_sudo_access_no_access(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1", "type": "IPAUser"}
            },
            "IPAComputer": {
                "fqdn=dc01": {"dn": "fqdn=dc01", "id": 2, "objectid": "S-2", "type": "IPAComputer"}
            },
        }
        og._add_rule_relationship(
            {"type": "IPAUser", "name": "uid=alice"},
            {"type": "IPAComputer", "name": "fqdn=dc01"},
            {"label": "MemberOf"},
            check_sudo_access=True,
        )
        assert len(og.og_edges) == 0

    def test_og_edge_kind_from_map(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAUser": {
                "uid=alice": {"dn": "uid=alice", "id": 1, "objectid": "S-1", "type": "IPAUser"}
            },
            "IPAComputer": {
                "fqdn=dc01": {"dn": "fqdn=dc01", "id": 2, "objectid": "S-2", "type": "IPAComputer"}
            },
        }
        og._add_rule_relationship(
            {"type": "IPAUser", "name": "uid=alice"},
            {"type": "IPAComputer", "name": "fqdn=dc01"},
            {"label": "CanSUDO"},
        )
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_CanSUDO"


# --- _process_trusts ---

class TestCeProcessTrusts:

    def test_no_trusts(self):
        og = make_og_processing_bare()
        og.objects = {"IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5"}}}
        og._process_trusts()
        assert len(og.og_edges) == 0

    def test_trust_type_1(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5"}},
            "IPATrust": {
                "cn=trusted": {
                    "dn": "cn=trusted",
                    "ipaNTTrustedDomainSID": "S-1-5-99",
                    "ipaNTTrustType": 1,
                }
            },
        }
        og._process_trusts()
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_TrustedBy"

    def test_trust_type_2_bidirectional(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5"}},
            "IPATrust": {
                "cn=trusted": {
                    "dn": "cn=trusted",
                    "ipaNTTrustedDomainSID": "S-1-5-99",
                    "ipaNTTrustType": 2,
                }
            },
        }
        og._process_trusts()
        assert len(og.og_edges) == 2


# --- _process_domain_relationships ---

class TestCeProcessDomainRelationships:

    def test_replication_permission(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5", "id": 0}},
        }
        perm_dn = "cn=REPLICATION MANAGERS,cn=permissions,cn=pbac,dc=ipa"
        og.permissions_and_privileges = {
            perm_dn: {
                "id": 10,
                "type": "permissions",
                "name": "REPLICATION MANAGERS@IPA.LOCAL",
                "objectid": "S-1-5-perm",
                "dn": perm_dn,
            }
        }
        og._process_domain_relationships()
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_DSync"

    def test_non_replication_permission_skipped(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5", "id": 0}},
        }
        perm_dn = "cn=Some Other Perm,cn=permissions,cn=pbac,dc=ipa"
        og.permissions_and_privileges = {
            perm_dn: {
                "id": 10,
                "type": "permissions",
                "name": "Some Other Perm@IPA.LOCAL",
                "objectid": "S-1-5-perm",
                "dn": perm_dn,
            }
        }
        og._process_domain_relationships()
        assert len(og.og_edges) == 0

    @pytest.mark.parametrize("spec", PRIVILEGE_EDGES, ids=lambda spec: spec.label)
    def test_registry_spec_kind_emitted(self, spec):
        og = make_og_processing_bare()
        og.objects = {
            "IPADomain": {"dc=ipa": {"dn": "dc=ipa", "objectid": "S-1-5", "id": 0}},
        }
        perm_name = spec.permission_names[0]
        perm_dn = f"cn={perm_name},cn=permissions,cn=pbac,dc=ipa"
        og.permissions_and_privileges = {
            perm_dn: {
                "id": 10,
                "type": "permissions",
                "name": f"{perm_name}@IPA.LOCAL",
                "objectid": "S-1-5-perm",
                "dn": perm_dn,
            }
        }
        og._process_domain_relationships()
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == spec.og_kind
        assert og.og_edges[0]["start"]["value"] == "S-1-5-perm"
        assert og.og_edges[0]["end"]["value"] == "S-1-5"

    @pytest.mark.parametrize("spec", PRIVILEGE_EDGES, ids=lambda spec: spec.label)
    def test_og_edge_kinds_consistent_with_registry(self, spec):
        assert OpenGraphPostProcessing.OG_EDGE_KINDS[spec.label] == spec.og_kind


# --- _process_RBCD ---

class TestCeProcessRBCD:

    def test_no_computers_or_services(self):
        og = make_og_processing_bare()
        og.objects = {}
        og._process_RBCD()
        assert len(og.og_edges) == 0

    def test_object_without_member_principal(self):
        og = make_og_processing_bare()
        og.objects = {
            "IPAComputer": {
                "fqdn=dc01": {"dn": "fqdn=dc01", "id": 1, "objectid": "S-1"}
            }
        }
        og._process_RBCD()
        assert len(og.og_edges) == 0

    def test_valid_principal_creates_edge(self):
        og = make_og_processing_bare()
        og.objects = {
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
        og._process_RBCD()
        assert len(og.og_edges) == 1
        assert og.og_edges[0]["kind"] == "IPA_AllowedToDelegate"
