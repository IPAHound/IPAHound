import datetime
import json
from pathlib import Path

import pytest

from ipahound.lib.consts import (
    ObjectProcessor,
    PRIVILEGE_EDGES,
    PRIVILEGE_EDGE_BY_NAME,
    PrivilegeEdgeSpec,
    REPLICATION_PERMISSIONS,
    check_bool_attribute,
    extract_hbac_rule_metadata,
    is_account_locked,
    is_enabled,
    search_dict_case_insensitive,
)

GRAPH_DEFINITION_PATH = (
    Path(__file__).resolve().parent.parent / "BloodHound CE" / "ipahound-graph-definition.json"
)


# --- check_bool_attribute ---

class TestCheckBoolAttribute:

    @pytest.mark.parametrize("entry,attr,expected", [
        ({}, "foo", False),
        ({"foo": True}, "foo", True),
        ({"foo": False}, "foo", False),
        ({"foo": "TRUE"}, "foo", True),
        ({"foo": "true"}, "foo", True),
        ({"foo": "True"}, "foo", True),
        ({"foo": "false"}, "foo", False),
        ({"foo": "FALSE"}, "foo", False),
        ({"foo": 1}, "foo", False),
        ({"foo": 0}, "foo", False),
        ({"foo": None}, "foo", False),
        ({"foo": ["a"]}, "foo", False),
    ], ids=[
        "missing_key",
        "bool_true",
        "bool_false",
        "str_TRUE",
        "str_true",
        "str_True",
        "str_false",
        "str_FALSE",
        "int_1",
        "int_0",
        "None",
        "list",
    ])
    def test_check_bool_attribute(self, entry, attr, expected):
        assert check_bool_attribute(entry, attr) == expected


# --- is_enabled ---

class TestIsEnabled:

    def test_missing_key(self):
        assert is_enabled({}) is False

    def test_bool_true(self):
        assert is_enabled({"ipaEnabledFlag": True}) is True

    def test_str_true(self):
        assert is_enabled({"ipaEnabledFlag": "TRUE"}) is True

    def test_bool_false(self):
        assert is_enabled({"ipaEnabledFlag": False}) is False

    def test_str_false(self):
        assert is_enabled({"ipaEnabledFlag": "false"}) is False


# --- is_account_locked ---

class TestIsAccountLocked:

    def test_missing_key(self):
        assert is_account_locked({}) is False

    def test_bool_true(self):
        assert is_account_locked({"nsaccountlock": True}) is True

    def test_str_true(self):
        assert is_account_locked({"nsaccountlock": "TRUE"}) is True

    def test_bool_false(self):
        assert is_account_locked({"nsaccountlock": False}) is False


# --- extract_hbac_rule_metadata ---

class TestExtractHbacRuleMetadata:

    def test_empty_rule(self):
        assert extract_hbac_rule_metadata({}) == {}

    def test_all_fields(self):
        rule = {
            "cn": "test_rule",
            "description": "A test rule",
            "accessRuleType": "allow",
            "ipaEnabledFlag": True,
            "userCategory": "all",
            "hostCategory": "all",
            "serviceCategory": "all",
        }
        meta = extract_hbac_rule_metadata(rule)
        assert meta == {
            "rule_name": "test_rule",
            "rule_description": "A test rule",
            "rule_type": "allow",
            "rule_enabled": True,
            "user_category": "all",
            "host_category": "all",
            "service_category": "all",
        }

    def test_only_cn(self):
        rule = {"cn": "my_rule"}
        assert extract_hbac_rule_metadata(rule) == {"rule_name": "my_rule"}

    def test_category_all(self):
        rule = {"userCategory": "all"}
        meta = extract_hbac_rule_metadata(rule)
        assert "user_category" in meta
        assert meta["user_category"] == "all"

    def test_category_not_all(self):
        rule = {"userCategory": "permissive"}
        meta = extract_hbac_rule_metadata(rule)
        assert "user_category" not in meta


# --- search_dict_case_insensitive ---

class TestSearchDictCaseInsensitive:

    def test_exact_match(self):
        assert search_dict_case_insensitive({"Foo": 1}, "Foo") == 1

    def test_case_insensitive_match(self):
        assert search_dict_case_insensitive({"FOO": 1}, "foo") == 1

    def test_no_match(self):
        assert search_dict_case_insensitive({"bar": 1}, "foo") is None

    def test_empty_dict(self):
        assert search_dict_case_insensitive({}, "foo") is None

    def test_value_is_none(self):
        # The function returns None both for "not found" and for "value is None"
        assert search_dict_case_insensitive({"foo": None}, "foo") is None


# --- ObjectProcessor.get_object_name ---

class TestObjectProcessorGetObjectName:

    def setup_method(self):
        self.proc = ObjectProcessor("IPA.LOCAL")

    def test_krb_principal_name(self):
        entry = {"krbPrincipalName": ["alice@IPA.LOCAL"]}
        assert self.proc.get_object_name(entry) == "ALICE@IPA.LOCAL"

    def test_sn(self):
        entry = {"sn": "Doe"}
        assert self.proc.get_object_name(entry) == "DOE@IPA.LOCAL"

    def test_cn(self):
        entry = {"cn": "admins"}
        assert self.proc.get_object_name(entry) == "ADMINS@IPA.LOCAL"

    def test_uid_string(self):
        entry = {"uid": "alice"}
        assert self.proc.get_object_name(entry) == "ALICE@IPA.LOCAL"

    def test_uid_list(self):
        entry = {"uid": ["alice"]}
        assert self.proc.get_object_name(entry) == "ALICE@IPA.LOCAL"

    def test_ipa_original_uid(self):
        entry = {"ipaOriginalUid": "alice"}
        assert self.proc.get_object_name(entry) == "ALICE"

    def test_associated_domain(self):
        entry = {"associatedDomain": "ipa.local"}
        assert self.proc.get_object_name(entry) == "IPA.LOCAL"

    def test_dn_fallback(self):
        entry = {"dn": "uid=alice,cn=users,dc=ipa,dc=local"}
        assert self.proc.get_object_name(entry) == "UID=ALICE,CN=USERS,DC=IPA,DC=LOCAL"

    def test_priority_krb_over_cn(self):
        # krbPrincipalName has higher priority than cn
        entry = {"krbPrincipalName": ["bob@IPA.LOCAL"], "cn": "alice"}
        assert self.proc.get_object_name(entry) == "BOB@IPA.LOCAL"


# --- ObjectProcessor.process_attributes ---

class TestObjectProcessorProcessAttributes:

    def setup_method(self):
        self.proc = ObjectProcessor("IPA.LOCAL")

    def test_blacklisted_attribute_removed(self):
        entry = {"name": "test", "memberof": "cn=group,dc=ipa", "member": "uid=alice"}
        result = self.proc.process_attributes(entry)
        assert "memberof" not in result
        assert "member" not in result
        assert "name" in result

    def test_scalar_values_preserved(self):
        entry = {
            "str_val": "hello",
            "int_val": 42,
            "bool_val": True,
            "none_val": None,
            "bytes_val": b"binary",
            "dt_val": datetime.datetime(2024, 1, 1, 12, 0, 0),
        }
        result = self.proc.process_attributes(entry)
        assert result["str_val"] == "hello"
        assert result["int_val"] == 42
        assert result["bool_val"] is True
        assert result["none_val"] is None
        assert result["bytes_val"] == b"binary"
        assert result["dt_val"] == datetime.datetime(2024, 1, 1, 12, 0, 0)

    def test_list_of_strings_joined(self):
        entry = {"tags": ["a", "b", "c"]}
        result = self.proc.process_attributes(entry)
        assert result["tags"] == "a\nb\nc"

    def test_list_of_bytes_joined(self):
        entry = {"certs": [b"cert1", b"cert2"]}
        result = self.proc.process_attributes(entry)
        assert result["certs"] == b"cert1\ncert2"

    def test_empty_list(self):
        entry = {"empty": []}
        result = self.proc.process_attributes(entry)
        assert result["empty"] == ""

    def test_krb_ticket_flags_all_set(self):
        entry = {"krbTicketFlags": 0x300000}
        result = self.proc.process_attributes(entry)
        assert result["ipakrbokasdelegate"] is True
        assert result["unconstraineddelegation"] is True
        assert result["ipakrboktoauthasdelegate"] is True

    def test_krb_ticket_flags_ok_as_delegate_only(self):
        entry = {"krbTicketFlags": 0x100000}
        result = self.proc.process_attributes(entry)
        assert result["ipakrbokasdelegate"] is True
        assert result["unconstraineddelegation"] is True
        assert result["ipakrboktoauthasdelegate"] is False

    def test_krb_ticket_flags_ok_to_auth_only(self):
        entry = {"krbTicketFlags": 0x200000}
        result = self.proc.process_attributes(entry)
        assert result["ipakrbokasdelegate"] is False
        assert result["unconstraineddelegation"] is False
        assert result["ipakrboktoauthasdelegate"] is True

    def test_krb_ticket_flags_zero(self):
        entry = {"krbTicketFlags": 0}
        result = self.proc.process_attributes(entry)
        assert result["ipakrbokasdelegate"] is False
        assert result["unconstraineddelegation"] is False
        assert result["ipakrboktoauthasdelegate"] is False

    def test_no_krb_ticket_flags(self):
        entry = {"name": "test"}
        result = self.proc.process_attributes(entry)
        assert "ipakrbokasdelegate" not in result
        assert "unconstraineddelegation" not in result
        assert "ipakrboktoauthasdelegate" not in result

    def test_blacklist_case_insensitive(self):
        entry = {"MemberOf": "cn=group", "MEMBER": "uid=alice", "name": "test"}
        result = self.proc.process_attributes(entry)
        assert "MemberOf" not in result
        assert "MEMBER" not in result
        assert "name" in result


# --- PrivilegeEdgeSpec registry ---

class TestPrivilegeEdges:

    def test_registry_not_empty(self):
        assert PRIVILEGE_EDGES
        assert all(isinstance(spec, PrivilegeEdgeSpec) for spec in PRIVILEGE_EDGES)

    @pytest.mark.parametrize("spec", PRIVILEGE_EDGES, ids=lambda spec: spec.label)
    def test_spec_fields_valid(self, spec):
        assert spec.label
        assert not spec.label.startswith("IPA_")
        assert spec.og_kind.startswith("IPA_")
        assert spec.permission_names
        assert all(name == name.upper() for name in spec.permission_names)

    def test_no_name_collisions_between_specs(self):
        total_names = sum(len(spec.permission_names) for spec in PRIVILEGE_EDGES)
        assert len(PRIVILEGE_EDGE_BY_NAME) == total_names

    def test_lookup_maps_each_name_to_its_spec(self):
        for spec in PRIVILEGE_EDGES:
            for name in spec.permission_names:
                assert PRIVILEGE_EDGE_BY_NAME[name] is spec

    def test_dcsync_spec_covers_replication_permissions(self):
        dcsync = next(spec for spec in PRIVILEGE_EDGES if spec.label == "DCSync")
        assert dcsync.og_kind == "IPA_DSync"
        assert dcsync.is_acl is True
        assert set(dcsync.permission_names) == set(REPLICATION_PERMISSIONS)

    @pytest.mark.parametrize("spec", PRIVILEGE_EDGES, ids=lambda spec: spec.og_kind)
    def test_og_kind_declared_in_ce_graph_definition(self, spec):
        definition = json.loads(GRAPH_DEFINITION_PATH.read_text())
        declared_kinds = {kind["name"] for kind in definition["relationship_kinds"]}
        assert spec.og_kind in declared_kinds
