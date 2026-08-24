import datetime
from typing import Dict, List, Optional, Any, Tuple, Union

from ipahound.lib.json_encoder import ExtendedEncoder


LIST_ATTRIBUTES = [
    "krbPrincipalName", "member", "memberOf", "memberHost", "memberUser",
    "memberService", "memberManager", "managedBy", "ipaAllowedToPerform;read_keys",
    "ipaAllowedToPerform;write_keys", "ipaUserAuthType"
]

BLACKLIST_ATTRIBUTES = [
    "memberof", "member", "objectclass", "usercertificate",
    "ipasshpubkey", "usercertificate;binary", "krbExtraData"
]

EDGE_TYPES = [
    "hbac_service", "hbac_rule", "sudo_rule", "association",
    "ca_acl", "S4U2Proxy", "IPATrust", "sysaccount",
    "permissions", "privileges"
]

EDGE_ATTRIBUTES = [
    "memberOf", "member", "memberManager", "managedBy",
    "ipaAllowedToPerform;read_keys", "ipaAllowedToPerform;write_keys",
    "ipaAllowedToPerform;write_delegation", "memberHost", "memberUser", "ipaExternalMember"
]

KRB_OK_AS_DELEGATE = 0x100000
KRB_OK_TO_AUTH_AS_DELEGATE = 0x200000

HIGH_VALUE_GROUPS = ["admins", "trust admins"]
REPLICATION_PERMISSIONS = [
    "REPLICATION MANAGERS", "REPLICATION ADMINISTRATORS",
    "ADD REPLICATION AGREEMENTS", "MODIFY REPLICATION AGREEMENTS"
]


def check_bool_attribute(entry: Dict, attr: str) -> bool:
    if attr not in entry:
        return False

    value = entry[attr]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.upper() == "TRUE"
    return False


def is_enabled(entry: Dict) -> bool:
    return check_bool_attribute(entry, "ipaEnabledFlag")


def extract_hbac_rule_metadata(rule: Dict) -> Dict:
    metadata = {}
    if "cn" in rule:
        metadata["rule_name"] = rule["cn"]
    if "description" in rule:
        metadata["rule_description"] = rule["description"]
    if "accessRuleType" in rule:
        metadata["rule_type"] = rule["accessRuleType"]
    if "ipaEnabledFlag" in rule:
        metadata["rule_enabled"] = rule["ipaEnabledFlag"]
    if rule.get("userCategory") == "all":
        metadata["user_category"] = "all"
    if rule.get("hostCategory") == "all":
        metadata["host_category"] = "all"
    if rule.get("serviceCategory") == "all":
        metadata["service_category"] = "all"
    return metadata


def extract_sudo_rule_metadata(rule: Dict) -> Dict:
    metadata = {}
    if "cn" in rule:
        metadata["rule_name"] = rule["cn"]
    if "description" in rule:
        metadata["rule_description"] = rule["description"]
    if "ipaEnabledFlag" in rule:
        metadata["rule_enabled"] = rule["ipaEnabledFlag"]
    if rule.get("userCategory") == "all":
        metadata["user_category"] = "all"
    if rule.get("hostCategory") == "all":
        metadata["host_category"] = "all"
    if rule.get("cmdCategory") == "all":
        metadata["cmd_category"] = "all"
    if "ipaSudoRunAsUser" in rule:
        metadata["run_as_user"] = rule["ipaSudoRunAsUser"]
    if "ipaSudoRunAsGroup" in rule:
        metadata["run_as_group"] = rule["ipaSudoRunAsGroup"]
    if "ipaSudoOption" in rule:
        metadata["sudo_options"] = rule["ipaSudoOption"]
    if rule.get("Allow cmd"):
        metadata["allow_cmd"] = rule["Allow cmd"]
    if rule.get("Deny cmd"):
        metadata["deny_cmd"] = rule["Deny cmd"]
    return metadata


def is_account_locked(entry: Dict) -> bool:
    return check_bool_attribute(entry, "nsaccountlock")


def search_dict_case_insensitive(src_dict: Dict, key: str) -> Optional[Any]:
    key_lower = key.lower()
    for dict_key, value in src_dict.items():
        if dict_key.lower() == key_lower:
            return value
    return None


class ObjectProcessor:

    def __init__(self, domain: str):
        self.domain = domain.upper()

    def get_object_name(self, entry: Dict) -> str:
        if "krbPrincipalName" in entry:
            return entry["krbPrincipalName"][0].upper()

        if "sn" in entry:
            return f'{entry["sn"].upper()}@{self.domain}'

        if "cn" in entry:
            return f'{entry["cn"].upper()}@{self.domain}'

        if "uid" in entry:
            uid = entry["uid"]
            if isinstance(uid, list):
                uid = uid[0]
            return f'{uid.upper()}@{self.domain}'

        if 'ipaOriginalUid' in entry:
            return f'{entry["ipaOriginalUid"].upper()}'

        if "associatedDomain" in entry:
            return entry["associatedDomain"].upper()

        return entry["dn"].upper()

    def process_attributes(self, entry: Dict) -> Dict:
        processed = {}

        for key, value in entry.items():
            if key.lower() in BLACKLIST_ATTRIBUTES:
                continue

            if isinstance(value, (str, int, bool, type(None), datetime.datetime, bytes)):
                processed[key] = value
            elif isinstance(value, list) and value and isinstance(value[0], bytes):
                processed[key] = b'\n'.join(value)
            elif isinstance(value, list):
                processed[key] = '\n'.join(str(v) for v in value)
            else:
                processed[key] = value

        if "krbTicketFlags" in processed:
            flags = processed["krbTicketFlags"]
            processed["ipakrbokasdelegate"] = bool(flags & KRB_OK_AS_DELEGATE)
            processed["unconstraineddelegation"] = bool(flags & KRB_OK_AS_DELEGATE)
            processed["ipakrboktoauthasdelegate"] = bool(flags & KRB_OK_TO_AUTH_AS_DELEGATE)

        return processed