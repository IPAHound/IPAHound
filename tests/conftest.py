import io
import logging

import pytest

from ipahound.lib.consts import ObjectProcessor
from ipahound.lib.object_processor import PostProcessing
from ipahound.lib.ce_object_processor import OpenGraphPostProcessing


@pytest.fixture
def fake_user_entry():
    return {
        "dn": "uid=alice,cn=users,cn=accounts,dc=ipa,dc=local",
        "uid": "alice",
        "cn": "alice",
        "krbPrincipalName": ["alice@IPA.LOCAL"],
        "ipaNTSecurityIdentifier": "S-1-5-21-12345-67890-11111-1001",
        "objectClass": ["person", "inetOrgPerson", "krbPrincipalAux"],
        "nsaccountlock": False,
        "ipaEnabledFlag": True,
    }


@pytest.fixture
def fake_group_entry():
    return {
        "dn": "cn=admins,cn=groups,cn=accounts,dc=ipa,dc=local",
        "cn": "admins",
        "member": ["uid=alice,cn=users,cn=accounts,dc=ipa,dc=local"],
        "objectClass": ["groupofnames"],
    }


@pytest.fixture
def fake_domain_entry():
    return {
        "dn": "dc=ipa,dc=local",
        "associatedDomain": "ipa.local",
        "objectid": "S-1-5-21-12345-67890-11111",
    }


@pytest.fixture
def fake_computer_entry():
    return {
        "dn": "fqdn=dc01.ipa.local,cn=computers,cn=accounts,dc=ipa,dc=local",
        "fqdn": "dc01.ipa.local",
        "krbPrincipalName": ["host/dc01.ipa.local@IPA.LOCAL"],
        "objectid": "S-1-5-21-12345-67890-11111-1000",
    }


@pytest.fixture
def fake_objects(fake_user_entry, fake_group_entry, fake_domain_entry, fake_computer_entry):
    return {
        "IPADomain": {fake_domain_entry["dn"]: fake_domain_entry},
        "IPAUser": {fake_user_entry["dn"]: fake_user_entry},
        "IPAGroup": {fake_group_entry["dn"]: fake_group_entry},
        "IPAComputer": {fake_computer_entry["dn"]: fake_computer_entry},
    }


def make_post_processing_bare(**overrides):
    """Create a PostProcessing instance without running __init__."""
    pp = object.__new__(PostProcessing)
    pp.domain = "IPA.LOCAL"
    pp.next_object_id = 0
    pp.relationship_id = 0
    pp.objects = {}
    pp.relationships = {}
    pp.permissions_and_privileges = {}
    pp.sudo_hbac_access = {}
    pp.lost_objects = {}
    pp.file_descriptor = io.StringIO()
    pp.object_processor = ObjectProcessor("IPA.LOCAL")
    pp.add_hbac_node = False
    pp.save_all_hbac = False
    pp.prepare_for_apoc = False
    pp.line_ending = "\n"
    pp.logger = logging.getLogger("test")
    pp.__dict__.update(overrides)
    return pp


def make_og_processing_bare(**overrides):
    """Create an OpenGraphPostProcessing instance without running __init__."""
    og = object.__new__(OpenGraphPostProcessing)
    og.domain = "IPA.LOCAL"
    og.next_object_id = 0
    og.relationship_id = 0
    og.objects = {}
    og.relationships = {}
    og.permissions_and_privileges = {}
    og.sudo_hbac_access = {}
    og.lost_objects = {}
    og.og_nodes = []
    og.og_edges = []
    og.object_processor = ObjectProcessor("IPA.LOCAL")
    og.add_hbac_node = False
    og.save_all_hbac = False
    og._og_environment_id = "test-env"
    og.logger = logging.getLogger("test")
    og.__dict__.update(overrides)
    return og
