#!/usr/bin/env python3

import sys
import json
import logging
from typing import Dict, List, Optional, Any, Tuple

from ldap3 import Server, Connection, ALL, SASL, GSSAPI, BASE, ANONYMOUS
from ldap3.core.exceptions import LDAPSocketOpenError
from rich.console import Console

from ipahound.lib.args_parser import get_parser, post_parsing_arguments, BANNER
from ipahound.lib.json_encoder import ExtendedEncoder
from ipahound.lib.logger import init_logging
from ipahound.lib.ce_object_processor import OpenGraphPostProcessing
from ipahound.lib.object_processor import PostProcessing

console = Console()

LIST_ATTRIBUTES = [
    'krbPrincipalName', 'member', 'memberOf', 'memberHost', 'memberUser',
    'memberService', 'memberManager', 'managedBy', 'aci', 'ipaMemberCertProfile',
    'ipaAllowedToPerform;read_keys', 'ipaAllowedToPerform;write_keys',
    'ipaUserAuthType', 'memberPrincipal', 'memberAllowCmd', 'memberDenyCmd'
]

PAGED_SEARCH_SIZE = 1000
PAGED_CONTROL_OID = '1.2.840.113556.1.4.319'


class LDAPPathConfig:

    PATHS = {
        'DOMAIN': {
            'filter': '(objectClass=domain)',
            'path': '{}',
            'type': 'IPADomain',
            'attributes': '*',
            'search_scope': 'BASE'
        },
        'USERS': {
            'filter': '(objectClass=person)',
            'path': 'cn=users,cn=accounts,{}',
            'type': 'IPAUser',
            'attributes': ['*', 'nsaccountlock']
        },
        'SYS_USERS': {
            'filter': '(objectClass=account)',
            'path': 'cn=sysaccounts,cn=etc,{}',
            'type': 'IPAUser',
            'attributes': ['*', 'nsaccountlock']
        },
        'EXTERNAL_USERS': {
            'filter': '(objectClass=ipaUserOverride)',
            'path': 'cn=views,cn=accounts,{}',
            'type': 'IPAUser',
            'attributes': ['*', 'nsaccountlock']
        },
        'SYS_GROUP': {
            'filter': '(objectClass=GroupOfNames)',
            'path': 'cn=sysaccounts,cn=etc,{}',
            'type': 'IPAGroup',
            'attributes': ['*']
        },
        'GROUPS': {
            'filter': '(objectClass=groupOfNames)',
            'path': 'cn=groups,cn=accounts,{}',
            'type': 'IPAGroup',
            'attributes': '*'
        },
        'HOST_GROUPS': {
            'filter': '(objectClass=groupOfNames)',
            'path': 'cn=hostgroups,cn=accounts,{}',
            'type': 'IPAGroup',
            'attributes': '*'
        },
        'COMPUTERS': {
            'filter': '(objectClass=ipahost)',
            'path': 'cn=computers,cn=accounts,{}',
            'type': 'IPAComputer',
            'attributes': '*'
        },
        'SERVICES': {
            'filter': '(objectClass=ipaservice)',
            'path': 'cn=services,cn=accounts,{}',
            'type': 'IPAService',
            'attributes': '*'
        },
        'HBAC_SERVICES': {
            'filter': '(objectClass=ipahbacservice)',
            'path': 'cn=hbacservices,cn=hbac,{}',
            'type': 'hbac_service',
            'attributes': '*'
        },
        'HBAC_RULES': {
            'filter': '(objectClass=ipahbacrule)',
            'path': 'cn=hbac,{}',
            'type': 'hbac_rule',
            'attributes': '*'
        },
        'PBAC_PERMISSIONS': {
            'filter': '(objectClass=ipapermission)',
            'path': 'cn=permissions,cn=pbac,{}',
            'type': 'IPAPermission',
            'attributes': '*'
        },
        'PBAC_PRIVILEGES': {
            'filter': '(objectClass=groupofnames)',
            'path': 'cn=privileges,cn=pbac,{}',
            'type': 'IPAGroup',
            'attributes': '*'
        },
        'SUDO_RULES': {
            'filter': '(objectClass=ipasudorule)',
            'path': 'cn=sudorules,cn=sudo,{}',
            'type': 'sudo_rule',
            'attributes': '*'
        },
        'SUDO_CMD_GROUP': {
            'filter': '(objectClass=ipasudocmdgrp)',
            'path': 'cn=sudocmdgroups,cn=sudo,{}',
            'type': 'sudo_cmd_rule',
            'attributes': '*'
        },
        'SUDO_CMD': {
            'filter': '(objectClass=ipasudocmd)',
            'path': 'cn=sudocmds,cn=sudo,{}',
            'type': 'sudo_cmd',
            'attributes': '*'
        },
        'CAACLS': {
            'filter': '(objectClass=ipacaacl)',
            'path': 'cn=caacls,cn=ca,{}',
            'type': 'ca_acl',
            'attributes': '*'
        },
        'CERT_PROFILES': {
            'filter': '(objectClass=ipacertprofile)',
            'path': 'cn=certprofiles,cn=ca,{}',
            'type': 'IPACertificateTemplate',
            'attributes': '*'
        },
        'CAS': {
            'filter': '(objectClass=ipaca)',
            'path': 'cn=cas,cn=ca,{}',
            'type': 'IPACA',
            'attributes': '*'
        },
        'S4U2Proxys': {
            'filter': '(objectClass=groupOfPrincipals)',
            'path': 'cn=s4u2proxy,cn=etc,{}',
            'type': 'S4U2Proxy',
            'attributes': '*'
        },
        'NG_ALT': {
            'filter': '(objectClass=IPAnisNetGroup)',
            'path': 'cn=ng,cn=alt,{}',
            'type': 'IPAGroup',
            'attributes': '*'
        },
        'Roles': {
            'filter': '(objectClass=groupofnames)',
            'path': 'cn=roles,cn=accounts,{}',
            'type': 'IPARole',
            'attributes': '*'
        },
        'SeLinux': {
            'filter': '(objectClass=ipaselinuxusermap)',
            'path': 'cn=usermap,cn=selinux,{}',
            'type': 'IPASeLinux',
            'attributes': '*'
        },
        'Trust': {
            'filter': '(objectClass=ipaNTTrustedDomain)',
            'path': 'cn=ad,cn=trusts,{}',
            'type': 'IPATrust',
            'attributes': '*'
        }
    }


class PermissionCheck:

    def __init__(self, dump_flag: str, type_name: str, is_attr: bool,
                 attr: Optional[List[str]], help_text: str):
        self.status = False
        self.dump_flag = dump_flag
        self.type = type_name
        self.is_attr = is_attr
        self.attr = attr if attr else []
        self.help = help_text


class LDAPCollector:

    def __init__(
        self,
        ldap_server: str,
        ldap_user: str,
        ldap_password: str,
        ldap_base_dn: Optional[str],
        use_kerberos: bool,
        dump_types: List[str]
    ):
        self.ldap_server = ldap_server
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.ldap_base_dn = ldap_base_dn
        self.use_kerberos = use_kerberos
        self.conn: Optional[Connection] = None
        self.results: Dict[str, List] = {}

        self.ldap_paths = LDAPPathConfig.PATHS
        self.dump_types = (
            self.ldap_paths.keys() if dump_types[0] == 'all'
            else dump_types
        )

        self._init_permission_checks()

        if not self.ldap_base_dn:
            self.ldap_base_dn = self._get_base_dn()

    def _init_permission_checks(self) -> None:
        self.permission_checks = {
            'computer_unconstrained_delegation': PermissionCheck(
                'COMPUTERS', 'Computer', True, ['krbTicketFlags'],
                'No "krbTicketFlags" in computer accounts, try again with more privileges.'
            ),
            'service_unconstrained_delegation': PermissionCheck(
                'SERVICES', 'Service', True, ['krbTicketFlags'],
                'No "krbTicketFlags" in service accounts, try again with more privileges.'
            ),
            'S4U2Proxy': PermissionCheck(
                'S4U2Proxys', 'S4U2Proxy', False, None,
                'No entries in the "cn=s4u2proxy,cn=..." DN, try again with more privileges.'
            ),
            'computer_ipaAllowedToPerform': PermissionCheck(
                'COMPUTERS', 'Computer', True,
                ['ipaAllowedToPerform;read_keys', 'ipaAllowedToPerform;write_keys'],
                'No "ipaAllowedToPerform" in computer accounts, try again with more privileges.'
            ),
            'service_ipaAllowedToPerform': PermissionCheck(
                'SERVICES', 'Service', True,
                ['ipaAllowedToPerform;read_keys', 'ipaAllowedToPerform;write_keys'],
                'No "ipaAllowedToPerform" in service accounts, try again with more privileges.'
            ),
            'computer_RBCD': PermissionCheck(
                'COMPUTERS', 'Computer', True, ['memberPrincipal'],
                'No "memberPrincipal" in computer accounts, try again with more privileges.'
            ),
            'service_RBCD': PermissionCheck(
                'SERVICES', 'Service', True, ['memberPrincipal'],
                'No "memberPrincipal" in service accounts, try again with more privileges.'
            ),
            'HBAC_SERVICES': PermissionCheck(
                'HBAC_SERVICES', 'hbac_service', False, None,
                'No entries in the "cn=hbacservices,cn=hbac,cn=..." DN, try again with more privileges.'
            ),
            'HBAC_RULES': PermissionCheck(
                'HBAC_RULES', 'hbac_rule', False, None,
                'No entries in the "cn=hbac,cn=..." DN, try again with more privileges.'
            ),
            'PBAC_PERMISSIONS': PermissionCheck(
                'PBAC_PERMISSIONS', 'Permission', False, None,
                'No entries in the "cn=hbacservices,cn=hbac,cn=..." DN, try again with more privileges.'
            ),
            'PBAC_PRIVILEGES': PermissionCheck(
                'PBAC_PRIVILEGES', 'Group', False, None,
                'No entries in the "cn=hbac,cn=..." DN, try again with more privileges.'
            )
        }

    def _get_base_dn(self) -> str:
        logging.debug('Trying to get base DN from LDAP server root')

        try:
            conn = Connection(
                Server(self.ldap_server),
                auto_bind=True,
                authentication=ANONYMOUS
            )

            conn.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope=BASE,
                attributes=['namingContexts']
            )

            if not conn.entries:
                logging.error("Couldn't get data from the server")
                return ''

            entry = conn.entries[0]
            if 'namingContexts' not in entry:
                logging.error('The namingContexts attribute was not found')
                return ''

            dc_contexts = [
                context for context in entry['namingContexts'].values
                if 'dc=' in context.lower()
            ]

            if not dc_contexts:
                logging.error('No DC contexts found')
                return ''

            if len(dc_contexts) > 1:
                logging.info(
                    'Multiple namingContexts found. Set one with --ldap-base-dn:'
                )
                for context in dc_contexts:
                    print(f'  - {context}')

            logging.debug(f'Using "{dc_contexts[0]}" as IPA root DN')
            return dc_contexts[0]

        except Exception as e:
            logging.error(f'Error getting base DN: {e}')
            return ''
        finally:
            if 'conn' in locals():
                conn.unbind()

    def connect(self) -> bool:
        logging.debug(f"Connecting to {self.ldap_server} {'using Kerberos' if self.use_kerberos else f'as {self.ldap_user}'}")

        server = Server(self.ldap_server, get_info=ALL)

        try:
            if self.use_kerberos:
                logging.debug('Using Kerberos authentication')
                self.conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=GSSAPI,
                    auto_bind=True
                )
            else:
                if ',dc=' not in self.ldap_user.lower():
                    self.ldap_user = (f'uid={self.ldap_user},cn=users,cn=accounts,{self.ldap_base_dn}')
                self.conn = Connection(
                    server,
                    self.ldap_user,
                    self.ldap_password,
                    auto_bind=True
                )

            return True

        except LDAPSocketOpenError as err:
            logging.error(f'Error connecting to LDAP server: {err}')
            return False

    def disconnect(self) -> None:
        if self.conn:
            try:
                self.conn.unbind()
            except Exception as e:
                logging.debug(f'Error unbinding connection: {e}')
            finally:
                self.conn = None

    def _get_data(
        self,
        dn: str,
        ldap_filter: str,
        attributes: Any = '*',
        search_scope: str = 'SUBTREE'
    ) -> List:
        logging.debug(f'Getting data with filter "{ldap_filter}" and DN "{dn}"')

        all_entries = []
        cookie = None

        with console.status(
            'Retrieved 0 results total.',
            spinner='aesthetic'
        ) as status:
            while True:
                self.conn.search(
                    dn,
                    ldap_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    paged_size=PAGED_SEARCH_SIZE,
                    paged_cookie=cookie
                )

                all_entries.extend(self.conn.entries)

                controls = self.conn.result.get('controls', {})
                cookie_data = controls.get(PAGED_CONTROL_OID, {})
                cookie = cookie_data.get('value', {}).get('cookie')

                status.update(f'Retrieved {len(all_entries)} results total.')

                if not cookie:
                    break

        logging.debug(f'Retrieved {len(all_entries)} entries')
        return all_entries

    def _search_attributes(
        self,
        attr_list: List[str],
        ldap_objects: List
    ) -> bool:
        for ldap_obj in ldap_objects:
            obj_attrs = ldap_obj.entry_attributes_as_dict
            if any(attr in obj_attrs for attr in attr_list):
                return True
        return False

    def _check_dump_permissions(
        self,
        result: List,
        dump_flag: str
    ) -> None:
        for check_name, check in self.permission_checks.items():
            if check.status or dump_flag != check.dump_flag:
                continue

            if check.is_attr:
                if self._search_attributes(check.attr, result):
                    check.status = True
            elif result:
                check.status = True

    def dump_ldap_data(self) -> None:
        for dump_type in self.dump_types:
            ldap_path = self.ldap_paths[dump_type]
            type_name = ldap_path['type']

            if type_name not in self.results:
                self.results[type_name] = []

            search_scope = ldap_path.get('search_scope', 'SUBTREE')

            result = self._get_data(
                ldap_path['path'].format(self.ldap_base_dn),
                ldap_path['filter'],
                ldap_path['attributes'],
                search_scope
            )

            self.results[type_name].extend(result)
            self._check_dump_permissions(result, dump_type)

        self._report_permission_issues()

    def _report_permission_issues(self) -> None:
        for check in self.permission_checks.values():
            if not check.status:
                logging.warning(check.help)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


def dump_ldap_to_json(
    dump_results: Dict[str, List],
    filename: Optional[str] = None
) -> Optional[List[Dict]]:
    all_data = []

    for entry_type, entries in dump_results.items():
        type_data = {
            'meta': {
                'type': entry_type,
                'count': len(entries),
                'methods': 0,
                'version': 4
            },
            'data': {}
        }

        for entry in entries:
            attributes = _process_entry_attributes(entry)
            type_data['data'][entry.entry_dn] = attributes

        all_data.append(type_data)

    if filename:
        with open(filename, 'w') as f:
            json.dump(all_data, f, cls=ExtendedEncoder)
        return None

    return all_data


def _process_entry_attributes(entry) -> Dict[str, Any]:
    attributes = {
        attr: entry[attr].value
        for attr in entry.entry_attributes
        if hasattr(entry[attr], 'value')
    }

    # Set object ID
    if 'ipaNTSecurityIdentifier' in attributes:
        attributes['objectid'] = entry['ipaNTSecurityIdentifier'].value
    else:
        attributes['objectid'] = entry.entry_dn

    attributes['dn'] = entry.entry_dn

    # Convert single strings to lists for specific attributes
    for attr_name in LIST_ATTRIBUTES:
        if attr_name in attributes and isinstance(attributes[attr_name], str):
            attributes[attr_name] = [attributes[attr_name]]

    return attributes


def main():
    parser = get_parser(LDAPPathConfig.PATHS.keys())

    if len(sys.argv) == 1:
        print(BANNER + '\n')
        parser.print_usage()
        return

    args = parser.parse_args()
    init_logging(args.debug)

    if args.input_raw:
        if args.opengraph_output:
            OpenGraphPostProcessing(
                args.input_raw,
                args.opengraph_output,
                None,
                logging,
                add_hbac_node=args.add_hbac_node,
                save_all_hbac=args.save_all_hbac
            )
        else:
            PostProcessing(
                args.input_raw,
                args.output,
                args.apoc_output,
                logging,
                add_hbac_node=args.add_hbac_node,
                save_all_hbac=args.save_all_hbac
            )
        return

    if not post_parsing_arguments(args, logging):
        parser.print_usage()
        return

    with LDAPCollector(
            args.ldap_server,
            args.ldap_user,
            args.ldap_password,
            args.ldap_base_dn,
            args.kerberos,
            ['all']
    ) as collector:

        if not collector.connect():
            return

        collector.dump_ldap_data()

        if args.output_raw:
            dump_ldap_to_json(collector.results, args.output_raw)

        if args.output or args.apoc_output:
            json_data = dump_ldap_to_json(collector.results, None)
            PostProcessing(
                None,
                args.output,
                args.apoc_output,
                logging,
                json_data,
                add_hbac_node=args.add_hbac_node,
                save_all_hbac=args.save_all_hbac
            )

        if args.opengraph_output:
            json_data = dump_ldap_to_json(collector.results, None)
            OpenGraphPostProcessing(
                None,
                args.opengraph_output,
                None,
                logging,
                json_data,
                add_hbac_node=args.add_hbac_node,
                save_all_hbac=args.save_all_hbac
            )


if __name__ == '__main__':
    main()
