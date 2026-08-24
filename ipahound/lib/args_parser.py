import logging
import argparse
from typing import List, Optional


def get_parser(dump_types: Optional[List[str]] = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='IPA BloodHound Сollector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug output'
    )

    ldap_group = parser.add_argument_group('LDAP connection parameters')
    ldap_group.add_argument(
        '-s', '--ldap-server',
        required=False,
        metavar='SERVER',
        help='IP address or DNS name of LDAP server'
    )
    ldap_group.add_argument(
        '-b', '--ldap-base-dn',
        metavar='BASE_DN',
        help='Base DN for LDAP dump (optional, defaults to auto-detection)'
    )

    auth_group = parser.add_argument_group('Authentication options')
    auth_group.add_argument(
        '-u', '--ldap-user',
        metavar='USER',
        help='Username for LDAP (you can use DN format: uid=admin,cn=users,cn=accounts,dc=positive,dc=ipa)'
    )
    auth_group.add_argument(
        '-p', '--ldap-password',
        metavar='PASSWORD',
        help='Password for LDAP authentication'
    )
    auth_group.add_argument(
        '-k', '--kerberos',
        action='store_true',
        help='Use Kerberos authentication instead of username/password'
    )

    output_group = parser.add_argument_group('Output format options')
    output_group.add_argument(
        '--save-all-hbac',
        action='store_true',
        help='Will draw all HBAC services in a graph (by default sudo and SSH)'
    )
    output_group.add_argument(
        '--add-hbac-node',
        action='store_true',
        help='Will add HBAC node. For optimization graph file size. (For big domain)'
    )
    output_group.add_argument(
        '-a', '--apoc-output',
        metavar='FILE',
        help='Output JSON for APOC neo4j plugin (recommended)'
    )
    output_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output JSON for BloodHound loader'
    )
    output_group.add_argument(
        '-O', '--opengraph-output',
        metavar='FILE',
        help='Output JSON for BloodHound CE OpenGraph ingest'
    )

    debug_group = parser.add_argument_group('Advanced options (debugging)')
    debug_group.add_argument(
        '--output-raw',
        metavar='FILE',
        help='Output RAW JSON before processing (useful for debugging)'
    )

    debug_group.add_argument(
        '--input-raw',
        metavar='FILE',
        help='Process existing RAW JSON instead of performing LDAP dump'
    )

    return parser


def post_parsing_arguments(args: argparse.Namespace, logger: logging.Logger) -> bool:
    validation_errors = []

    if args.input_raw:
        return True

    if not args.kerberos:
        if not (args.ldap_user and args.ldap_password):
            validation_errors.append('Authentication required: Use either --kerberos OR --ldap-user AND --ldap-password')
    elif args.ldap_user or args.ldap_password:
        logger.warning('Both Kerberos and username/password specified. Kerberos will be used')

    if not args.ldap_server:
        validation_errors.append('LDAP server required: Specify --ldap-server')

    if not any([args.output_raw, args.output, args.apoc_output, args.opengraph_output]):
        validation_errors.append('Output required: Specify at least one of --raw, --output, --apoc-output, OR --opengraph-output')

    if validation_errors:
        validation_errors[-1] += '\n'
        for error in validation_errors:
            logger.error(error)
        return False

    return True


BANNER = '''\
\033[0;32m _____ _____ _____\033[0;34m _____               _ 
\033[0;32m|     |  _  |  _  \033[1;37m|\033[0;34m  |  |___ _ _ ___ _| |
\033[0;32m|-   -|   __|     \033[1;37m|\033[0;34m     | . | | |   | . |
\033[0;32m|_____|__|  |__|__\033[1;37m|\033[0;34m__|__|___|___|_|_|___|
    \033[0;38;5;252m by Mikhail Sukhov (@Im10n), @ptswarm\033[0m'''
