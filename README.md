<p align="center">
  <h1 align="center">IPAHound</h1>
  <p align="center">
    <strong>BloodHound Collector for FreeIPA</strong><br>
    <em>"Attackers think in graphs..."</em> — true for Linux as well!
  </p>
</p>

<p align="center">
  <img src="assets/logo.png" width="300">
</p>

> **⚠️ Disclaimer:** All information contained in this repository is provided for educational and research purposes only. The author is not responsible for any illegal use of this tool.

---

## Table of Contents

- [Overview](#overview)
- [Companion GUI](#companion-gui)
- [Quickstart](#quickstart)
- [Requirements](#requirements)
- [Types and Edges](#types-and-edges)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Loading Data into Neo4j](#loading-data-into-neo4j)
- [ToDo](#todo)
- [Additional Resources](#additional-resources)
- [Star History](#star-history)
- [Contributing](#contributing)

## Overview

IPAHound is a specialized LDAP collector designed for FreeIPA domain controllers, enabling comprehensive domain analysis through graph-based visualization. It bridges the gap between FreeIPA's complex structure and BloodHound's powerful analysis capabilities.

The collector operates in two main phases:

1. **Data Collection** - Gathering information from the FreeIPA LDAP server.
2. **Data Processing** - Creating relationships (edges) and exporting to JSON format.

Once collected, data can be imported using either:

- **APOC (Awesome Procedures On Cypher) plugin for Neo4j** (recommended - significantly faster)
- **BloodHound CE**
- **Classic BloodHound GUI** (legacy support)

### Philosophy

> From hackers for hackers

IPAHound prioritizes user-friendly functionality by simplifying FreeIPA's numerous abstractions into an intuitive format. It transforms complex FreeIPA structures into easily analyzable graphs, making your security assessment work more efficient.

## Companion GUI

Stock BloodHound does not know about FreeIPA node and edge labels and will not render them. To visualize and query the data IPAHound produces, use the companion fork:

- **[IPAHound-GUI](https://github.com/IPAHound/IPAHound-GUI)** - BloodHound fork with FreeIPA node/edge support.

## Quickstart

End-to-end, from zero to a queryable graph:

1. Install IPAHound.

    ```console
    ~$ uv tool install git+https://github.com/IPAHound/IPAHound.git
    ```

2. Collect from your FreeIPA DC (Kerberos auth shown; see Usage for password auth).

    ```console
    ~$ kinit admin
    ~$ ipahound -k -s dc01.ipa.local -a out.json
    ```

3. In Neo4j (one-time, before the very first import) - create constraints. See "Loading Data into Neo4j" below for the full constraint list.
4. Import the JSON via APOC (cypher-shell or Neo4j Browser).

    ```
    CALL apoc.import.json("/absolute/path/to/out.json");
    ```

5. Open IPAHound-GUI, point it at your Neo4j, and start hunting.

## Requirements

- **Python** ≥ 3.10
- **Neo4j** 4.x or 5.x with a matching **APOC** plugin version (the Neo4j minor version and APOC version **must** match).
- **FreeIPA** - tested against 4.9–4.11. Earlier versions may work but are not actively tested.
- Network access to LDAP/LDAPS on the FreeIPA DC, and either a valid Kerberos ticket or LDAP credentials.

## Types and Edges

### Node Types

IPAHound consolidates various FreeIPA objects into simplified node types:

|       IPAHound Type        | FreeIPA Objects                                            |
|:--------------------------:|:-----------------------------------------------------------|
|       **IPADomain**        | Root domain object                                         |
|        **IPAUser**         | Users, System Users                                        |
|        **IPAGroup**        | Groups, System Groups, Privileges, Net groups, Host groups |
|      **IPAComputer**       | Computers                                                  |
|       **IPAService**       | Services                                                   |
|     **IPAPermission**      | Permissions                                                |
|        **IPARole**         | Roles                                                      |
|         **IPACA**          | Certificate Authorities                                    |
| **IPACertificateTemplate** | Certificate Templates                                      |
|       **IPASELinux**       | SELinux rules                                              |

### Edge Types

Relationships between nodes represent various permissions and memberships:

|        Edge Type        | Description                                                                                                                                                          |
|:-----------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|      **TrustedBy**      | Trust relationships between FreeIPA domains and MS Active Directory                                                                                                  |
|      **MemberOf**       | Membership in IPAGroup, IPASELinux, IPACertificateTemplate, and others                                                                                               |
|      **AddMember**      | Ability to manage group members (via _MemberManager_ attribute)                                                                                                      |
| **ForceChangePassword** | Permission to create new Kerberos keys (_ipaAllowedToPerform;write_keys_)                                                                                            |
|   **ReadKerberosKey**   | Permission to read Kerberos keys/retrieve keytabs (_ipaAllowedToPerform;read_keys_)                                                                                  |
|        **Owns**         | Full control over Computer or Group objects (_ManagedBy_ attribute). Enables RBCD configuration, Kerberos key creation, SSH key addition, and certificate management |
|       **CanSSH**        | HBAC rule allowing SSH access                                                                                                                                        |
|       **CanSUDO**       | Combined HBAC and SUDO rules allowing sudo execution on hosts                                                                                                        |
|       **Can{*}**        | With `--save-all-hbac`, one edge per HBAC service (e.g., `Cancrond`, `CanFTP`). Edge name is derived from the service's `cn`.                                        |
|  **AllowedToDelegate**  | Constrained Delegation rights (S4U2Proxy)                                                                                                                            |
|       **Enroll**        | Permission to issue certificates                                                                                                                                     |
|       **AddRBCD**       | Permission to configure Resource-Based Constrained Delegation (_ipaAllowedToPerform;write_delegation_)                                                               |
|       **DCSync**        | DCSync rights (inferred from default permission values)                                                                                                              |

## How It Works

### Step 1: Authentication

FreeIPA LDAP servers support two authentication methods:

- **Kerberos** - Automatically uses credentials from your Kerberos ticket.
- **Simple Bind** - Requires a full DN (Distinguished Name).

For Simple Bind, the collector accepts a bare username and attempts to construct the full DN automatically. This prediction may fail in non-standard configurations; pass the full DN explicitly if it does.

DN examples:

- **User:** `uid=admin,cn=users,cn=accounts,dc=ipa,dc=local`
- **Service:** `krbprincipalname=dogtag/pc01.ipa.local@IPA.LOCAL,cn=services,cn=accounts,dc=ipa,dc=local`

### Step 2: Data Collection

The collector retrieves all accessible data based on the `LDAP_PATHS` structure. FreeIPA may restrict visibility of certain entries and attributes based on your permissions. Consider running the collector with different user accounts for comprehensive coverage.

After the run, IPAHound prints warnings such as `No "krbTicketFlags" in computer accounts, try again with more privileges.` - these are **expected** on an under-privileged bind and indicate which graph features will be missing, not a bug.

Raw data can be saved using the `--output-raw` flag for:

- Offline processing
- Debugging purposes
- Audit trails

### Step 3: Data Processing

During this phase, IPAHound:

- Analyzes raw data to create relationship edges
- Filters out disabled accounts and inactive rules
- Optimizes the graph structure for analysis

### Step 4: Export

IPAHound supports two export formats. They are **mutually exclusive** - pick one per run:

1. **APOC Format** (`-a` option) - Optimized for Neo4j APOC plugin import (recommended)
2. **Classic Format** (`-o` option) - Compatible with the classic BloodHound JSON loader

## Installation

Install [uv](https://docs.astral.sh/uv/):

```console
~$ curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install `ipahound` as a CLI tool:

```console
~$ uv tool install git+https://github.com/IPAHound/IPAHound
~$ ipahound -h
```

Install `ipahound` for development:

```console
~$ git clone https://github.com/IPAHound/IPAHound
~$ cd IPAHound
~$ uv sync
~$ uv run ipahound -h
```

The repo also ships a `poetry.lock` if you prefer [Poetry](https://python-poetry.org/):

```console
~$ pip install poetry
~$ poetry install
~$ poetry run ipahound -h
```

## Usage

### Command-Line Options

```
 _____ _____ _____ _____               _
|     |  _  |  _  |  |  |___ _ _ ___ _| |
|-   -|   __|     |     | . | | |   | . |
|_____|__|  |__|__|__|__|___|___|_|_|___|
     by Mikhail Sukhov (@Im10n), @ptswarm

usage: ipahound [-h] [-d] [-s SERVER] [-b BASE_DN] [-u USER] [-p PASSWORD] [-k]
                [--save-all-hbac] [-a FILE] [-o FILE] [--output-raw FILE] [--input-raw FILE]

IPA BloodHound Collector

options:
  -h, --help            Show this help message and exit
  -d, --debug           Enable debug output

LDAP connection parameters:
  -s SERVER, --ldap-server SERVER
                        IP address or DNS name of LDAP server
  -b BASE_DN, --ldap-base-dn BASE_DN
                        Base DN for LDAP dump (optional, defaults to auto-detection)

Authentication options:
  -u USER, --ldap-user USER
                        Username for LDAP (can use DN format: uid=admin,cn=users,cn=accounts,dc=ipa,dc=local)
  -p PASSWORD, --ldap-password PASSWORD
                        Password for LDAP authentication
  -k, --kerberos        Use Kerberos authentication instead of username/password

Output format options:
  --save-all-hbac       Draw all HBAC services in the graph (default: only sudo and SSH)
  -a FILE, --apoc-output FILE
                        Output JSON for APOC neo4j plugin (recommended)
  -o FILE, --output FILE
                        Output JSON for BloodHound loader
  -O FILE
                        Output JSON for BloodHound CE OpenGraph ingest

Advanced options (debugging):
  --output-raw FILE     Output RAW JSON before processing (useful for debugging)
  --input-raw FILE      Process existing RAW JSON instead of performing LDAP dump
```

### Examples

Dump domain with password authentication (APOC format):

```console
~$ ipahound -u uid=admin,cn=users,cn=accounts,dc=ipa,dc=local -p P@ssw0rd -s dc01.ipa.local -a out_for_apoc.json
~$ ipahound -u admin -p P@ssw0rd -s dc01.ipa.local -a out_for_apoc.json
```

Dump domain with Kerberos authentication (BloodHound classic format):

```console
~$ ipahound -k -s dc01.ipa.local -o out.json
```

Process an existing raw dump (no LDAP traffic):

```console
~$ ipahound --input-raw raw_dump.json -a processed_output.json
```

## Loading Data into Neo4j

### Prerequisites

1. Install the APOC plugin from the [APOC releases page](https://github.com/neo4j/apoc/releases). The Neo4j version **must** match the version of the APOC plugin.
2. Enable file imports in Neo4j by adding the following to `/etc/neo4j/apoc.conf` (Linux) or `conf/apoc.conf` (Windows):
   ```
   apoc.import.file.enabled=true
   ```
3. Create the necessary constraints in Neo4j (one-time, before the **first** import):
   ```cypher
   CREATE CONSTRAINT FOR (n:IPADomain) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPAUser) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPAGroup) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPAComputer) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPAService) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPAPermission) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPACertificateTemplate) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPACA) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:Base) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPARole) REQUIRE n.neo4jImportId IS UNIQUE;
   CREATE CONSTRAINT FOR (n:IPASELinux) REQUIRE n.neo4jImportId IS UNIQUE;
   ```

### Import Process

Import (or re-import) the collected data:

```cypher
CALL apoc.import.json("/path/to/file.json");
```

To wipe existing data before a fresh import (e.g., between engagements):

```cypher
MATCH (n) DETACH DELETE n;
```

The constraints from step 3 above persist across `DETACH DELETE` and never need to be recreated.

## ToDo

- [ ] Add ACI parser

## Additional Resources

For more detailed information about FreeIPA security analysis and attack techniques, please refer to our blog posts:
1. https://swarm.ptsecurity.com/thinking-in-graphs-with-ipahound/
2. https://habr.com/ru/companies/pt/articles/1028412/

- ...

## Star History

<a href="https://star-history.com/#IPAHound/IPAHound&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=IPAHound/IPAHound&type=Date&theme=dark">
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=IPAHound/IPAHound&type=Date">
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=IPAHound/IPAHound&type=Date">
  </picture>
</a>

## Contributing

We welcome contributions! Please feel free to submit issues, feature requests, and pull requests.

---

<p align="center">
  <em>Happy Hunting! 🎯</em>
</p>
