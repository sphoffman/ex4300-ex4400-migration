# QFX5700 ESI-LAG Bootstrap

This utility preprovisions a pair of QFX5700s with deterministic all-active ESI-LAGs for the EX4300-to-EX4400 migration environment.

It is a **site bootstrap utility**, separate from the normal guided `./migrate` workflow. Run it before `./migrate site-prep` when the QFX migration-facing ET -> AE/LACP/ESI infrastructure has not already been provisioned.

The intended sequence is:

```text
QFX5700 ESI bootstrap
        |
        v
ET -> AE / LACP / ESI infrastructure exists
        |
        v
./migrate site-prep
        |
        v
migration workflow discovers/approves the existing QFX pair
and manages migration VLAN membership as required
```

## What the bootstrap creates

For each eligible physical `et-*` interface on each online FPC, the utility deterministically maps the physical port to an AE. With the default 16 ports per FPC:

```text
et-0/0/0  -> ae0
et-0/0/1  -> ae1
...
et-0/0/15 -> ae15
et-1/0/0  -> ae16
...
```

For each new pair it renders equivalent configuration on both QFXs:

```text
set interfaces ae<N> esi auto-derive type-1-lacp
set interfaces ae<N> esi all-active
set interfaces ae<N> aggregated-ether-options lacp active
set interfaces ae<N> aggregated-ether-options lacp system-id <deterministic-system-id>
set interfaces ae<N> unit 0 family ethernet-switching interface-mode trunk
set interfaces ae<N> unit 0 family ethernet-switching vlan members <management-vlan>
set interfaces et-<fpc>/<pic>/<port> ether-options 802.3ad ae<N>
```

The deterministic LACP system ID is derived from the configured four-octet prefix plus the AE number.

## Configuration file

The default configuration path is:

```text
config/qfx5700-esi-bootstrap.json
```

Start with the repository example:

```bash
cp config/qfx5700-esi-bootstrap.example.json \
   config/qfx5700-esi-bootstrap.json
```

Example:

```json
{
  "qfx_pair": [
    {
      "role": "qfx-a",
      "management_address": "10.255.3.14"
    },
    {
      "role": "qfx-b",
      "management_address": "10.255.3.15"
    }
  ],
  "management_vlan": {
    "name": "v163",
    "vlan_id": 163
  },
  "interfaces": {
    "type": "et",
    "pic": 0,
    "first_port": 0,
    "last_port": 15,
    "ports_per_fpc": 16
  },
  "lacp_system_id": {
    "prefix": "02:00:00:00"
  }
}
```

Adjust the QFX management addresses, management VLAN, and port range for the site before running the utility.

`interfaces.type` must currently be `et`. `first_port` through `last_port` define the candidate port range on every online FPC. Optic presence is not required; online FPC inventory is used instead.

## Prerequisites

Before running the bootstrap:

- Both QFX5700s must be reachable over NETCONF/SSH.
- The configured management VLAN must already exist on **both** QFXs with the exact configured name and VLAN ID.
- The two QFXs must report matching online FPCs.
- Any physical ET or AE interface already containing configuration is treated as already owned/configured rather than overwritten.
- Port ownership must be symmetric across the pair. A port available on one QFX but already configured on the other causes preflight to fail.

The bootstrap is deliberately conservative: it does not repair or overwrite existing interface configuration.

## Always run a dry run first

From the Linux host checkout, use the repository's portable PyEZ launcher:

```bash
./py -m ex_migration_qfx_bootstrap.cli --dry-run
```

The utility prompts for the QFX username and password.

To use a different configuration file:

```bash
./py -m ex_migration_qfx_bootstrap.cli \
  --config config/qfx5700-esi-bootstrap.json \
  --dry-run
```

The dry run connects to both QFXs and performs the full read-only preflight. It displays:

```text
online FPCs on each QFX
management-VLAN validation
CREATE count
SKIP_CONFIGURED count
WARN_ASYMMETRIC count
preflight PASS/FAIL
candidate configuration
```

No configuration is changed during `--dry-run`.

A successful preflight should end with `Result: PASS`. Review the candidate configuration before proceeding.

## Run the bootstrap

After reviewing a successful dry run:

```bash
./py -m ex_migration_qfx_bootstrap.cli
```

The utility reconnects and repeats preflight before making changes. It then:

1. Locks the configuration database on both QFXs.
2. Re-runs observations after both locks are acquired.
3. Refuses to continue if QFX state changed between preflight and lock acquisition.
4. Loads the candidate on both QFXs.
5. Runs commit-check on both devices.
6. Requires the candidate diffs to be identical.
7. Displays the exact diff.
8. Prompts:

```text
Commit exactly this configuration to BOTH QFXs? [y/N]:
```

Only `y` or `yes` authorizes the coordinated commit.

## Commit protection and validation

Writes use commit-confirmed protection on both QFXs. The default confirmation interval is 10 minutes.

After the commit-confirmed operation, the utility re-runs pair preflight and verifies that the newly created physical-interface configuration exists on both devices. Only after successful validation does it issue the final confirming commits.

If an exception occurs after configuration handling begins, the utility attempts to roll back both QFXs. This does not replace normal operator review of the candidate diff and post-run device state.

A successful run ends with output similar to:

```text
SUCCESS: configured and validated <N> ESI-LAG pairs on both QFX5700s.
```

## Existing and partially configured ports

For each candidate ET/AE mapping:

- If both sides are unused, the pair is `CREATE`.
- If both sides already have physical or AE configuration, the pair is `SKIP_CONFIGURED`.
- If one QFX is available while the corresponding port on the other QFX is already configured, the pair is `WARN_ASYMMETRIC` and the overall preflight fails.

This behavior lets the bootstrap coexist with intentionally reserved or previously configured ports without modifying them, while preventing accidental asymmetric ESI-LAG creation.

## Command options

```text
--config PATH
    Bootstrap JSON file.
    Default: config/qfx5700-esi-bootstrap.json

--username USER
    QFX login username. If omitted, the utility prompts.

--password-env ENV_VAR
    Read the QFX password from the named environment variable instead of prompting.

--port PORT
    NETCONF SSH port. Default: 830.

--dry-run
    Run preflight and display candidate configuration without changing either QFX.

--confirm-minutes MINUTES
    Commit-confirmed interval. Default: 10; minimum: 1.

--no-host-key-check
    Disable NETCONF SSH host-key verification.
```

For example, using an environment variable for the password:

```bash
export QFX_PASSWORD='...'

./py -m ex_migration_qfx_bootstrap.cli \
  --username <username> \
  --password-env QFX_PASSWORD \
  --dry-run
```

Avoid placing passwords directly in repository files or command-line arguments.

## Relationship to `site-prep`

The bootstrap and migration workflow intentionally have different responsibilities.

The bootstrap creates the underlying QFX migration-facing infrastructure:

```text
ET -> AE mapping
LACP active/system-id
ESI auto-derive type-1-lacp
ESI all-active
ethernet-switching trunk structure
initial permanent management-VLAN membership
```

The normal migration workflow assumes that infrastructure already exists. After bootstrap, proceed with:

```bash
./migrate site-prep
```

`site-prep` discovers and approves the QFX pair and validates/stages the migration site's QFX baseline. Later migration phases may add the required migration-specific data/voice VLAN membership, but they do not create or repair the underlying ET/AE/LACP/ESI structure.

## Recommended site bring-up sequence

For a new QFX5700 migration pair:

```bash
# 1. Create the local bootstrap config from the example.
cp config/qfx5700-esi-bootstrap.example.json \
   config/qfx5700-esi-bootstrap.json

# 2. Edit it for the site.
vi config/qfx5700-esi-bootstrap.json

# 3. Preflight only.
./py -m ex_migration_qfx_bootstrap.cli --dry-run

# 4. Review CREATE/SKIP/WARN counts and every candidate statement.

# 5. Bootstrap both QFXs.
./py -m ex_migration_qfx_bootstrap.cli

# 6. Verify SUCCESS and, if desired, verify the resulting Junos config directly.

# 7. Enter the normal migration workflow.
./migrate site-prep
```

Do not proceed past a failed preflight by manually forcing the bootstrap. Resolve the FPC, VLAN, or asymmetric ownership condition first and re-run `--dry-run`.
