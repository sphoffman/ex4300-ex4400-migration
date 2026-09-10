# EX4300-to-EX4400 Migration Automation

Evidence-driven automation for staged Juniper EX4300-to-EX4400 migrations.

The normal operator entry point is the root `./migrate` launcher. It manages site
readiness, old-switch discovery, analysis, migration planning, replacement pre-stage,
QFX attachment discovery and VLAN staging, endpoint correlation/activation,
post-cutover validation, facilities reporting, and final cleanup.

The design deliberately separates observation, approval, planning, and device writes.
Migration evidence and approvals are retained as immutable, digest-bound artifacts
under:

```text
snapshots/migrations/<migration-id>/
```

Site-level QFX discovery and inventory artifacts are stored under:

```text
snapshots/site/<site-id>/
```

## Operator workflow

### 1. Prepare the site

The QFX migration-facing physical interfaces and AEs are expected to be
**preprovisioned by a separate site tool** before this migration project uses them.
This migration project does not create ET-to-AE mappings, LACP system IDs, ESI, or
trunk structure.

Initialize the site:

```bash
./migrate site-init
```

Discover and approve the existing QFX pair and preprovisioned migration AEs:

```bash
./migrate site-discover
```

Validate the pre-cutover QFX baseline and add only missing management and
`TEMP-RECOVERY` VLAN membership when required:

```bash
./migrate site-stage
```

Check readiness at any time:

```bash
./migrate site-status
```

Before an EX4300 migration begins, every approved migration AE must already have:

```text
ET -> AE mapping
LACP active
matching LACP system ID on both QFXs
ESI auto-derive type-1-lacp
ESI all-active
ethernet-switching trunk
management VLAN membership
TEMP-RECOVERY VLAN membership
```

`site-stage` may repair only the final two VLAN memberships. If the AE/LACP/ESI/trunk
structure itself is missing or inconsistent, the migration tool fails closed and the
external QFX preprovisioning process must correct it.

Data and voice VLANs are intentionally **not** part of the site baseline. They are
added only to the actual QFX AE discovered for each migration.

### 2. Start a migration with initial discovery

The first discovery does **not** require a migration ID. The switch hostname is
observed and the migration ID is derived automatically:

```bash
./migrate discover
```

Example with a short lab collection:

```bash
./migrate discover --count 1 --duration 60 --interval 30
```

The command prompts for the old EX4300 reachable address and credentials when they
are not supplied. On success it prints the derived ID, for example:

```text
Discovered migration ID: sw1203
Continue with: ./migrate sw1203
```

For several independent collections:

```bash
./migrate discover --count 3 --duration 60 --interval 30 --pause-minutes 5
```

The first collection derives the migration ID. Every later collection in that same
invocation asserts the derived ID so evidence cannot silently move to another switch.

### 3. Resume the guided migration

Once the ID exists, the normal command is simply:

```bash
./migrate sw1203
```

The launcher prints current state, determines the next safe phase, and asks whether
to run it. One logical phase is run per invocation.

Typical progression:

```text
discover
  -> analyze
  -> build
  -> prestage
  -> cutover-ready (only when silent-port probing is required)
  -> cutover
  -> activate
  -> validate
  -> finalize
  -> complete
```

A bare migration resume also checks site readiness first. If the generated QFX site
policy does not exist, the migration is redirected to the required site action rather
than failing later in `prestage`.

### 4. Repeat discovery after the migration ID exists

Additional old-switch collections use the migration ID first:

```bash
./migrate sw1203 discover
```

Example:

```bash
./migrate sw1203 discover --count 3 --duration 60 --interval 30
```

The previously observed source connection address is reused unless `--address` is
supplied, and every collection verifies that the hostname still derives to `sw1203`.

### 5. Endpoint activation and accepted exceptions

Endpoint activation is evidence-driven and resumable. An endpoint is configured only
when approved historical MAC evidence maps unambiguously to a current EX4400 edge
port.

If some endpoints are still unresolved, activation may be rerun later:

```bash
./migrate sw1203 activate
```

When unresolved endpoints remain, the operator may explicitly accept them as
migration exceptions so the overall migration can continue. An accepted exception:

- does **not** mark the endpoint migrated;
- does **not** authorize a VLAN assignment;
- requires an operator reason;
- is stored as an immutable artifact bound to the current approved plan and
  correlation evidence;
- remains eligible for later reconciliation.

Status may therefore show:

```text
Endpoint activation: 7/8 + 1 ACCEPTED_EXCEPTION
```

Even after validation/finalization, the operator may run:

```bash
./migrate sw1203 activate
```

again. If the missing MAC later appears and can be correlated safely, the endpoint is
configured through a normal committed endpoint transaction and the active exception
is automatically retired. The original exception remains immutable history.

## `./migrate` CLI reference

### Top-level forms

```bash
./migrate site-init [options]
./migrate site-discover [options]
./migrate site-stage [options]
./migrate site-status [options]

./migrate discover [address] [options]

./migrate <migration-id>
./migrate <migration-id> status [options]
./migrate <migration-id> discover [options]
./migrate <migration-id> analyze [options]
./migrate <migration-id> build [options]
./migrate <migration-id> prestage [options]
./migrate <migration-id> cutover-ready [options]
./migrate <migration-id> cutover [options]
./migrate <migration-id> activate [options]
./migrate <migration-id> validate [options]
./migrate <migration-id> finalize [options]
./migrate <migration-id> mac <mac-address> [options]
```

A migration command cannot be used as the first positional token. For example,
`./migrate status` is rejected; use `./migrate sw1203 status`.

### `site-init`

```text
--settings PATH
--site-id ID
--environment {lab,production}
--qfx-a ADDRESS
--qfx-b ADDRESS
--management-vlan-id VLAN_ID
--management-vlan-name NAME
--recovery-vlan-id VLAN_ID
--recovery-vlan-name NAME
--prestage-vlan-id VLAN_ID
--prestage-vlan-name NAME
--exclude INTERFACE              repeatable
```

Interactive defaults currently include site ID `campus`, management VLAN 163,
`TEMP-RECOVERY` 3999, and `TEMP-ACCESS` 3998.

### `site-discover`

```text
--settings PATH
--username USER
--password-env ENV_VAR
--port PORT                     default 830
--no-host-key-check             lab only
```

Read-only discovery of the QFX identities and already-preprovisioned symmetric
ET-to-AE migration attachments.

### `site-stage`

```text
--settings PATH
--username USER
--password-env ENV_VAR
--port PORT                     default 830
--confirm-minutes MINUTES       default 10; valid 1-60
--no-host-key-check             lab only
```

May add only missing management and `TEMP-RECOVERY` VLAN memberships to the approved
preprovisioned migration AEs. It does not create or repair the AE structure.

### `site-status`

```text
--settings PATH
```

### Initial `discover`

```text
[address]                       optional; otherwise prompted
--settings PATH
--username USER
--password-env ENV_VAR
--duration SECONDS
--interval SECONDS
--port PORT                     default 830
--count COUNT                   default 1
--pause-minutes MINUTES         default 0
--no-host-key-check
```

The root launcher prompts once for discovery credentials when they are not supplied
and exposes the password to child collections only through an ephemeral environment
variable for that launcher invocation.

### `<migration-id>`

No extra arguments. Prints current status, chooses the next action, and asks whether
to run it.

```bash
./migrate sw1203
```

### `status`

```text
--settings PATH
```

### Repeat `discover`

```text
--settings PATH
--address ADDRESS
--duration SECONDS
--interval SECONDS
--username USER
--password-env ENV_VAR
--port PORT                     default 830
--count COUNT                   default 1
--pause-minutes MINUTES         default 0
--no-host-key-check
```

### `analyze`

```text
--settings PATH
--policy PATH
--non-interactive
```

Runs the offline composite analyzer over all eligible discovery collections for the
migration. Interactive mode handles evidence approval and finding disposition.

### `build`

```text
--settings PATH
--non-interactive
```

Builds and approves immutable migration intent from the accepted analysis.

### `prestage`

```text
--settings PATH
--oob-address ADDRESS/PREFIX
--old-transport-address ADDRESS    lab only
--username USER
--password-env ENV_VAR
--no-host-key-check
```

This grouped phase resumes only the incomplete pre-cutover steps: package creation,
render, replacement identity, EX4400 pre-stage, and old-EX recovery staging.
Credentials are reused for the grouped device operations.

In a lab where one virtual switch is reused for both replacement and old-switch roles,
the old-recovery step pauses before connecting so the operator can swap the lab device
back to the approved EX4300 role. Production does not use this role-swap checkpoint.

### `cutover-ready`

```text
--settings PATH
--username USER
--password-env ENV_VAR
--port PORT                     default 830
--down-seconds SECONDS          default 5
--relearn-seconds SECONDS       default 30
--observation-seconds SECONDS   default 120
--interval-seconds SECONDS      default 30
--plan-only
--no-host-key-check             lab only
```

Used only when approved analysis contains eligible silent-port candidates. State-only
evidence never authorizes a VLAN assignment.

### `cutover`

```text
--settings PATH
```

Records the operator's immutable physical-cutover acknowledgement. It performs no
device writes.

### `activate`

```text
--settings PATH
--environment PATH              default config/environment.lab.json
--username USER
--password-env ENV_VAR
--no-host-key-check
```

Grouped post-cutover phase. As needed it performs:

```text
QFX attachment discovery (read-only)
QFX per-migration VLAN staging
EX4400 endpoint correlation/activation
```

One shared credential prompt is reused across QFX and EX4400 operations for the phase.
The password is retained only in an ephemeral environment variable for the invocation.

The command remains valid after accepted endpoint exceptions and after the main
workflow reaches completion, allowing late endpoint migrations to be reconciled.

### `validate`

```text
--settings PATH
--environment PATH              default config/environment.lab.json
```

Runs the post-cutover port-state comparison and facilities/cabling report.

### `finalize`

Arguments are passed through to the final cleanup command:

```text
--settings PATH
--environment PATH              default config/environment.lab.json
--site-policy PATH
--identity-id ID
--package-id ID
--qfx-transaction-id ID
--username USER                 shared EX/QFX username
--password-env ENV_VAR          shared EX/QFX password variable
--ex-username USER
--ex-password-env ENV_VAR
--qfx-username USER
--qfx-password-env ENV_VAR
--port PORT                     default 830
--confirm-minutes MINUTES       default 10
--plan-only
--no-host-key-check             lab only
```

Finalization removes the active `TEMP-RECOVERY` transit membership while preserving
the disabled local recovery attachment, hardens proven-unused edge ports, and removes
only proven-unused legacy VLANs. Historical migration evidence and accepted endpoint
exceptions remain available so late `activate` reconciliation can still occur.

### `mac`

```text
<mac-address>
--settings PATH
```

Looks up a MAC in the approved historical EX4300 evidence and reports the old
interface, description, configured data VLAN, observed VLAN evidence, and supporting
discovery snapshots.

Example:

```bash
./migrate sw1203 mac 02:54:af:72:dc:1c
```

## Useful help commands

Every routed CLI is backed by `argparse`, so command-specific help can be requested
with `-h`/`--help`, for example:

```bash
./migrate site-init --help
./migrate discover --help
./migrate sw1203 discover --help
./migrate sw1203 activate --help
./migrate sw1203 finalize --help
```

## Safety model

The project intentionally fails closed around device identity, immutable artifact
integrity, candidate state, QFX symmetry, and ambiguous endpoint evidence.

Important rules include:

- first discovery derives the migration ID from the old-switch hostname;
- later discovery asserts the known migration ID;
- QFX ET-to-AE/LACP/ESI/trunk infrastructure is preprovisioned externally;
- site-stage may repair only management and `TEMP-RECOVERY` membership;
- QFX attachment is discovered after physical cutover through live LLDP/LACP evidence;
- per-migration data and voice VLANs are added only to the discovered AE;
- endpoint VLAN assignment requires unambiguous approved historical MAC evidence;
- state-only/same-position evidence is advisory and never authorizes VLAN assignment;
- accepted endpoint exceptions allow workflow continuation but never mark an endpoint
  migrated;
- write-capable phases show the exact candidate diff and require approval;
- device writes use commit-confirmed plus post-change validation before final
  confirmation;
- immutable history is retained rather than edited in place.

## Development

The project supports Python 3.8 and 3.12 in CI.

Tests:

```bash
pytest -q
```

In the Juniper PyEZ container environment used by the lab:

```bash
pyez -c '
import sys
sys.path.insert(0, "/scripts/.test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
```
