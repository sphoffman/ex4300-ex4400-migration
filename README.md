# EX4300-to-EX4400 Migration Automation

Evidence-driven automation for staged Juniper EX4300-to-EX4400 migrations.

The project is organized around a small number of **operator-facing workflow commands**. Lower-level phase commands remain available for troubleshooting/resume, but the normal operator should not need to remember them.

## Quick start

From the server/host checkout:

```bash
./migrate site-prep
./migrate discover
./migrate <migration-id>
```

Inside the PyEZ1 container where the repository is mounted as `~/scripts`:

```bash
cd ~/scripts
python migrate.py site-prep
python migrate.py discover
python migrate.py <migration-id>
```

Those are the three primary operator entry points:

1. `site-prep` — initialize the site, discover/approve the QFX pair, and validate/stage the QFX site baseline.
2. `discover` — collect the first EX4300 evidence and derive the migration ID from the switch hostname.
3. `<migration-id>` — resume the guided migration from whatever safe phase is next.

Migration artifacts are immutable and digest-bound under:

```text
snapshots/migrations/<migration-id>/
```

Site-level QFX discovery/inventory artifacts are stored under:

```text
snapshots/site/<site-id>/
```

## Testing

For the repeatable vJunos/post-cutover simulation rehearsal, including reset steps, expected checkpoints, and the remaining simulator workflow work, see:

[`docs/simulated-migration-testing.md`](docs/simulated-migration-testing.md)

## VLAN and management model

The migration workflow manages two VLAN roles directly:

```text
3998  TEMP-ACCESS   replacement EX4400 holding/default access VLAN
163   v163/MGMT     permanent replacement EX4400 in-band management
```

A separate temporary-management network may be used to reach the replacement EX4400 `fxp0` before cutover, but that path is an **external prerequisite** and is outside this project's configuration scope.

### VLAN 3998 — `TEMP-ACCESS`

`TEMP-ACCESS` is local to the replacement EX4400 prestage design. The Junos `default` VLAN is renumbered to 3998 so edge ports remain in a non-production holding VLAN until endpoint activation.

It is **not** used for switch management and is not part of the QFX pre-cutover baseline.

### Temporary `fxp0` management — external prerequisite

In production, temporary pre-cutover reachability may be provided through the legacy network, for example:

```text
replacement EX4400 fxp0
        |
legacy EX4300 access port
        |
legacy EX4300 uplink
        |
EX9200 legacy network
```

The temporary network may use VLAN 3999 / `Temp-Management`, but **this project does not create, stage, validate, modify, or remove that VLAN on any device**. In particular, it does not manage VLAN 3999 on:

```text
EX4300
EX9200
EX4400
QFX5700
```

Before `prestage`, the operator is responsible for ensuring that the replacement EX4400 `fxp0` address is reachable. The migration workflow validates and binds the supplied replacement identity/address; it does not build the legacy transit path that provides that reachability.

The QFX5700s are not part of the temporary `fxp0` path. A migration-facing QFX AE must therefore contain no temporary-management VLAN membership.

### VLAN 163 — permanent in-band management

The QFX pre-cutover baseline contains only the permanent management VLAN. Before site staging, a preprovisioned migration AE may be empty or already contain the management VLAN. After site staging, the baseline must be management-only.

After physical cutover, the replacement EX4400 uses its normal in-band management interface/VLAN (for example `irb.163` / `v163`) through its new uplinks to the QFX pair.

## Site preparation

Normal site preparation:

```bash
./migrate site-prep
```

or inside PyEZ1:

```bash
python migrate.py site-prep
```

`site-prep` runs:

```text
site-init
  -> site-discover
  -> site-stage
```

in one process and prompts for QFX credentials once. Approval boundaries remain intact.

Site initialization asks for the site/environment, QFX management addresses, permanent management VLAN, EX-only TEMP-ACCESS VLAN, and any reserved QFX ET interfaces. It does **not** ask for a temporary-management VLAN.

The QFX migration-facing ET interfaces and AEs must already be preprovisioned by the external QFX provisioning process. This migration project does **not** create or repair:

```text
ET -> AE mapping
LACP active/system-id
ESI auto-derive type-1-lacp
ESI all-active
ethernet-switching trunk structure
```

`site-stage` may add only missing permanent management-VLAN membership to the approved migration AEs. It does not stage temporary management, data VLANs, or voice VLANs.

The lower-level site commands remain available for troubleshooting/resume:

```bash
./migrate site-init
./migrate site-discover
./migrate site-stage
./migrate site-status
```

Inside PyEZ1 use `python migrate.py ...` instead.

## Old-switch discovery

Initial discovery does not require a migration ID:

```bash
./migrate discover
```

or:

```bash
python migrate.py discover
```

The switch hostname is observed and becomes the migration ID.

A short lab collection can be requested explicitly:

```bash
./migrate discover --count 1 --duration 60 --interval 60
```

For production, normally omit `--duration` and `--interval`. Current production defaults are:

```text
observation window: 1800 seconds (30 minutes)
sample interval:    180 seconds (3 minutes)
minimum samples:    10
```

Repeat collections after the migration ID exists with:

```bash
./migrate <migration-id> discover
```

## Guided migration

Once discovery exists, the normal command is simply:

```bash
./migrate <migration-id>
```

or inside PyEZ1:

```bash
python migrate.py <migration-id>
```

Typical progression:

```text
discover
  -> analyze
  -> build + prestage
  -> cutover-ready (only when silent-port probing is required)
  -> cutover
  -> activate
  -> validate
  -> finalize
  -> complete
```

The guided workflow groups related internal phases but retains meaningful approval boundaries. During `build + prestage`:

```text
approve exact migration intent
  -> create package/render
  -> bind replacement EX4400 identity/OOB fxp0 address
  -> approve exact EX4400 candidate diff
  -> commit-confirm + validate replacement EX4400
```

The replacement OOB address **must include an explicit CIDR prefix**. A bare address such as `10.255.3.16` is rejected rather than silently becoming `/32`.

Temporary `fxp0` reachability must already exist before prestage; no EX4300/EX9200 temporary-management provisioning is performed by this workflow.

## Physical cutover

The `cutover` checkpoint is an operator acknowledgement only; it performs no device writes.

In production, the legacy EX4300 uplinks terminate on EX9200s before cutover. During cutover those uplink fibers are moved to the replacement EX4400/QFX5700 topology. Once the replacement uplinks are active, permanent in-band management is used and the external temporary `fxp0` path is no longer required.

After cutover, `activate` discovers the live QFX attachment, stages only the required per-migration QFX data/voice VLANs, and activates endpoints using approved historical MAC evidence.

## Endpoint activation and exceptions

Endpoint activation is evidence-driven. An endpoint receives a data VLAN only when approved historical MAC evidence maps unambiguously to a current EX4400 edge port.

### Preview and correct client placement before endpoint activation

After the physical cable move and after the migration-specific QFX VLAN transaction has completed, an operator may preview the current EX4400 client mapping without writing endpoint configuration.

From the server/host checkout:

```bash
PYTHONPATH=src python -m ex_migration_provisioner.endpoint_stage_cli \
    <migration-id> \
    --plan-only
```

Inside PyEZ1, the same command can be run from the repository root:

```bash
PYTHONPATH=src python -m ex_migration_provisioner.endpoint_stage_cli \
    <migration-id> \
    --plan-only
```

With no `--observation-id`, every `--plan-only` invocation collects a **fresh live post-cutover EX4400 observation** and recomputes endpoint correlation from the currently learned MAC table. The observation and correlation are retained as immutable audit evidence, but no endpoint candidate is loaded, no endpoint transaction is committed, and no endpoint is marked migrated.

This supports a migration-night inspect/correct/recheck loop:

```text
move endpoint cables
  -> run endpoint_stage_cli --plan-only
  -> inspect old-interface -> new-interface MAC correlation
  -> physically correct any misplaced cables
  -> generate traffic from moved/quiet endpoints so the EX4400 relearns them
  -> rerun endpoint_stage_cli --plan-only
  -> repeat until mappings are acceptable
  -> run normal endpoint activation
```

For example, if a preview reports:

```text
ge-0/0/2 -> ge-0/0/3
ge-0/0/3 -> ge-0/0/2
```

those cables can be corrected and `--plan-only` run again. The second run uses newly collected live MAC/interface evidence; it does not overwrite or silently reuse the first observation.

Do **not** pass an older `--observation-id` when the goal is to verify a physical cable correction. Supplying an observation ID intentionally reuses that immutable observation and therefore will not discover the new live mapping.

After the live mapping is satisfactory, proceed with normal activation so the endpoint-specific VLAN/description configuration is generated from the current correlation and committed through the normal approval and commit-confirmed safety path.

If unresolved endpoints remain, the operator may accept them as migration exceptions. An accepted exception:

- does not mark the endpoint migrated;
- does not authorize a VLAN assignment;
- requires an operator reason;
- is stored as immutable, digest-bound evidence;
- can be reconciled later by rerunning `activate`.

Example status:

```text
Endpoint activation: 7/8 + 1 ACCEPTED_EXCEPTION
```

## Lower-level per-migration commands

These remain available for explicit resume/troubleshooting:

```bash
./migrate <migration-id> status
./migrate <migration-id> discover
./migrate <migration-id> analyze
./migrate <migration-id> build
./migrate <migration-id> prestage
./migrate <migration-id> cutover-ready
./migrate <migration-id> cutover
./migrate <migration-id> activate
./migrate <migration-id> validate
./migrate <migration-id> finalize
./migrate <migration-id> mac <mac-address>
```

The normal guided path remains `./migrate <migration-id>`.

## Useful options

### `prestage`

```text
--settings PATH
--oob-address ADDRESS/PREFIX
--username USER
--password-env ENV_VAR
--no-host-key-check
```

### `cutover-ready`

```text
--settings PATH
--username USER
--password-env ENV_VAR
--port PORT
--down-seconds SECONDS
--relearn-seconds SECONDS
--observation-seconds SECONDS
--interval-seconds SECONDS
--plan-only
--no-host-key-check
```

Used only when approved analysis contains eligible silent-port candidates.

### `activate`

```text
--settings PATH
--environment PATH
--username USER
--password-env ENV_VAR
--no-host-key-check
```

Grouped post-cutover phase:

```text
QFX attachment discovery
QFX per-migration VLAN staging
EX4400 endpoint correlation/activation
```

For a no-write preview of endpoint placement after QFX staging, use the documented `endpoint_stage_cli --plan-only` workflow above. The grouped `activate` wrapper does not currently expose that lower-level flag.

### `mac`

```bash
./migrate <migration-id> mac <mac-address>
```

Reports the old interface, description, configured data VLAN, observed VLAN evidence, and supporting discovery snapshots for a MAC in approved historical evidence.

## Safety model

The project intentionally fails closed around device identity, immutable artifact integrity, QFX symmetry, candidate state, and ambiguous endpoint evidence.

Important rules include:

- first discovery derives the migration ID from the old-switch hostname;
- later discovery asserts that migration ID;
- QFX ET/AE/LACP/ESI infrastructure is externally preprovisioned;
- QFX site baseline is permanent management only;
- TEMP-ACCESS/3998 remains EX4400-only;
- temporary `fxp0` management is an external prerequisite and has no project-managed device writes;
- QFX migration AEs must not contain a temporary-management VLAN;
- replacement EX `fxp0` is the pre-cutover management endpoint;
- replacement in-band management is used after cutover;
- endpoint VLAN assignment requires unambiguous approved MAC evidence;
- write-capable phases show the exact candidate diff and require approval;
- device writes use commit-confirmed and post-change validation before final confirmation;
- historical artifacts are retained rather than edited in place.

## Development

The project supports Python 3.8 and 3.12 in CI.

Run tests with:

```bash
pytest -q
```

In the Juniper PyEZ container environment:

```bash
pyez -c '
import sys
sys.path.insert(0, "/scripts/.test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
```
