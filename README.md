# EX4300-to-EX4400 Migration Automation

Evidence-driven automation for staged Juniper EX4300-to-EX4400 migrations.

The project is organized around a small number of **operator-facing workflow commands**. Internal phase commands remain available for troubleshooting/resume, but the normal operator should not need to remember them.

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

## Management and temporary VLAN model

Three VLAN roles are intentionally separate:

```text
3998  TEMP-ACCESS      replacement EX4400 holding/default access VLAN
3999  Temp-Management  pre-cutover old-EX transit for replacement fxp0
163   v163             permanent replacement EX4400 in-band management
```

### VLAN 3998 — `TEMP-ACCESS`

`TEMP-ACCESS` is local to the replacement EX4400 prestage design. The Junos `default` VLAN is renumbered to 3998 so edge ports remain in a non-production holding VLAN until endpoint activation.

It is **not** used for switch management and is not part of the QFX pre-cutover baseline.

### VLAN 3999 — `Temp-Management`

`Temp-Management` provides temporary management of the replacement EX4400 **before physical cutover**.

The intended path is:

```text
replacement EX4400 fxp0
        |
        | Ethernet cable
        |
proven-unused old EX4300 access port
        |
        | VLAN 3999 Temp-Management
        |
old EX4300 ae0/uplink
        |
QFX migration AE carrying VLAN 3999
        |
management network
```

The automation selects a proven-unused old EX4300 access port from the approved migration plan, preferring the highest-numbered eligible port. It fails closed if no safe unused port is available.

The old EX temporary-management prestage may add:

```text
set vlans Temp-Management vlan-id 3999
set interfaces <unused-old-port> unit 0 family ethernet-switching interface-mode access
set interfaces <unused-old-port> unit 0 family ethernet-switching vlan members Temp-Management
```

If the old EX `ae0` trunk uses explicit VLAN members, the automation also adds `Temp-Management` to `ae0`. If `ae0` already uses `vlan members all`, no redundant member statement is needed.

The temporary-management step **does not rewrite old-switch `vme.0`**, does not move the replacement OOB address onto the old EX, and does not change the old EX management identity.

VLAN 3999 remains part of the QFX pre-cutover site baseline because the still-running old EX must carry it upstream while the new EX is being managed through `fxp0`.

The replacement EX4400 switching configuration itself does **not** contain VLAN 3999 and does not reserve one of its edge ports for Temp-Management. `fxp0` is physically connected to the old EX access port instead.

### VLAN 163 — permanent in-band management

After physical cutover, the replacement EX4400 uses its normal in-band management interface/VLAN (for example `irb.163` / `v163`) through `ae0` to the QFX pair.

The temporary `fxp0 -> old EX -> VLAN 3999` path is then no longer required, and the retired EX4300 can be removed/powered down when the site policy says post-cutover old-switch recovery is not required.

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

The QFX migration-facing ET interfaces and AEs must already be preprovisioned by the external QFX provisioning process. This migration project does **not** create or repair:

```text
ET -> AE mapping
LACP active/system-id
ESI auto-derive type-1-lacp
ESI all-active
ethernet-switching trunk structure
```

The QFX pre-cutover baseline requires the site management VLAN and `Temp-Management`/3999 on approved migration AEs. Data and voice VLANs are added later only to the actual AE discovered for a migration.

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

The 30-minute window gives intermittent endpoints time to transmit while the 3-minute cadence avoids redundant polling relative to normal MAC aging behavior.

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

The guided workflow groups related internal phases but retains meaningful approval boundaries. During `build + prestage`, for example:

```text
approve exact migration intent
  -> create package/render
  -> bind replacement EX4400 identity/OOB fxp0 address
  -> approve exact EX4400 candidate diff
  -> commit-confirm + validate replacement EX4400
  -> stage/approve old EX Temp-Management access-port candidate
```

The replacement OOB address **must include an explicit CIDR prefix**. A bare address such as `10.255.3.16` is rejected rather than silently becoming `/32`.

Status now reports the pre-cutover old-switch step as:

```text
Old-EX temp mgmt:       PENDING|COMPLETE
```

rather than describing it as old-switch recovery.

## Physical cutover

The `cutover` checkpoint is an operator acknowledgement only; it performs no device writes.

By that point the replacement EX4400 has been managed pre-cutover through `fxp0` and the old EX temporary-management port. The cutover acknowledgement confirms that endpoint/uplink cabling has moved and that the temporary `fxp0` management path is no longer required.

After cutover, the `activate` phase discovers the live QFX attachment, stages only the required per-migration QFX VLANs, and activates endpoints using approved historical MAC evidence.

## Endpoint activation and exceptions

Endpoint activation is evidence-driven. An endpoint receives a data VLAN only when approved historical MAC evidence maps unambiguously to a current EX4400 edge port.

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
--old-transport-address ADDRESS    lab only
--username USER
--password-env ENV_VAR
--no-host-key-check
```

`--old-transport-address` is a lab-only override for reaching the original EX4300 while staging its Temp-Management access port.

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
- QFX site baseline includes management + Temp-Management, but not endpoint data/voice VLANs;
- Temp-Management is staged on a proven-unused **old EX** access port, never on a replacement EX switching port;
- old EX `vme.0` is not rewritten for temporary management;
- replacement EX `fxp0` is its pre-cutover management path;
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
