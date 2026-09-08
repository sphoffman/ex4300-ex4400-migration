# EX4300-to-EX4400 Migration Automation

Evidence-driven automation for staged Juniper EX4300-to-EX4400 migrations. The
workflow discovers the existing switch, builds immutable migration intent,
pre-stages the replacement EX4400, validates the physical QFX attachment after
cutover, coordinates production VLAN changes across the QFX pair, correlates moved
endpoints from MAC evidence, and activates only unambiguous endpoint intent.

The design deliberately separates observation, approval, planning, rendering, and
live writes. Evidence and approvals are retained as immutable digest-bound artifacts
under `snapshots/migrations/<migration-id>/`.

## Normal operator workflow

The normal sequence is:

```text
DISCOVER OLD EX4300
        ->
ANALYZE + APPROVE EVIDENCE
        ->
BUILD + APPROVE MIGRATION INTENT
        ->
PREPARE EX4400 PACKAGE
        ->
RENDER EX4400 PRE-STAGE CONFIG
        ->
IDENTIFY REPLACEMENT EX4400
        ->
PRE-STAGE EX4400
        ->
---------------- PHYSICAL CUTOVER ----------------
        ->
DISCOVER + APPROVE QFX ATTACHMENT
        ->
COORDINATED QFX VLAN STAGING
        ->
CORRELATE + ACTIVATE ENDPOINTS
        ->
VALIDATED MIGRATION
        ->
RECOVERY WINDOW
        ->
TEMP-RECOVERY CLEANUP
```

The final recovery cleanup phase is intentionally still pending implementation.
The old-switch temporary recovery-management workflow and facilities cable-relabel
report are also planned follow-on phases; see **Planned post-migration operational
work** below.

### 1. Discover the existing EX4300

Single-switch lab example:

```bash
py -m ex_migration_discovery.cli collect 10.255.3.18 \
  --duration 120 \
  --interval 60 \
  --no-host-key-check
```

Production uses the normal reachable management address and host-key validation.
The migration ID is derived from the validated source-switch hostname.

Discovery is read-only. It records normalized state plus raw evidence, including:

- VLAN definitions and configured-but-unobserved VLANs;
- access-port configuration and descriptions;
- reconciled MAC-table observations;
- voice policy;
- management VLAN/IRB/address/default route;
- SNMP identity and required migration metadata;
- LLDP and relevant operational evidence.

### 2. Analyze and approve the evidence

```bash
py -m ex_migration_analyzer.cli run <migration-id>
```

Example:

```bash
py -m ex_migration_analyzer.cli run sw1203
```

The analyzer validates the selected immutable collection, builds historical endpoint
evidence from eligible snapshots, classifies silent/unused ports, shows findings,
and records any required operator dispositions. It does not connect to or configure
a device.

### 3. Build and approve migration intent

```bash
py -m ex_migration_planner.cli build <migration-id>
```

Example:

```bash
py -m ex_migration_planner.cli build sw1203
```

The plan binds approved evidence into deterministic intent. It preserves all
configured VLAN definitions and separates pre-stage configuration from endpoint
configuration that must wait until after cables move.

The plan itself cannot render configuration, connect to devices, or authorize
writes.

### 4. Prepare the EX4400 pre-stage package

```bash
py -m ex_migration_provisioner.cli prepare <migration-id>
```

This binds the approved plan to the EX4400 template, bootstrap profile, site policy,
and renderer contract. No QFX connection occurs in this phase.

### 5. Render the EX4400 pre-stage configuration

```bash
py -m ex_migration_provisioner.cli render <migration-id>
```

The render includes everything safely known before physical cutover, including:

- target hostname;
- production management IRB/address/default route;
- all approved VLAN definitions, including configured-but-unobserved VLANs;
- SNMP/syslog/NTP identity;
- edge-port boilerplate;
- LLDP/LLDP-MED, RSTP, storm control, and IGMP snooping;
- EX4400 `ae0` and normal active LACP;
- voice VLAN policy;
- `TEMP-RECOVERY` VLAN and recovery-port overlay.

Endpoint-specific descriptions and data-VLAN memberships are deliberately excluded.

### 6. Identify and bind the replacement EX4400

Lab/vJunos example:

```bash
py -m ex_migration_provisioner.cli identify sw1203 \
  --transport-address 10.255.3.18
```

The identity record pins the replacement device's SSH host key, chassis/VC identity,
model, serial information, and bootstrap transport. The operator explicitly approves
binding that device to the migration.

Production uses the pre-established temporary `fxp0` bootstrap path rather than the
vJunos transport override.

### 7. Pre-stage the EX4400

```bash
py -m ex_migration_provisioner.cli run <migration-id>
```

This is the first EX4400 write-capable phase. It:

1. revalidates the approved replacement identity;
2. locks the candidate configuration;
3. loads only the approved pre-stage render;
4. runs commit check;
5. shows the exact candidate diff and digest;
6. asks one operator approval;
7. uses commit confirmed;
8. validates migration-critical running state;
9. confirms only after validation passes.

### 8. Perform the physical cutover

Operator/facilities action:

- move the old EX4300 uplinks to the replacement EX4400;
- move the upstream ends from the existing EX9200 environment to the QFX pair;
- move endpoint cables from the old EX4300 VC to the new EX4400 VC.

The QFX migration-facing AEs are independently pre-provisioned. Before migration,
they carry only the migration baseline: management VLAN 163 and temporary recovery
VLAN 3999.

### 9. Discover and approve the actual QFX attachment

```bash
py -m ex_migration_provisioner.cli discover-attachment <migration-id>
```

This command is read-only. It discovers the replacement EX4400 via LLDP on both
QFXs and requires:

- the same physical QFX interface on both devices;
- that interface to belong to the allowed migration-facing port pool;
- the same existing `aeN` on both devices;
- matching configured LACP system IDs;
- normal LACP with no `force-up`;
- all-active auto-derived ESI;
- the expected pre-cutover VLAN baseline;
- operational collecting/distributing state.

The observed attachment is shown to the operator for explicit approval and stored as
an immutable artifact. The migration does not allocate or invent a QFX AE.

### 10. Stage the required production VLANs on both QFXs

```bash
py -m ex_migration_provisioner.qfx_stage_cli <migration-id>
```

The command derives the production VLANs actually required by approved endpoint
intent. Configured-but-unused VLANs remain defined on the EX4400 but are not added to
the QFX AE unless endpoint intent requires them.

The coordinated transaction:

1. connects to both QFXs and revalidates the approved attachment;
2. locks both candidate databases;
3. rejects pre-existing candidate changes;
4. verifies required VLAN definitions already exist on both QFXs;
5. loads only planned AE VLAN-membership additions;
6. runs commit check on both;
7. requires symmetric candidate diffs;
8. shows the exact pair of diffs and asks one approval;
9. commit-confirms both devices;
10. validates LLDP, AE mapping, VLANs, no `force-up`, and LACP state on both;
11. finally confirms both only after pair validation passes.

Failure/asymmetry triggers coordinated rollback or compensating rollback as needed.
There is no true distributed atomic commit between Junos devices, so the workflow
approximates atomicity with locks, symmetric diffs, commit confirmed, pair
validation, and compensation.

### 11. Correlate and activate moved endpoints

```bash
py -m ex_migration_provisioner.cli activate-endpoints <migration-id>
```

The command connects to the replacement EX4400 and reads the current MAC table. It
correlates approved historical endpoint MAC evidence to the current physical edge
ports and applies only unambiguous endpoint intent.

For each activated endpoint port it may add:

- the approved interface description;
- the approved data-VLAN membership.

The global voice policy is already present from pre-stage and is not re-created per
port.

Silent, ambiguous, conflicting, duplicate, infrastructure, recovery, or otherwise
unsafe mappings are held for operator resolution rather than guessed.

The write path uses the same guarded candidate/commit-confirmed model as pre-stage:
identity revalidation, candidate lock, commit check, exact diff approval, commit
confirmed, validation, and final confirmation.

A separate in-band-management validation command is not required by the normal
workflow. In production, the endpoint activation connection itself targets the
approved production `management_ip`; inability to connect is the operational failure
signal. Lab profiles may use a transport override for vJunos while preserving the
logical production management identity.

## Planned post-migration operational work

### Old EX4300 recovery management

Before production cutover, give the old EX4300 a temporary recovery address on
`fxp0` and prove that recovery path works. The replacement EX4400 can then assume the
old switch's production management IP while the old switch remains independently
reachable for troubleshooting or rollback during the recovery window.

This phase is not yet automated.

### Facilities cable-position preservation and relabel report

Facilities wants to preserve existing cable labels wherever practical. EX4300-32F
VC members provide 40 endpoint-facing port positions in the existing deployment,
while EX4400 members provide additional port capacity.

The preferred physical move policy is:

- preserve the VC member number and port number whenever that equivalent location
  exists and is available;
- for example, an endpoint on `ge-0/0/12` should move to `ge-0/0/12`;
- preserve this same-position mapping across successive VC members first, leaving
  the additional EX4400 port positions unused initially;
- when the old VC has more member capacity than can be preserved one-for-one,
  place the remaining endpoint cables into the unused EX4400 access-port positions
  in a deterministic order;
- never consume reserved uplinks or the temporary recovery interface as ordinary
  endpoint positions while those reservations are active.

The post-cutover endpoint correlation already records the actual
`old_interface -> new_interface` mapping. A future facilities report should consume
that artifact and list **only ports whose physical interface changed**, because
those are the cables that need relabeling.

Example:

```text
Old port     New port      Description          VLAN   Action
ge-0/0/12    ge-0/0/12     Printer-101          200    no relabel
ge-5/0/7     ge-1/0/44     Camera-527           100    RELABEL
```

The normal facilities-facing output should suppress unchanged rows and provide a
concise Markdown/text report plus CSV containing at least:

- old interface;
- new interface;
- description;
- data VLAN;
- endpoint/MAC evidence;
- relabel required yes/no or reason.

This report is not yet implemented.

### TEMP-RECOVERY cleanup

After the recovery window closes, remove only the temporary recovery overlay and
leave the recovered interface as a normal edge port. This final lifecycle phase is
not yet automated.

## Identity and management discovery

For an old hostname such as:

```text
site1-ex4300-vc-fd-room101
```

the collector derives migration ID `room101` and proposed replacement hostname
`site1-ex4400-vc-fd-room101`. An optional `--migration-id` is an assertion and must
match the derived value.

The normalized management profile distinguishes the NETCONF connection and
`fxp0`/`mgmt_junos` path from the production management VLAN, IRB, address, and
default route. Management VLAN 163 is the default policy and can be changed with
`--management-vlan`.

SNMP name, location, engine ID, and SNMPv3 presence are collected through narrow
queries. Source-address configuration is deliberately not collected: the
authoritative EX4400 template renders required source addresses from the discovered
management IP. SNMP communities, authentication/privacy keys, login passwords, and
complete configuration dumps are not requested. A fail-closed content guard rejects
credential-bearing configuration before it can be written to a snapshot.

## Discovery collection details

Username and password are prompted when not otherwise supplied. A direct invocation
outside the project helper wrapper is also supported:

```bash
ex-migration-discovery collect \
  --host 192.0.2.15 \
  --output snapshots \
  --duration 120 \
  --interval 60
```

Repeat `--host` for batch collection or use an inventory. Credentials are obtained
once per batch and targets run concurrently with a bounded worker pool. A failed
device is reported without discarding successful collections from other devices.

Typical collection output:

```text
snapshots/migrations/<derived-migration-id>/
|-- manifest.json
|-- status.json
`-- old-switch/collections/
    `-- <timestamp>_<hostname>_<snapshot-id>/
        |-- snapshot.json
        |-- report.md
        |-- integrity.json
        |-- errors.json
        `-- raw/
```

## Reconciled MAC evidence

Current schema 1.4 discovery samples both `show ethernet-switching table` and
`show ethernet-switching table detail`. The views are parsed independently and
reconciled as a set of MAC, VLAN, and interface observations. Per-sample counts,
summary-only rows, detail-only rows, and reconciliation status are retained in the
immutable snapshot.

A failed reconciliation makes the snapshot ineligible under current policies.
Historical eligible snapshots remain independent artifacts; the analyzer builds a
digest-bound historical endpoint catalog rather than merging or rewriting old
collections.

## Finding review and silent-port classification

Operationally down access ports with no configured VLAN and no MAC are
`UNUSED_ACCESS_PORT` audit records. An operationally up, unassigned port with no MAC
is `ACTIVE_UNASSIGNED_SILENT`; a configured port without a current MAC is
`CONFIGURED_NO_MAC`. Historical observations remain attached to ports and can be
accepted explicitly during guided review.

The analyzer records review dispositions in immutable integrity-protected artifacts.
Routine approval uses the standard audit reason automatically; an operator reason is
requested when deliberately deviating from the recommended baseline or disposition.

## Safety model

The project intentionally fails closed around uncertain or stale state:

- raw discovery evidence is immutable and integrity checked;
- analysis and plan approvals are digest-bound;
- package/render changes produce new artifacts rather than mutating history;
- QFX attachment is discovered only after physical cutover;
- migration code never allocates an arbitrary QFX port/AE;
- `lacp force-up` is prohibited;
- QFX candidate changes require symmetric pair diffs;
- EX/QFX writes use commit check and commit confirmed;
- endpoint activation configures only unambiguous post-move correlations;
- silent/ambiguous/conflicting endpoints become holds rather than guesses;
- `TEMP-RECOVERY` is retained until the recovery window explicitly closes.
