# EX4300-to-EX4400 Migration Automation

Evidence-driven automation for staged Juniper EX4300-to-EX4400 migrations. The
workflow discovers the existing switch repeatedly, builds a composite immutable
evidence set, creates approved migration intent, pre-stages the replacement EX4400,
provides a guarded recovery path to the old EX4300 VC, validates the physical QFX
attachment after cutover, coordinates production VLAN changes across the QFX pair,
correlates moved endpoints from MAC evidence, activates only unambiguous endpoint
intent, and produces a facilities cable-relabel report from the completed move.

The design deliberately separates observation, approval, planning, rendering, and
live writes. Evidence and approvals are retained as immutable digest-bound artifacts
under `snapshots/migrations/<migration-id>/`.

## Normal operator workflow

The normal sequence is:

```text
DISCOVER OLD EX4300 (ONE OR MORE COLLECTIONS)
        ->
ANALYZE COMPOSITE EVIDENCE + APPROVE
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
ESTABLISH TEMP-RECOVERY L2 PATH
        ->
STAGE + PROVE OLD EX4300 VC RECOVERY
        ->
---------------- PHYSICAL CUTOVER ----------------
        ->
DISCOVER + APPROVE QFX ATTACHMENT
        ->
COORDINATED QFX VLAN STAGING
        ->
CORRELATE + ACTIVATE ENDPOINTS
        ->
GENERATE FACILITIES CABLING REPORT
        ->
VALIDATED MIGRATION
        ->
RECOVERY WINDOW
        ->
TEMP-RECOVERY CLEANUP
```

The final TEMP-RECOVERY cleanup phase is intentionally still pending implementation.

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

Repeated discovery is intentional. Different collections may observe different
sleeping/intermittent endpoints.

### 2. Analyze and approve composite evidence

```bash
py -m ex_migration_analyzer.cli run <migration-id>
```

Example:

```bash
py -m ex_migration_analyzer.cli run sw1203
```

The analyzer automatically includes all complete policy-eligible collections for the
migration. It does not ask the operator to choose one baseline snapshot.

The composite model:

- requires one consistent logical source identity (configured hostname);
- compares management, interface, VLAN, voice, and Junos configuration across
  eligible collections;
- uses the latest eligible collection as current configuration only after differences
  have been surfaced;
- accumulates endpoint MAC evidence across all eligible collections;
- treats a MAC observed on multiple old physical ports as conflicting evidence;
- retains hardware/serial observations as audit metadata rather than logical identity;
- creates an immutable evidence-set artifact binding all contributing collections.

The analyzer does not connect to or configure a device.

### 3. Build and approve migration intent

```bash
py -m ex_migration_planner.cli build <migration-id>
```

Example:

```bash
py -m ex_migration_planner.cli build sw1203
```

The plan binds approved composite evidence into deterministic intent. It preserves all
configured VLAN definitions and separates pre-stage configuration from endpoint
configuration that must wait until after cables move.

The plan itself cannot render configuration, connect to devices, or authorize writes.

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

Production uses the pre-established temporary management bootstrap path rather than
the vJunos transport override.

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

### 8. Stage and prove old EX4300 VC recovery management

For an EX4300 Virtual Chassis, the physical management ports are `me0`; the VC-wide
floating logical management interface is `vme`. The recovery workflow therefore adds
a temporary, distinct recovery address to `vme.0`. It does not remove or change the
existing in-band production management address.

The temporary recovery IP/prefix is intentionally explicit because no authoritative
production recovery-address pool is currently defined in site policy.

Example production form:

```bash
py -m ex_migration_provisioner.cli stage-old-recovery <migration-id> \
  --recovery-address <temporary-ip/prefix>
```

The TEMP-RECOVERY L2 path must be physically available before running this step—for
example by connecting an old-VC management port into the pre-staged EX4400 recovery
port and making VLAN 3999 reachable from the automation host.

The guarded transaction:

1. resolves the approved old hostname and current production management IP from the
   approved plan;
2. connects through the current old-switch management path;
3. requires the configured hostname to match the approved source identity;
4. preserves existing in-band management;
5. adds only the approved temporary `vme.0` recovery address;
6. locks the candidate, requires it to be clean, commit-checks, and shows the exact
   diff/digest;
7. asks one operator approval;
8. commit-confirms the change;
9. opens a second NETCONF connection through the temporary recovery address;
10. requires the recovery path to present the same SSH host key and hostname;
11. confirms the commit only after that second-path proof succeeds.

If second-path validation fails, the command explicitly rolls back or leaves the
commit-confirmed timer as the final safety boundary.

Lab transport overrides exist only to exercise workflow logic when vJunos cannot
expose `vme` directly; they are not accepted under a production site policy.

### 9. Perform the physical cutover

Operator/facilities action:

- move the old EX4300 uplinks to the replacement EX4400;
- move the upstream ends from the existing EX9200 environment to the QFX pair;
- move endpoint cables from the old EX4300 VC to the new EX4400 VC.

The QFX migration-facing AEs are independently pre-provisioned. Before migration,
they carry only the migration baseline: management VLAN 163 and temporary recovery
VLAN 3999.

### 10. Discover and approve the actual QFX attachment

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

### 11. Stage the required production VLANs on both QFXs

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

### 12. Correlate and activate moved endpoints

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
identity revalidation, candidate lock, candidate read-back/completeness proof,
commit check, exact diff approval, commit confirmed, bulk validation, and final
confirmation.

### 13. Generate the facilities cable-relabel report

```bash
py -m ex_migration_provisioner.cli cabling-report <migration-id>
```

The report is purely offline and selects the newest integrity-valid endpoint
transaction that is both **committed-and-confirmed** and validation `PASS`. An
explicit transaction can be selected with `--endpoint-transaction-id`.

The report intentionally lists only activated endpoint moves where:

```text
old_interface != new_interface
```

Those are the cables that require relabeling. Same-position moves are counted but
suppressed from the facilities rows.

Immutable output is written under:

```text
snapshots/migrations/<migration-id>/facilities-reports/<report-id>/
```

with:

- `report.md` — concise facilities-facing report;
- `report.csv` — spreadsheet/import-friendly rows;
- `report.json` — digest-bound machine-readable lineage;
- `integrity.json` — artifact hashes.

Rows contain old/new interface, description, VLAN, MAC evidence, and relabel reason.
Operator-held endpoint intents are counted but are not represented as completed
physical moves.

## Recovery window and cleanup

During the recovery window:

- the replacement EX4400 owns the production management IP;
- the old EX4300 VC remains independently reachable through its temporary `vme.0`
  recovery address;
- TEMP-RECOVERY VLAN 3999 remains present until cleanup is explicitly authorized.

Automation for removing the temporary old-switch recovery address and removing the
TEMP-RECOVERY overlay from the replacement is still pending.
