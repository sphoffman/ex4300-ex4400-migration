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
IDENTIFY REPLACEMENT EX4400 + BIND OOB ADDRESS/GATEWAY
        ->
PRE-STAGE EX4400
        ->
PRE-STAGE OLD EX4300 VC RECOVERY WHILE IN-BAND ACCESS STILL EXISTS
        ->
---------------- PHYSICAL CUTOVER ----------------
        ->
MOVE OOB/RECOVERY CABLING
        ->
OPTIONAL READ-ONLY OLD-EX RECOVERY VERIFICATION
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

### 6. Identify and bind the replacement EX4400 and OOB management intent

The address supplied to `identify` is a first-class migration input. It is the address
used to reach the replacement, the address/prefix pinned to the approved replacement
identity, and the address that will later be pre-staged on the old EX4300 VC as
`vme.0` recovery management.

Lab/vJunos example:

```bash
py -m ex_migration_provisioner.cli identify sw1203 \
  --oob-address 10.255.3.18/24
```

Production uses the same command and semantics with the replacement EX4400's actual
reachable OOB address/prefix. There is no separate replacement `transport_address`
concept for new identities.

During the same read-only connection, `identify` reads the configured IPv4 default
next-hop under `mgmt_junos`. The approved identity pins:

- the operator-supplied OOB address/prefix;
- the configured `mgmt_junos` default gateway observed on the replacement;
- SSH host key;
- hostname/model/serial and VC member identity.

The automation intentionally does not require the supplied OOB address to be bound to
a particular Junos interface on the replacement. That keeps lab and production on the
same identity/lineage path. On the old EX4300 VC, the approved OOB address will always
be staged on `vme.0`.

Historical schema-1.0 lab identities containing a separate `transport_address` remain
readable, but new identity artifacts use schema 1.1 and one authoritative OOB address.

### 7. Pre-stage the EX4400

```bash
py -m ex_migration_provisioner.cli run <migration-id>
```

This is the first EX4400 write-capable phase. It connects to the address pinned by
`identify` and:

1. revalidates the approved replacement identity;
2. locks the candidate configuration;
3. loads only the approved pre-stage render;
4. runs commit check;
5. shows the exact candidate diff and digest;
6. asks one operator approval;
7. uses commit confirmed;
8. validates migration-critical running state;
9. confirms only after validation passes.

### 8. Pre-stage old EX4300 VC recovery management

For an EX4300 Virtual Chassis, the VC-wide logical management interface is `vme`.
The recovery workflow consumes the OOB address/prefix and `mgmt_junos` default gateway
already pinned by the approved replacement identity. Recovery addressing is not
entered again at this stage.

Production form:

```bash
py -m ex_migration_provisioner.cli stage-old-recovery <migration-id>
```

The current lab may still use `--transport-address` only to reach the **old EX4300's
existing source/in-band path** through vrnetlab. That option is unrelated to the
replacement identity model and is rejected by production policy.

The deterministic recovery candidate is limited to the equivalent of:

```text
set system management-instance
set interfaces vme unit 0 family inet address <approved-oob-address/prefix>
set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop <approved-mgmt_junos-gateway>
```

`mgmt_junos` is the reserved Junos management instance. `set system
management-instance` places the supported VC management interface in that instance;
the workflow does not add a normal `routing-instances mgmt_junos interface vme.0`
statement.

The command never adds or changes a master `routing-options` default route. If an
existing `mgmt_junos` default route conflicts with the gateway pinned during
`identify`, the transaction fails closed rather than replacing or combining it.

This phase must run **before physical cutover**, while the old EX4300 is still
reachable through its existing management path. The replacement may still own the
same OOB address at this point. The safety boundary is physical: the replacement OOB
path and the old-switch recovery OOB path must remain L2-isolated until the recovery
cable is moved.

The guarded transaction:

1. resolves the approved old hostname and production management IP from the approved
   plan;
2. resolves and integrity-validates the approved replacement identity;
3. inherits the identity's OOB address/prefix and observed `mgmt_junos` gateway;
4. connects to the still-reachable old EX4300 source path;
5. requires the configured hostname to match approved source identity;
6. records and preserves the master routing-table default configuration;
7. loads only the deterministic `mgmt_junos`/`vme.0` recovery state;
8. locks the candidate, requires it to be clean, commit-checks, and shows the actual
   Junos delta/digest;
9. asks one operator approval;
10. commit-confirms the change;
11. validates the complete intended recovery state through the existing source path
    and proves the master default-route configuration did not change;
12. finally confirms the commit.

The candidate display is intentionally the Junos delta. Statements that already exist
(for example `set system management-instance` or the matching `mgmt_junos` default)
will not be repeated in the diff, but the complete intended state is still validated.

After the physical OOB cable move, an optional read-only diagnostic can verify that
the old VC is reachable through the recovery address:

```bash
py -m ex_migration_provisioner.cli verify-old-recovery <migration-id>
```

Failure of this optional diagnostic does not roll back or invalidate the pre-staged
recovery configuration. The first operator action is to verify/move the physical
recovery cabling, because that is the recovery path by design.

### 9. Perform the physical cutover

Operator/facilities action:

- move the old EX4300 uplinks to the replacement EX4400;
- move the upstream ends from the existing EX9200 environment to the QFX pair;
- move endpoint cables from the old EX4300 VC to the new EX4400 VC;
- move the OOB/recovery cable so the approved OOB address is physically presented to
  the old EX4300 VC recovery path rather than the replacement bootstrap path.

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
- the old EX4300 VC retains the approved migration OOB address on `vme.0` in
  `mgmt_junos` after the recovery cable is moved;
- TEMP-RECOVERY VLAN 3999 remains present until cleanup is explicitly authorized.

Automation for removing the temporary old-switch recovery address and removing the
TEMP-RECOVERY overlay from the replacement is still pending.
