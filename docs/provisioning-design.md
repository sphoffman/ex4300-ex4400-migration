# Provisioning design boundary

Release 0.10.0 realigns the provisioner to the actual physical migration sequence.
The important rule is simple: **the EX4400 is fully pre-staged before it is connected
to the QFX pair, so no pre-cutover command may depend on live QFX state or a known
QFX attachment.**

Renderer version remains 0.8.2. The EX4400 render semantics are unchanged; the
change is to package scope and migration sequencing.

## Agreed migration sequence

### 1. Discover and plan from the existing EX4300

Run discovery/analyzer/planner against the live EX4300 while the existing network is
still intact. The approved plan carries the discovered VLAN inventory, management
identity, endpoint correlations, and post-move port intent.

No EX4400 or QFX write is part of this phase.

### 2. Day-zero/bootstrap the replacement EX4400 over `fxp0`

Before production cabling is moved, the new EX4400 is reachable through temporary
`fxp0` connectivity provided by the existing environment. Day-zero provisioning is
responsible for:

- Virtual Chassis formation/member numbering;
- initial administrative credentials;
- SSH/NETCONF;
- temporary `fxp0` addressing;
- other minimum bootstrap state needed to reach the replacement switch.

Those settings are intentionally outside the migration render. `identify` then pins
the exact replacement-switch identity: logical management address, reachable
transport endpoint, SSH host key, chassis serial/model, hostname, and VC member
inventory.

### 3. Pre-stage the EX4400 before cutover

`prepare`, `render`, and `run` build and apply everything that can safely be known
before physical cutover:

- target hostname;
- management IRB/default route;
- all approved VLAN definitions, including configured-but-unobserved VLANs;
- voice VLAN and DHCP-trust intent;
- SNMP/syslog/NTP identity;
- LLDP/LLDP-MED, RSTP, storm control, IGMP snooping, and other boilerplate;
- EX4400 `ae0` with both uplink members and normal active LACP;
- `TEMP-RECOVERY` VLAN and the dedicated recovery-port overlay.

Endpoint-specific data-VLAN memberships and descriptions remain excluded until
after physical cutover.

**No QFX connection occurs in this phase.**

### 4. Perform the physical cutover

Move the physical topology:

- EX4300 uplinks to the EX4400;
- upstream ends from the EX9200 environment to the QFX5700 pair;
- endpoint/client cables from EX4300 to EX4400.

The QFX pair is assumed to have been independently pre-provisioned before migration
work begins. Migration-facing physical ports already map to prebuilt AEs, and those
AEs already carry the minimum migration baseline needed for initial connectivity:
management VLAN 163 and TEMP-RECOVERY VLAN 3999.

The migration workflow does **not** know which physical QFX port/AE a specific
closet will use before the cables are moved.

### 5. Post-cutover QFX attachment discovery

Only after the new physical cabling exists does the migration automation connect
read-only to the QFX pair.

The discovery algorithm will:

1. locate the target EX4400 by LLDP on each QFX;
2. require the discovered physical interface number to be the same on both QFXs;
3. verify the discovered interface is inside an allowed migration-facing port pool
   and not excluded/reserved;
4. read the existing QFX interface configuration to learn which `aeN` owns that
   physical interface;
5. require both QFXs to resolve to the same `aeN`;
6. read and compare the already-configured LACP system ID/ESI/LACP baseline;
7. bind that observed attachment into an immutable post-cutover discovery artifact.

Physical interfaces and AE numbers are therefore **observed after cutover**, not
operator-entered and not pre-bound to migration IDs.

### 6. Post-cutover provisioning and validation

After the attachment is discovered and approved, the post-cutover transaction can
add the migration's required production VLANs to the discovered QFX AE and apply the
endpoint-specific EX4400 interface configuration.

QFX changes must be a coordinated two-device transaction with locks, commit-check,
exact diff approval, commit-confirmed, symmetric validation, and rollback of both
sides on failure/asymmetry.

The expected order is:

1. validate discovered QFX attachment;
2. provision the discovered AE on both QFXs with the required production VLANs;
3. validate normal dual-sided LACP and LLDP;
4. prove EX4400 in-band management over VLAN 163;
5. apply endpoint descriptions/data-VLAN memberships on the EX4400;
6. validate endpoint/VLAN state;
7. retain TEMP-RECOVERY for the old-switch recovery window, then remove the
   migration-only overlay when complete.

## Normal LACP is the cabling safety mechanism

Migration AEs use normal active LACP. `force-up` is explicitly prohibited by the
site policy.

Each prebuilt AE on the QFX pair is expected to present a distinct LACP system ID,
while matching AE numbers across the two QFXs present the same system ID. If the two
EX4400 uplink cables are accidentally landed on different prebuilt AEs, the EX4400
sees incompatible LACP partner identities. Both links therefore cannot participate
in one valid aggregate; the incompatible link remains non-forwarding/detached while
a compatible member can still provide a management path.

That is preferable to `force-up`: normal LACP both protects production forwarding
and leaves enough connectivity for LLDP/QFX discovery to identify the cabling
mistake.

Post-cutover automation must still independently verify LLDP, physical-interface
symmetry, AE symmetry, LACP system-ID symmetry, and collecting/distributing state
before any production VLAN write is authorized.

## QFX site policy 1.1

The QFX policy no longer contains a migration-ID-to-port/AE mapping. It binds only
facts that are known before cutover:

- QFX pair identities/management addresses;
- allowed migration-facing physical-port pools and exclusions;
- permitted AE range;
- management, voice, and TEMP-RECOVERY VLAN identities;
- expected pre-cutover QFX baseline (VLAN 163 + 3999, active LACP, no force-up);
- ESI method;
- required post-cutover LLDP/LACP/symmetry validation rules.

The attachment method is explicitly `discover-from-existing-qfx-config`, and
`migration_assignment_prebound` must be false.

## Pre-cutover package 1.1

`prepare <migration-id>` is now fully offline. It accepts no QFX username/password,
NETCONF port, or host-key override because it performs no QFX connection.

The package binds:

- approved plan and approval digests;
- EX4400 template/contract digests;
- static QFX site-policy digest;
- bootstrap-profile digest;
- effective settings digest;
- renderer version;
- normalized render variables.

It deliberately contains no QFX preflight artifact or QFX preflight digest. Its QFX
metadata records:

```text
attachment_state: UNKNOWN_UNTIL_POST_CUTOVER_DISCOVERY
physical_interface: null
ae_interface: null
force_up: false
```

Its safety contract explicitly states that QFX connections are disallowed and that
no QFX attachment is pre-bound.

Legacy package schema 1.0 artifacts remain immutable historical records and can
still be read for audit/history, but new `prepare` runs create schema 1.1 packages.

## EX4400 bootstrap identity

Before a write session can be opened, `identify <migration-id>` reads the SSH server
host key and connects read-only to the EX4400. It records the logical bootstrap
address/port, SHA256 SSH host-key fingerprint, hostname, model, chassis serial, and
VC member serial/model inventory. The operator explicitly approves that exact
identity.

For vJunos/vrnetlab, the logical Junos `fxp0` address remains `10.0.0.15`, while an
explicit lab transport endpoint can point at the containerlab management address.
The transport endpoint is pinned into the identity; `run` accepts no arbitrary
transport override.

The vJunos EX9214 model alias remains lab-only and single-member-only.

## EX4400 write safety

`run` is the only currently implemented write command and remains LAB_ONLY. It:

- revalidates package/render/identity integrity;
- rechecks SSH host key and chassis/VC identity;
- locks the candidate;
- loads the render with merge;
- runs commit-check;
- displays the exact candidate diff and SHA256;
- requires explicit operator approval;
- commits with `commit confirmed`;
- validates migration-critical running state;
- explicitly rolls back on validation failure;
- issues final confirmation only after validation passes.

QFX connections and writes remain disabled in this command.

## Stale artifact recovery

Packages/renders are immutable and digest-bound. If a template, contract, settings
file, site policy, bootstrap profile, or renderer version changes, the operator is
told to rebuild only the affected downstream artifacts:

```text
prepare <migration-id>
render <migration-id>
run <migration-id>
```

`prepare` is offline and never refreshes a QFX preflight. If the bootstrap profile
changes, `identify` must also be repeated. Discovery/analyzer/planner are rerun only
when their own inputs changed.

## Current implementation boundary

Implemented now:

```text
EX4300 discovery/analyzer/planner
        ->
EX4400 day-zero identity binding
        ->
offline pre-cutover package/render
        ->
guarded EX4400 pre-stage write
```

Next implementation target:

```text
physical cutover
        ->
read-only QFX LLDP attachment discovery
        ->
approved discovered physical-port/AE binding
        ->
coordinated dual-QFX VLAN transaction
        ->
EX4400 post-move endpoint provisioning
        ->
end-to-end validation/recovery cleanup
```
