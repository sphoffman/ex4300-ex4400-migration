# Provisioning design boundary

Release 0.11.0 follows the actual physical EX4300-to-EX4400 migration sequence.
The central rule is that the EX4400 is fully pre-staged before it is connected to
the QFX pair, so pre-cutover work cannot depend on live QFX state or a known QFX
attachment.

Renderer version remains 0.8.2. Release 0.11.0 adds read-only post-cutover QFX
attachment discovery; QFX writes remain disabled.

## Agreed migration sequence

### 1. Discover and plan from the existing EX4300

Run discovery, analyzer, and planner against the live EX4300 while the existing
network is intact. The approved plan carries discovered VLAN inventory, management
identity, endpoint correlations, and post-move endpoint intent.

### 2. Day-zero/bootstrap the replacement EX4400 over fxp0

Before production cabling is moved, the replacement EX4400 is reachable over its
temporary fxp0 path. Day-zero provisioning is responsible for Virtual Chassis
formation/member numbering, initial credentials, SSH/NETCONF, temporary fxp0
addressing, and the minimum state required to reach the replacement switch.

`identify` then pins the replacement-switch identity: logical management address,
reachable transport endpoint, SSH host key, chassis serial/model, hostname, and VC
member inventory.

### 3. Pre-stage the EX4400 before cutover

`prepare`, `render`, and `run` apply everything safely knowable before the move:

- target hostname;
- management IRB/default route;
- all approved VLAN definitions, including configured-but-unobserved VLANs;
- voice VLAN and DHCP-trust intent;
- SNMP/syslog/NTP identity;
- LLDP/LLDP-MED, RSTP, storm control, IGMP snooping, and boilerplate;
- EX4400 ae0 with both uplink members and normal active LACP;
- TEMP-RECOVERY VLAN and the dedicated recovery-port overlay.

Endpoint-specific data-VLAN memberships and descriptions remain excluded.

**No QFX connection occurs in this phase.** `prepare` is fully offline with respect
to the QFX pair.

### 4. Perform the physical cutover

Move the EX4300 uplinks to the EX4400, move the upstream ends from the EX9200
environment to the QFX5700 pair, and move endpoint/client cables to the EX4400.

The QFX pair is independently pre-provisioned before migration work begins.
Migration-facing physical ports already map to prebuilt AEs. Those AEs initially
carry exactly the migration baseline required to establish connectivity:
management VLAN 163 and TEMP-RECOVERY VLAN 3999.

The migration workflow does not know which physical QFX port or AE a closet will
use until after these cables are moved.

### 5. Discover and bind the post-cutover QFX attachment

After the physical cabling exists, run:

```text
ex-migration-provisioner discover-attachment <migration-id>
```

This command is read-only. It connects to both QFXs and:

1. derives the expected target EX4400 hostname from the approved migration plan;
2. finds exactly one LLDP neighbor with that hostname on each QFX;
3. requires each discovered local interface to be in the allowed migration-facing
   port pool and not excluded;
4. requires the physical interface name to be identical on both QFXs;
5. reads the existing physical-interface configuration to learn its configured
   aeN rather than allocating or accepting an operator-supplied AE;
6. requires the learned aeN to be identical on both QFXs and inside the allowed AE
   range;
7. verifies active LACP with no force-up, all-active auto-derived ESI, and a
   configured LACP system ID;
8. requires the LACP system ID to match across the QFX pair;
9. requires the discovered AE to contain exactly the pre-cutover migration baseline
   VLAN IDs 163 and 3999;
10. requires the physical member to be collecting/distributing under normal LACP.

A passing observation is shown to the operator for explicit approval. Approval
creates an immutable artifact under:

```text
snapshots/migrations/<migration-id>/qfx-attachments/<attachment-id>/
  attachment.json
  integrity.json
```

The artifact binds the approved plan digest, site-policy digest, QFX SSH host-key
fingerprints, QFX identities, target EX hostname, LLDP evidence, physical interface,
existing AE, LACP system ID, baseline VLANs, and pair checks. It authorizes no QFX
or EX4400 writes.

If either cable is landed on the wrong physical port/AE, discovery fails and no
attachment artifact is created.

### 6. Post-cutover provisioning and validation

The next implementation phase will consume the approved attachment artifact rather
than rediscovering or accepting a port from the operator. It will:

1. revalidate the pinned QFX identities/host keys and discovered attachment;
2. coordinate both QFX candidate databases;
3. add the migration's production VLANs to the discovered AE on both QFXs;
4. commit-check both candidates and present exact diffs for approval;
5. commit-confirm both devices as one coordinated transaction;
6. validate symmetry, LLDP, normal LACP, and EX4400 in-band management;
7. apply endpoint descriptions/data-VLAN memberships to the EX4400;
8. validate endpoint/VLAN state;
9. retain TEMP-RECOVERY for the old-switch recovery window and clean it up only
   after migration completion.

QFX failure/asymmetry must roll back both QFXs; one-sided success is not an
acceptable outcome.

## Normal LACP is the cabling safety mechanism

Migration AEs use normal active LACP. `force-up` is explicitly prohibited by site
policy.

Matching AE numbers across the QFX pair are expected to present the same LACP
system ID, while different AEs present different system IDs. If an EX4400's two
uplinks are accidentally landed on different prebuilt AEs, the EX4400 sees
incompatible partner identities. The incompatible member cannot participate in the
same valid aggregate, which protects forwarding while still allowing the valid
member to provide a troubleshooting/management path.

Post-cutover discovery independently proves physical-interface symmetry, AE
symmetry, LACP system-ID symmetry, and collecting/distributing state before the
attachment can be approved.

## QFX site policy 1.1

The site policy contains no migration-ID-to-port/AE assignment. It binds only facts
known before cutover:

- QFX pair identities and management addresses;
- allowed migration-facing physical-port pools and exclusions;
- permitted AE range;
- management, voice, and TEMP-RECOVERY VLAN identities;
- expected pre-cutover baseline: VLAN 163 + 3999, active LACP, no force-up;
- ESI method;
- required post-cutover LLDP/LACP/symmetry checks.

Attachment method is `discover-from-existing-qfx-config`, and
`migration_assignment_prebound` must remain false.

## Pre-cutover package 1.1

`prepare <migration-id>` accepts no QFX credentials or NETCONF options and opens no
QFX connection. It binds the approved plan/approval, template/contract, static site
policy, bootstrap profile, settings, renderer version, and normalized EX4400 render
variables.

It contains no QFX preflight artifact/digest. Its QFX state is explicitly:

```text
attachment_state: UNKNOWN_UNTIL_POST_CUTOVER_DISCOVERY
physical_interface: null
ae_interface: null
force_up: false
```

Legacy package 1.0 artifacts remain immutable history; new prepare runs create
package schema 1.1.

## EX4400 write safety

`run` remains the only implemented write command and remains LAB_ONLY. It revalidates
package/render/identity integrity, SSH host key, and chassis/VC identity; locks the
candidate; performs merge + commit-check; displays the exact candidate diff and
SHA256 for explicit approval; uses commit confirmed; validates migration-critical
running state; rolls back on failure; and confirms only after validation passes.

`run` never connects to or writes the QFX pair.

## Stale artifact recovery

Packages and renders are immutable and digest-bound. If a template, contract,
settings file, site policy, bootstrap profile, or renderer version changes, rebuild
only the affected downstream artifacts:

```text
prepare <migration-id>
render <migration-id>
run <migration-id>
```

If the bootstrap profile changes, `identify` must also be repeated. Discovery,
analyzer, and planner are rerun only when their own inputs change.

## Current implementation boundary

Implemented in 0.11.0:

```text
EX4300 discovery/analyzer/planner
        ->
EX4400 day-zero identity binding
        ->
offline pre-cutover package/render
        ->
guarded EX4400 pre-stage write
        ->
physical cutover (operator action)
        ->
read-only QFX LLDP attachment discovery
        ->
approved physical-port/AE binding artifact
```

Next implementation target:

```text
coordinated dual-QFX VLAN transaction
        ->
EX4400 in-band validation
        ->
EX4400 post-move endpoint provisioning
        ->
end-to-end validation and recovery cleanup
```
