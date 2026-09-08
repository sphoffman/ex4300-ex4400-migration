# Provisioning design boundary

Release 0.9.2 adds a guarded **LAB-ONLY EX4400 pre-stage write path** on top of
the deterministic offline renderer introduced in 0.8.x. The renderer itself
remains version 0.8.1 so an already-approved 0.8.1 package/render does not become
stale merely because live-write orchestration or lab transport handling changes.
The `prepare` path may connect to the QFX pair only for read-only preflight.
`render` performs no device connections. `identify` connects read-only to the
bootstrap EX4400. `run` is the only command currently allowed to write, and it can
write only the bootstrap EX4400 pre-stage configuration. QFX writes remain
disabled.

## Artifact chain

An approved migration-intent plan is not renderable or writable by itself. A
provisioning package binds the exact plan and plan-approval digests, EX4400
template and contract digests, QFX site-policy digest, bootstrap-profile digest,
effective settings digest, read-only QFX preflight digest, renderer version,
normalized variables, artifacts, and validation result.

The package normalizes the configured VLAN inventory for rendering. Management,
voice, and temporary-recovery VLAN identities are explicit and digest-bound. The
approved plan must contain exactly the site-policy voice VLAN and management VLAN;
all configured VLAN names and IDs must be unique and valid; and TEMP-RECOVERY must
not collide with a configured VLAN. The renderer does not infer voice intent from
a VLAN name.

A render manifest then binds the package digest, template/contract digests,
rendered configuration digest, phase, renderer version, and static-validation
result. Live write authorization is not inherited from the render manifest; the
write transaction creates a separate exact-diff approval record.

## Day-zero bootstrap

Virtual Chassis formation, the initial administrative credential, SSH/NETCONF,
and temporary `fxp0` addressing are bootstrap responsibilities. They are excluded
from the migration template. Lab defaults are `10.0.0.15/24` with gateway
`10.0.0.2`. Production uses `local-fxp0-mac`; asserted and in-place-lab modes are
lab-only and can never regain production eligibility downstream.

The bootstrap VC topology also determines the recovery access port. A single-member
lab resolves to `ge-0/0/47`. For a multi-member VC, the member inventory must be
explicit and complete; the package selects port 47 on the highest declared member.
It fails closed rather than guessing when a multi-member inventory is incomplete.

## Bootstrap identity binding

Before a write session can be opened, `ex-migration-provisioner identify
<migration-id>` reads the SSH server host key and connects read-only to the EX4400.
It records the logical bootstrap address/port, SHA256 SSH host-key fingerprint,
hostname, model, chassis serial, and Virtual Chassis member serial/model inventory.
The operator must explicitly approve that exact observed identity. The resulting
immutable artifact is stored under:

```
snapshots/migrations/<migration-id>/bootstrap-identities/<identity-id>/
  identity.json
  integrity.json
```

Release 0.9.2 distinguishes the **logical Junos management address** from the
**transport endpoint used to reach the device**. This is needed for vrnetlab/
vJunos-switch, where the Junos VM retains logical management address `10.0.0.15`
while containerlab exposes the VM through the container's management address. In a
lab, the operator may therefore run:

```
ex-migration-provisioner identify <migration-id> \
  --transport-address <containerlab-management-ip>
```

The bootstrap profile remains unchanged and continues to bind logical `fxp0` to
`10.0.0.15`. The approved identity separately records the reachable transport
endpoint. The transport override is part of the operator-approved identity and is
therefore included in the deterministic identity ID. `run` accepts **no transport
override**; it must reconnect through the endpoint pinned by the selected identity.
If that endpoint changes, the operator must perform a new read-only `identify` and
approve the new binding. Normal physical hardware simply omits the override, in
which case logical and transport addresses are the same.

vJunos-switch is built from an EX9214 reference platform and reports `EX9214` as
its model. Release 0.9.2 accepts that model alias **only** when an explicit lab
transport endpoint different from the logical `fxp0` address is being pinned. A
direct bootstrap connection still requires an actual EX4400-family model and will
reject EX9214. The vJunos EX9214 alias is additionally limited to the single-member
lab bootstrap profile; it cannot become production eligible.

Interactive identity enrollment remains restricted to a lab bootstrap profile.
Production identity enrollment remains fail-closed until an independently pre-bound
serial/host-key trust source is implemented. Reachability to an IP address alone
never authorizes a write.

## Pre-stage render

Through `fxp0`, pre-stage applies the authoritative boilerplate, all approved
configured VLANs (including configured-but-unobserved VLANs), voice and management
VLANs, `TEMP-RECOVERY` VLAN 3999, management IRB/default route/SNMP identity, and
`ae0` with `vlan members all`. Endpoint descriptions and data-VLAN assignments
remain excluded.

The recovery port is the sole intentional physical-port VLAN assignment in
pre-stage. It remains part of the normal `edge_ports` range and receives a temporary
access-VLAN overlay for `TEMP-RECOVERY`. For the single-member lab this renders as
`ge-0/0/47 -> TEMP-RECOVERY`. Once the migration and old-switch recovery window are
complete, removing that one VLAN-membership statement returns port 47 to the same
ordinary edge-port behavior as the other client ports.

`ex-migration-provisioner render <migration-id>` renders that EX4400 pre-stage
configuration offline from the newest integrity-valid provisioning package (or an
explicit `--package-id`). Before rendering it revalidates the current settings,
template, template contract, QFX site policy, bootstrap profile, QFX preflight,
approved plan, and approval against the digests bound into the package. Any changed
input makes the package stale and rendering fails closed.

The rendered configuration uses the discovered management prefix rather than
assuming `/24`. Static validation rejects unresolved template syntax, credential
material, `fxp0` configuration, endpoint descriptions, any physical access-VLAN
assignment other than the exact package-bound TEMP-RECOVERY overlay, missing or
unapproved VLAN definitions, missing management identity, missing `ae0` trunking,
and missing DHCP-trust intent. A successful render creates:

```
snapshots/migrations/<migration-id>/packages/<package-id>/renders/<render-id>/
  ex4400-pre-stage.set
  render.json
  integrity.json
```

## Guarded EX4400 pre-stage write

`ex-migration-provisioner run <migration-id>` is LAB-ONLY in release 0.9.2. Before
loading configuration it revalidates the package/render digest chain and bootstrap
profile, loads the newest approved bootstrap identity (or an explicit identity ID),
reads the SSH server key again, and fails closed unless the pinned host key,
bootstrap address/port, hostname, model, and VC serial/model inventory still match.
For a vJunos identity, the transport endpoint is taken only from the approved
identity artifact; `run` provides no CLI transport override. The NETCONF session is
opened only after the independently read SSH fingerprint matches the approved
identity.

The configuration transaction uses the shared candidate database with an explicit
lock. The rendered `set` statements are loaded with **merge**, preserving day-zero
credentials and `fxp0` bootstrap configuration. It then performs `commit check`,
calculates the candidate diff, displays that exact diff and its SHA256 digest, and
requires explicit operator approval of that exact diff. Rejecting the prompt rolls
back the candidate and performs no commit.

After approval, the transaction record is written before device activation. The
first device commit is always `commit confirmed` (10 minutes by default, adjustable
within the guarded CLI range). While the automatic rollback timer is active, the
code rechecks the pinned host key and hardware identity and reads only targeted,
non-credential configuration hierarchies to prove every rendered statement is
present, including the planned hostname. Only after those validations pass does it
issue the final confirming commit. Validation failure triggers an explicit rollback
to rollback 1; if that rollback cannot be completed, the original confirmed-commit
timer remains the safety boundary.

Each approved write creates:

```
snapshots/migrations/<migration-id>/transactions/<transaction-id>/
  candidate.diff
  transaction.json
  integrity.json
```

The transaction binds the package, render manifest/config, bootstrap identity,
bootstrap-profile digest, exact candidate-diff digest, operator approval, commit
state, validation result, and rollback state. It explicitly records that QFX
connections and QFX writes are disabled.

## Recovery handoff

The temporary `fxp0` address is reused with physical break-before-make. Before
cutover, it is configured on the physically disconnected old EX4300 `fxp0`. After
the old production path is isolated, new EX in-band management is proven, and the
QFX/EX uplink is validated, the cable moves from new EX `fxp0` to old EX `fxp0`.
Its other end connects to `ge-<highest-active-VC-member>/0/47` on the new EX4400.
That port remains in `edge_ports` and receives explicit `TEMP-RECOVERY` membership.
Every management-ownership transition requires hostname, model, serial/chassis,
and SSH host-key validation; reachability alone is insufficient.

## QFX boundary

The lab site policy is concrete: BD-1 is `10.255.3.14`, BD-2 is `10.255.3.15`,
and the established migration mappings are `dh4301` on `et-0/0/3 -> ae0`,
`nh5302` on `et-0/0/4 -> ae1`, and `sw1203` on `et-0/0/5 -> ae2`. ESI is
all-active `auto-derive type-1-lacp`; the per-AE LACP system IDs are explicit in
the policy. The lab site policy also binds voice VLAN `voip`/1111, management VLAN
163, and TEMP-RECOVERY/3999.

`ex-migration-provisioner prepare <migration-id>` connects read-only to both BDs
and fails closed unless hostname/model, physical link state, port-to-AE mapping,
ESI mode, configured LACP system ID, collecting/distributing state, and symmetric
LLDP neighbor identity all match policy. A failed preflight creates no package.
The successful preflight is saved as `qfx-preflight.json` and digest-bound into the
package. Operator-supplied QFX ports remain prohibited.

No QFX connection occurs in `identify` or `run`, and no QFX write implementation
exists in 0.9.2. The future QFX transaction remains a separate coordinated two-QFX
candidate/commit-confirmed workflow with stronger partner-identity validation.

## Operator flow

The current safety-first lab flow is:

```
prepare <migration-id>
render <migration-id>
identify <migration-id> [--transport-address <lab-endpoint>]
run <migration-id>
```

`prepare` and `render` may already have been completed under renderer 0.8.1; adding
0.9.x live-write or lab-transport tooling does not invalidate an otherwise current
0.8.1 render. `status` and `recover` remain future work. Active silent-port probing
remains a separate, explicit, fail-closed change-run component and is not part of
read-only discovery, QFX preflight, offline rendering, or EX4400 pre-stage writes.
