# Provisioning design boundary

Release 0.8.0 adds deterministic **offline EX4400 pre-stage rendering** on top of
the read-only provisioning preparation introduced in 0.7.x. The `prepare` path
may connect to the QFX pair only for read-only preflight. The new `render` path
performs no device connections. No EX4400 or QFX configuration lock, load,
commit, or write implementation exists.

## Artifact chain

An approved migration-intent plan is not renderable by itself. A provisioning
package binds the exact plan and plan-approval digests, EX4400 template and
contract digests, QFX site-policy digest, bootstrap-profile digest, effective
settings digest, read-only QFX preflight digest, provisioner/renderer version,
normalized variables, artifacts, and validation result. Package approval and live
phase authorization remain separate future records.

The package normalizes the configured VLAN inventory for rendering. Management,
voice, and temporary-recovery VLAN identities are explicit and digest-bound. The
approved plan must contain exactly the site-policy voice VLAN and management VLAN;
all configured VLAN names and IDs must be unique and valid; and TEMP-RECOVERY must
not collide with a configured VLAN. The renderer does not infer voice intent from
a VLAN name.

## Day-zero bootstrap

Virtual Chassis formation, the initial administrative credential, SSH/NETCONF,
and temporary `fxp0` addressing are bootstrap responsibilities. They are excluded
from the migration template. Lab defaults are `10.0.0.15/24` with gateway
`10.0.0.2`. Production uses `local-fxp0-mac`; asserted and in-place-lab modes are
lab-only and can never regain production eligibility downstream.

## Pre-stage

Through `fxp0`, pre-stage eventually applies the authoritative boilerplate, all
approved configured VLANs (including configured-but-unobserved VLANs), voice and
management VLANs, `TEMP-RECOVERY` VLAN 3999, management IRB/default route/SNMP
identity, and `ae0` with `vlan members all`. Endpoint descriptions and access-VLAN
assignments remain excluded.

`ex-migration-provisioner render <migration-id>` now renders that EX4400 pre-stage
configuration offline from the newest integrity-valid provisioning package (or an
explicit `--package-id`). Before rendering it revalidates the current settings,
template, template contract, QFX site policy, bootstrap profile, QFX preflight,
approved plan, and approval against the digests bound into the package. Any changed
input makes the package stale and rendering fails closed.

The rendered configuration uses the discovered management prefix rather than
assuming `/24`. Static validation rejects unresolved template syntax, credential
material, `fxp0` configuration, endpoint descriptions, endpoint data-VLAN
assignments, missing or unapproved VLAN definitions, missing management identity,
missing `ae0` trunking, and missing DHCP-trust intent. A successful render creates:

```
snapshots/migrations/<migration-id>/packages/<package-id>/renders/<render-id>/
  ex4400-pre-stage.set
  render.json
  integrity.json
```

The render ID is deterministic for the package/config/version inputs. Re-rendering
unchanged inputs produces the same artifact and returns `UNCHANGED`. Render
manifests explicitly state that device connections and device writes are disabled.

## Recovery handoff

The temporary `fxp0` address is reused with physical break-before-make. Before
cutover, it is configured on the physically disconnected old EX4300 `fxp0`. After
the old production path is isolated, new EX in-band management is proven, and the
QFX/EX uplink is validated, the cable moves from new EX `fxp0` to old EX `fxp0`.
Its other end connects to `ge-<highest-active-VC-member>/0/47` on the new EX4400.
That port remains in `edge_ports` and receives explicit `TEMP-RECOVERY` membership.
Every ownership transition requires hostname, model, serial, chassis, and SSH
host-key validation; reachability alone is insufficient.

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

The initial QFX AE will eventually carry only the management and temporary-recovery
VLANs. Adding the remaining approved VLANs is still a future separately authorized
write phase.

## Operator flow

The intended final public CLI remains `prepare`, `run`, `status`, and `recover`.
During the safety-first implementation sequence, release 0.8.0 also exposes an
explicit `render` command so rendered artifacts can be inspected before any `run`
implementation exists. `run`, `status`, and `recover` remain future work. Active
silent-port probing remains a separate, explicit, fail-closed change-run component
and is not part of read-only discovery, QFX preflight, or offline rendering.
