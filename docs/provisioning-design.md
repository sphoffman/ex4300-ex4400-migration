# Provisioning design boundary

Release 0.7.0 introduces provisioning **preparation**, not configuration writes.
The new `prepare` path may connect to the QFX pair only for read-only preflight.
No EX4400 or QFX configuration lock, load, commit, or write implementation exists.

## Artifact chain

An approved migration-intent plan is not renderable by itself. A provisioning
package binds the exact plan and plan-approval digests, EX4400 template and
contract digests, QFX site-policy digest, bootstrap-profile digest, effective
settings digest, read-only QFX preflight digest, provisioner/renderer version,
normalized variables, artifacts, and validation result. Package approval and live
phase authorization remain separate future records.

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

The lab site policy is now concrete: BD-1 is `10.255.3.14`, BD-2 is
`10.255.3.15`, and the established migration mappings are `dh4301` on
`et-0/0/3 -> ae0`, `nh5302` on `et-0/0/4 -> ae1`, and `sw1203` on
`et-0/0/5 -> ae2`. ESI is all-active `auto-derive type-1-lacp`; the per-AE
LACP system IDs are explicit in the policy.

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

The intended public CLI remains `prepare`, `run`, `status`, and `recover`.
Release 0.7.0 implements only `prepare`; `run`, `status`, and `recover` remain
future work. Active silent-port probing remains a separate, explicit, fail-closed
change-run component and is not part of read-only discovery or QFX preflight.
