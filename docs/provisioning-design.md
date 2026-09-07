# Provisioning design boundary

This document records the agreed design after release 0.6.1. No renderer, device
connection, or device-write implementation exists in this increment.

## Artifact chain

An approved migration-intent plan is not renderable. A future immutable
provisioning package must bind the exact plan and plan-approval digests, template
and template-contract digests, QFX site-policy digest, settings digest, renderer
version, normalized variables, rendered artifacts, and static-validation results.
Package approval and live phase authorization are separate records.

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

The initial QFX AE carries the management and temporary-recovery VLANs. After
LLDP/LACP discovery proves symmetric physical interfaces, deterministic AE/ESI,
and the expected EX LACP partner, the required remaining VLANs are added. Operators
never supply QFX port numbers. Real campus QFX addresses, port pools, exclusions,
AE mapping, ESI convention, and LACP system-ID convention remain explicit blockers.

## Operator flow

The intended public CLI is `prepare`, `run`, `status`, and `recover`; internal
phases remain separately journaled. Active silent-port probing remains a separate,
explicit, fail-closed change-run component and is not part of read-only discovery.
