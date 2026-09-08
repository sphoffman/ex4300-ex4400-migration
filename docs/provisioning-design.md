# Provisioning design boundary

Release 0.9.6 provides a guarded **LAB-ONLY EX4400 pre-stage write path** on top of
the deterministic offline renderer. Renderer version 0.8.2 includes the
`in-place-lab` vJunos handling for nonstop-bridging while preserving the normal
production intent. `prepare` may connect to the QFX pair only for read-only
pre-stage policy validation. `render` performs no device connections. `identify`
connects read-only to the bootstrap EX4400. `run` is the only command currently
allowed to write, and it can write only the bootstrap EX4400 pre-stage
configuration. QFX writes remain disabled.

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

vJunos/vrnetlab separates the logical Junos management address from the reachable
container transport endpoint. In a lab the operator may use:

```
ex-migration-provisioner identify <migration-id> \
  --transport-address <containerlab-management-ip>
```

The bootstrap profile still binds logical `fxp0` to `10.0.0.15`; the approved
identity separately pins the reachable transport endpoint. `run` accepts no
transport override and must reconnect through that approved endpoint. If it
changes, a new read-only `identify` is required.

vJunos-switch reports the EX9214 reference platform. That alias is accepted only
for an explicit lab transport override and only for a single-member lab target. A
direct bootstrap connection still requires an EX4400-family model. The observed
bootstrap hostname must not match the approved source-switch hostname.

Interactive identity enrollment remains restricted to a lab bootstrap profile.
Production identity enrollment remains fail-closed until an independently pre-bound
serial/host-key trust source is implemented. Reachability alone never authorizes a
write.

## QFX pre-stage policy validation

`prepare` needs enough QFX evidence to bind the intended attachment before an EX
render can be created, but it must not require operational evidence that depends on
the EX pre-stage configuration itself. Release 0.9.6 therefore separates **static
QFX policy checks** from **live peer checks**.

The pre-stage-required checks are:

- expected QFX hostname and model;
- physical port maps to the policy-bound AE;
- configured LACP system ID matches policy;
- all-active auto-derived ESI configuration matches policy;
- physical-interface and AE symmetry across the QFX pair;
- LACP system-ID symmetry across the QFX pair.

The following operational checks are observed but may be deferred during
`prepare`:

- physical link up;
- LACP collecting/distributing;
- LLDP neighbor present;
- symmetric LLDP neighbor identity.

This removes the circular dependency in which LLDP was required before the EX
configuration that enables LLDP had been applied. The resulting
`qfx-preflight.json` uses schema 1.1 with readiness scope `EX4400_PRE_STAGE`, records
which observations were deferred, and explicitly lists the live checks that must
be revalidated after EX pre-stage and before any QFX write or cutover authorization.

Deferral is not a bypass. Positive contradictory evidence still fails closed. For
example, if neither QFX sees an LLDP neighbor, LLDP symmetry can be deferred. If
one or both QFXs see neighbors and the identities disagree, pre-stage readiness
fails.

Operator-supplied QFX physical ports remain prohibited. QFX mappings continue to
come only from the explicit approved site policy.

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
complete, removing that one VLAN-membership statement returns port 47 to ordinary
edge-port behavior.

For `in-place-lab`, renderer 0.8.2 emits the nonstop-bridging statement and then
explicitly deactivates `protocols layer2-control` because the single-member vJunos
reference platform rejects active nonstop-bridging without graceful switchover.
Non-lab-in-place rendering keeps nonstop-bridging active.

`render` operates offline from the newest integrity-valid provisioning package (or
an explicit `--package-id`). It revalidates current settings, template, template
contract, QFX site policy, bootstrap profile, QFX preflight, approved plan, and
approval against the package-bound digests. Any changed input makes the package
stale and fails closed.

A successful render creates:

```
snapshots/migrations/<migration-id>/packages/<package-id>/renders/<render-id>/
  ex4400-pre-stage.set
  render.json
  integrity.json
```

## Guarded EX4400 pre-stage write

`run` is LAB-ONLY. Before loading configuration it revalidates the package/render
digest chain and bootstrap profile, loads the selected approved bootstrap identity,
reads the SSH server key again, and fails closed unless the pinned host key,
bootstrap address/port, hostname, model, and VC serial/model inventory still match.
For vJunos, the transport endpoint comes only from the approved identity artifact.

The transaction uses an explicit candidate lock and loads the rendered `set`
statements with **merge**, preserving day-zero credentials and `fxp0` bootstrap
configuration. It performs `commit check`, calculates the exact candidate diff,
displays the diff and SHA256 digest, and requires explicit operator approval.
Rejecting the prompt rolls back the candidate and performs no commit.

After approval, the transaction record is written before activation. The first
commit is always `commit confirmed`. While that timer is active, the code rechecks
the pinned host key and hardware identity and proves every rendered statement is
present. Only after validation passes does it issue the final confirming commit.
Validation failure triggers explicit rollback; if explicit rollback fails, the
confirmed-commit timer remains the safety boundary.

Each approved write creates:

```
snapshots/migrations/<migration-id>/transactions/<transaction-id>/
  candidate.diff
  transaction.json
  integrity.json
```

No QFX connection occurs in `identify` or `run`, and no QFX write implementation
exists yet.

## Stale artifact recovery

Packages and renders are immutable and digest-bound. If a template, contract,
settings file, site policy, bootstrap profile, or renderer version changes, the CLI
reports which input changed and gives the minimum recovery sequence. Normally that
is:

```
prepare <migration-id>
render <migration-id>
run <migration-id>
```

If the bootstrap profile changed, `identify` must also be repeated. Discovery,
analyzer, and planner do not need to be rerun unless their own inputs changed.
Stale artifacts remain immutable history and should not be edited or deleted to
recover.

## Recovery handoff

The temporary `fxp0` address is reused with physical break-before-make. Before
cutover it is configured on the physically disconnected old EX4300 `fxp0`. After
the old production path is isolated, new EX in-band management is proven, and the
QFX/EX uplink is validated, the cable moves from new EX `fxp0` to old EX `fxp0`.
Its other end connects to `ge-<highest-active-VC-member>/0/47` on the new EX4400.
That port remains in `edge_ports` and receives explicit `TEMP-RECOVERY` membership.
Every management-ownership transition requires hostname, model, serial/chassis,
and SSH host-key validation.

## QFX boundary

The lab site policy is concrete: BD-1 is `10.255.3.14`, BD-2 is `10.255.3.15`, and
the established mappings are `dh4301` on `et-0/0/3 -> ae0`, `nh5302` on
`et-0/0/4 -> ae1`, and `sw1203` on `et-0/0/5 -> ae2`. ESI is all-active
`auto-derive type-1-lacp`; per-AE LACP system IDs are explicit. The policy also
binds voice VLAN `voip`/1111, management VLAN 163, and TEMP-RECOVERY/3999.

Before any future QFX write or cutover authorization, the deferred live-peer checks
must be rerun against the post-pre-stage EX and strengthened to prove the intended
EX peer. The future QFX write transaction remains a coordinated two-QFX
lock/commit-check/diff-approval/commit-confirmed workflow with symmetric rollback.

## Operator flow

The current lab flow is:

```
prepare <migration-id>
render <migration-id>
identify <migration-id> [--transport-address <lab-endpoint>]
run <migration-id>
```

`status`, live post-pre-stage QFX validation, coordinated QFX writes, cutover, and
`recover` remain future work. Active silent-port probing remains a separate,
explicit, fail-closed component.
