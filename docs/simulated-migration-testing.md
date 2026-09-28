# Simulated EX4300-to-EX4400 Migration Test Runbook

This document describes how to repeat the high-fidelity migration rehearsal that uses vJunos-switch and the post-cutover observation simulator.

The goal is to exercise as much of the production migration workflow as possible while simulating only the physical client cable move that cannot be reproduced reliably before the first real migration.

## Test objective

The rehearsal should prove this sequence:

```text
old-switch discovery
  -> analysis
  -> migration-plan approval
  -> replacement-switch identity/prestage
  -> physical-cutover workflow checkpoint
  -> QFX attachment discovery and VLAN staging
  -> simulated physical endpoint cable move
  -> normal endpoint correlation
  -> real replacement-switch endpoint configuration
  -> port-state/cabling validation
```

The important design rule is that the simulator does **not** invent a separate correlation algorithm. It creates the same immutable post-cutover observation artifact that the live collector creates, and the normal production correlation/activation code consumes that artifact.

## What is real and what is simulated

In the initial all-vJunos rehearsal:

| Phase | Test behavior |
| --- | --- |
| Old-switch discovery | Real collection from source vJunos-switch |
| Analyzer/planner | Normal production code |
| Replacement identity | Real connection to replacement vJunos-switch |
| Replacement prestage | Real candidate, commit-check, commit-confirmed, validation, final confirmation |
| Physical cutover checkpoint | Normal operator workflow acknowledgement used as a lab gate |
| QFX attachment discovery | Real if lab QFX topology is present |
| QFX VLAN staging | Real writes to the lab QFX pair |
| Physical client move | **Simulated** |
| Post-move MAC/interface evidence | **Simulated observation artifact** |
| Endpoint correlation | Normal production code |
| Endpoint configuration | Real write to replacement vJunos-switch |
| Post-commit config validation | Real live validation |
| Post-commit endpoint MAC validation | Live; expected MACs may be absent because no physical clients are connected |

A later, higher-fidelity rehearsal can replace the source vJunos-switch with a real EX4300 VC while keeping the replacement side virtual or physical.

## Prerequisites

Use the feature branch while this work is under development:

```bash
git checkout feature/postcutover-observation-simulation
git pull --ff-only
```

The test environment should have:

- one source vJunos-switch representing the old EX4300;
- one replacement vJunos-switch representing the EX4400;
- the lab QFX pair if QFX attachment/staging is being exercised;
- working NETCONF/SSH reachability to all devices used by the test;
- site configuration and environment files appropriate for the lab;
- a clean migration artifact directory or a new migration ID for a full repeat.

vJunos-switch is intentionally allowed only in the lab replacement-identity path. A vJunos source may also report `VIRTUAL_CHASSIS_UNSUPPORTED`; for an all-vJunos rehearsal this can be acknowledged as a lab limitation.

## Run the unit test suite first

Before a migration rehearsal, run the complete suite from the PyEZ environment.

If the local test dependency directory is already populated:

```bash
py -c '
import sys
sys.path.insert(0, "/scripts/.test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
```

The known-good checkpoint before the operator `activate --plan-only` wiring was:

```text
254 passed
```

New tests have since been added for operator preview/replay behavior, so the total will be higher after those changes are pulled.

If this isolated PyEZ environment uses normal `python` rather than the `py` helper, use the equivalent local invocation for that environment.

## Step 1 - Discover the source switch

For a short lab collection, explicitly reduce the observation window.

Example from the first rehearsal:

```bash
python migrate.py discover 172.16.163.10 --count 1 --duration 10
```

Expected outcome:

```text
Collection summary
SUCCESS ...
Discovered migration ID: <migration-id>
```

The first rehearsal derived:

```text
Migration ID: dh4301
```

For production-like testing, use a longer collection window and multiple samples.

## Step 2 - Analyze the old-switch evidence

```bash
python migrate.py <migration-id> analyze
```

Review the evidence summary and approve the exact evidence set used for analysis.

For an all-vJunos source, `VIRTUAL_CHASSIS_UNSUPPORTED` may be accepted as a lab limitation. Do not automatically carry that disposition into a real EX4300 production rehearsal.

Known-good first-rehearsal summary:

```text
Unique MACs:              20
Consistent MAC/port IDs:  20
Historical MAC conflicts: 0
Findings:                  3
```

## Step 3 - Build and approve the migration intent

```bash
python migrate.py <migration-id> build
```

Review the generated intent and approve it.

Known-good first-rehearsal summary:

```text
Endpoint ports to correlate: 8
Unused/template-default ports: 2
Operator holds: 0
Eligibility: LAB_ONLY
```

The first rehearsal created plan:

```text
43413a1bdaa9521a
```

## Step 4 - Prestage the replacement vJunos-switch

Use the normal prestage path so the test exercises real identity binding, rendering, candidate review, commit-confirmed, and validation.

Typical command:

```bash
python migrate.py <migration-id> prestage --oob-address <replacement-address>/<prefix>
```

Expected outcome:

```text
EX4400 pre-stage transaction: PASS
Commit confirmed validation: PASS
Final commit confirmation: PASS
```

Known-good first-rehearsal transaction:

```text
eb48af4c2d2f7f30
```

At this point the replacement switch is genuinely pre-staged. Do not generate the simulated post-cutover observation before prestage has passed.

## Step 5 - Use the normal physical-cutover workflow checkpoint

For the lab rehearsal, continue through the normal operator workflow:

```bash
python migrate.py <migration-id> cutover
```

The command performs no device writes. It records the normal physical-cutover acknowledgement required by the production state machine.

For this simulation, the acknowledgement is intentionally being used as a **lab workflow gate** so the rehearsal can continue through the same traditional operator path. No synthetic cutover state is currently required.

Treat this acknowledgement as disposable lab evidence only. It must not be interpreted as proof that physical client cabling actually moved during the simulated rehearsal.

## Step 6 - Generate the simulated post-cutover observation

At the point where the real migration would have physically moved the endpoint cables, run:

```bash
PYTHONPATH=src python -m ex_migration_provisioner.postcutover_simulator_cli \
    <migration-id>
```

The default scenario uses two deterministic swap pairs:

```text
NORMAL_WITH_TWO_SWAPS
```

Useful options:

```text
--swap-pairs 0    no intentional cable swaps
--swap-pairs 1    one swapped pair
--swap-pairs 2    default; two swapped pairs
```

The simulator performs no device connection and no device write.

Expected output includes:

```text
Post-cutover observation: VALID
Source: SIMULATED
Integrity: PASS
Device connections performed: no
Device writes performed: no
```

Known-good first-rehearsal result:

```text
Correlatable endpoint intents: 8
Approved endpoint MACs: 16
Same-position placements: 4
Moved placements: 4
Missing endpoints: 0
Unexpected endpoints: 0
Physical interfaces observed: 48
Dynamic MACs observed: 16
Observation: 79720a061c216eb9
```

The intentional cable mutations were:

```text
ge-0/0/2 -> ge-0/0/3
ge-0/0/3 -> ge-0/0/2
ge-0/0/4 -> ge-0/0/5
ge-0/0/5 -> ge-0/0/4
```

The observation is stored under:

```text
snapshots/migrations/<migration-id>/new-switch/postcutover-observations/<observation-id>/
```

with:

```text
observation.json
mac-table.txt
interfaces-terse.txt
integrity.json
```

## Step 7 - Discover and stage the QFX attachment

The grouped `activate` workflow can perform QFX attachment discovery and coordinated QFX VLAN staging automatically if they are still pending. The first rehearsal exercised those stages separately and produced:

```text
Coordinated QFX VLAN transaction: PASS
QFX commit-check: PASS on both
Commit-confirmed validation: PASS on both
Final confirmation: PASS on both
EX4400 writes performed: no
```

Known-good first-rehearsal QFX transaction:

```text
71f60d4ec40f6335
```

For a repeat test, either stage QFX separately as before or allow the grouped `activate` command in the next step to satisfy the missing QFX prerequisites using the normal approval path.

## Step 8 - Inspect the simulated endpoint mapping without endpoint writes

Use the normal operator-facing activation workflow and replay the synthetic observation:

```bash
python migrate.py <migration-id> activate \
    --plan-only \
    --observation-id <observation-id>
```

`--observation-id` is accepted through the operator wrapper only with a lab environment profile.

Expected result for a clean scenario:

```text
Completed endpoint intents: 0
Newly resolvable endpoint intents: 8
Holds: 0
Result: PASS
EX4400 writes performed: no (--plan-only)
QFX writes performed: no
```

Verify that the four intentionally swapped old ports map to the four simulated destination ports, and that the remaining four endpoint intents stay at the same physical position.

`--plan-only` still persists immutable observation/correlation evidence, but it does not create an endpoint transaction, does not commit endpoint configuration, does not mark endpoint intents completed, and does not offer endpoint-exception acceptance.

If QFX attachment/staging was still pending when this command started, those prerequisite phases may run first through their normal approval/commit-confirmed workflow. `--plan-only` applies specifically to the endpoint-activation portion.

## Step 9 - Apply the endpoint configuration to the replacement vJunos-switch

After the plan-only correlation looks correct, rerun the operator command without `--plan-only` while selecting the same synthetic observation:

```bash
python migrate.py <migration-id> activate \
    --observation-id <observation-id>
```

This is a **real endpoint write** to the replacement vJunos-switch.

Review the exact candidate diff. The expected destination interfaces must match the MAC-derived simulated placement, including the intentionally swapped interfaces.

If correct, approve the candidate.

Expected successful result:

```text
EX4400 endpoint activation transaction: PASS
Commit-confirmed validation: PASS
Final confirmation: PASS
QFX writes performed: no
```

Because the clients are synthetic rather than physically connected, the post-commit live MAC check may warn that an expected MAC is not currently learned. The configuration validation remains real and is the hard pass/fail check for this rehearsal.

## Step 10 - Run post-cutover port-state comparison

The current grouped `validate` path still collects/uses its normal validation inputs. To force the exact same simulated observation into the port-state comparison during this rehearsal, use:

```bash
PYTHONPATH=src python -m ex_migration_provisioner.port_state_cli \
    <migration-id> \
    --observation-id <observation-id>
```

Review the generated comparison artifact.

## Step 11 - Generate the cabling report

Run the normal cabling report command after endpoint mappings exist.

The two swapped pairs should produce four old/new interface differences that require relabeling/cabling attention.

This validates that facilities output is derived from the completed endpoint mappings rather than assuming same-position cabling.

## Real-migration plan-only recabling workflow

The simulator is not required for this production workflow.

During a real migration, use the normal operator command with no observation ID:

```bash
python migrate.py <migration-id> activate --plan-only
```

If the mapping shows misplaced client cables:

1. correct the physical cabling;
2. cause quiet endpoints to transmit/relearn if needed;
3. run the same `activate --plan-only` command again;
4. because no `--observation-id` is supplied, a new live EX4400 observation is collected;
5. repeat until the mapping is correct;
6. run `python migrate.py <migration-id> activate` normally.

Do not reuse an old `--observation-id` after recabling when the goal is to discover the new physical state. Reusing an observation ID intentionally replays the old immutable evidence.

## Repeating the entire simulated test

The migration artifacts and successful endpoint transactions are intentionally persistent. A full test repeat therefore needs a clean lab state.

Before repeating:

1. restore the source vJunos-switch to the intended old-switch test configuration and MAC population;
2. restore the replacement vJunos-switch to its pre-migration/base configuration;
3. restore the lab QFX pair to the expected pre-migration baseline;
4. use a new migration ID, **or**, in a disposable lab only, archive/remove the prior `snapshots/migrations/<migration-id>/` test artifacts before rediscovery;
5. rerun discovery from the beginning.

Never delete production migration evidence merely to rerun a workflow.

## What this test does not prove

A successful vJunos rehearsal does not validate:

- physical EX4400 VC formation;
- real FPC/PIC inventory behavior;
- optics and physical link behavior;
- LLDP/LACP convergence timing on production hardware;
- actual endpoint relearning after cable movement;
- real silent endpoint behavior;
- hardware-specific commit/rollback timing;
- production management-path transition behavior.

Those require a later real EX4300/EX4400 hardware rehearsal or the first controlled production migration.

## Remaining simulator/workflow improvements

The current simulator is sufficient to continue the present rehearsal. The operator wrapper now supports both `activate --plan-only` and lab-only `--observation-id`, and the lab rehearsal can use the normal physical-cutover checkpoint.

### Recommended next improvements

1. **Expose simulated post-cutover generation through the central/operator CLI.**
   `postcutover_simulator_cli` currently works as a standalone module. A cohesive lab command such as `simulate-postcutover` would make the rehearsal even easier to repeat.

2. **Derive replacement client-port inventory instead of assuming 48 GE ports per member.**
   The initial simulator intentionally targets the current EX4400-48-port design. Future hardware/model testing should derive valid edge interfaces from approved device/model inventory rather than hardcoding `ge-<member>/0/0-47`.

3. **Reuse the production recovery-interface fallback.**
   If a compatibility package leaves `recovery_interface` empty, the simulator should call the same production helper that derives the recovery port. Otherwise a future scenario could accidentally place a synthetic endpoint on the implicit recovery port.

4. **Make simulated provenance explicit in final transaction/report output.**
   Configuration writes can be real while pre-activation forwarding evidence is simulated. Reports should clearly state both facts, for example:

   ```text
   CONFIGURATION TRANSACTION: REAL/PASS
   PRE-ACTIVATION MAC/FORWARDING EVIDENCE: SIMULATED
   POST-COMMIT MAC EVIDENCE: LIVE
   ```

5. **Optional future lab-only cutover marker.**
   A separate simulated-cutover state is no longer required for the current rehearsal because the lab workflow intentionally uses the traditional cutover acknowledgement. It could still be added later if a distinct audit marker becomes useful.

### Future fault-injection scenarios

After the normal/two-swap scenario passes end to end, add deterministic scenarios for:

- one expected MAC missing;
- unexpected MAC on a client port;
- approved MACs from one old port appearing on multiple new ports;
- two old endpoint intents colliding on one new port;
- up/up silent port;
- phone + PC on one port;
- voice-only endpoint;
- multiple data MACs behind one port;
- same MAC observed in multiple data VLANs on the same physical port;
- endpoint moved after an initial plan-only observation;
- partially completed migration followed by rerun/reconciliation.

These should continue to generate the normal post-cutover observation artifact and should not introduce simulator-specific branches into the production correlation algorithm.
