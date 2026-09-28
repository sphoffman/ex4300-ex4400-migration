# EX4300-to-EX4400 Migration Rehearsal Runbook

This document describes the lab test strategy for the EX4300-to-EX4400 migration automation.

The preferred high-fidelity rehearsal uses a **real EX4300 VC as the source of truth** for configuration, VLANs, interfaces, MAC learning, endpoint history, and discovery evidence. The physical endpoint cable move is then simulated so that the normal post-cutover correlation and EX4400 activation workflow can be exercised before the first production migration.

The simulator does **not** implement a separate endpoint-correlation algorithm. It generates the same immutable post-cutover observation artifact that the live collector generates. The normal production correlation, activation, validation, and reporting code consumes that artifact.

## Rehearsal levels

### Level 1 - All-virtual regression rehearsal

Use this for software development and repeatable regression testing.

```text
source vJunos-switch
  -> normal discovery
  -> normal analysis/planning
  -> replacement vJunos-switch prestage
  -> simulated physical client move
  -> normal correlation
  -> real config write to replacement vJunos-switch
  -> validation/reporting
```

This validates workflow and software behavior but does not prove physical EX4300/EX4400 hardware behavior.

### Level 2 - Real-EX4300 hardware-source rehearsal

This is the preferred pre-production lab test.

```text
real EX4300 VC
  -> real discovery/config/MAC evidence
  -> normal analysis
  -> normal migration-plan approval
  -> EX4400 replacement identity/prestage
  -> normal physical-cutover workflow checkpoint
  -> QFX attachment discovery/VLAN staging as applicable
  -> simulated physical endpoint cable move
       - mostly same-position placements
       - intentional swapped-port placements
  -> normal production endpoint correlation
  -> real EX4400 endpoint configuration
  -> port-state/cabling validation
```

The MAC addresses used by the simulator are **not invented**. They come from the real EX4300 discovery evidence. Only their post-cutover placement on the replacement switch is simulated.

## What Level 2 proves

| Phase | Test behavior |
| --- | --- |
| EX4300 discovery | **Real** collection from the physical EX4300 VC |
| Source configuration/VLAN inventory | **Real** |
| Source MAC/interface evidence | **Real** |
| Historical endpoint evidence | **Real** |
| Analyzer/planner | Normal production code |
| Replacement identity | Real connection to replacement EX4400 or approved lab surrogate |
| Replacement prestage | Real candidate, commit-check, commit-confirmed, validation, final confirmation |
| Physical cutover checkpoint | Normal operator workflow acknowledgement used as a lab gate |
| QFX attachment discovery | Real when the lab QFX topology is present |
| QFX VLAN staging | Real writes to the lab QFX pair when included in the rehearsal |
| Physical client cable move | **Simulated** |
| Post-move MAC/interface evidence | **Simulated placement using real EX4300 MAC evidence** |
| Endpoint correlation | Normal production code |
| Endpoint configuration | Real write to the replacement switch |
| Post-commit config validation | Real |
| Cabling report | Normal production output derived from completed endpoint mappings |

## Prerequisites

Use the consolidated production branch:

```bash
git checkout main
git pull --ff-only
```

The test environment should have:

- one real EX4300 VC containing representative production-like configuration and endpoint/MAC learning;
- one replacement EX4400 VC, or an approved lab replacement target where hardware is not available;
- the lab QFX pair when QFX attachment/staging is part of the rehearsal;
- working NETCONF/SSH reachability to every device used by the test;
- site configuration, policies, templates, and environment files appropriate for the lab;
- a clean migration artifact area or a new migration ID for each complete rehearsal;
- the `juniper/pyez` Docker image available locally;
- the repository's portable `./py` launcher.

For an air-gapped lab, the runtime does not require Internet access. The optional unit-test suite can use the repository's offline test dependency bundle.

## Test 0 - Verify the software baseline

Before a migration rehearsal, run:

```bash
./scripts/test.sh
```

The current consolidated checkpoint is:

```text
278 passed
```

On an air-gapped server, `test.sh` uses `vendor/test-wheels/` when that offline dependency bundle was built and transferred with the repository.

The unit tests are a software sanity check. They are not a substitute for the hardware-source rehearsal below.

## Test 1 - Discover the real EX4300 VC

Run the normal discovery path against the real EX4300 management address.

For a short lab collection:

```bash
./py migrate.py discover <ex4300-management-ip> --count 1 --duration 10
```

For a production-like rehearsal, use the normal observation duration and multiple samples rather than the short example above.

Expected outcome:

```text
Collection summary
SUCCESS ...
Discovered migration ID: <migration-id>
```

Record the migration ID. All later steps use the same ID.

### Verify

Confirm that the discovery captured the expected:

- VC member/inventory information;
- configured interfaces;
- VLAN inventory;
- Ethernet-switching/MAC evidence;
- LLDP evidence where expected;
- management identity;
- configured-but-silent ports;
- historical observations used by the analyzer.

Do not continue if the source evidence is obviously incomplete.

## Test 2 - Analyze the real EX4300 evidence

```bash
./py migrate.py <migration-id> analyze
```

Review the analysis summary and findings.

The objective is to prove that the analyzer can consume a real EX4300 evidence set and correctly distinguish:

- observed endpoint ports;
- historically observed but currently silent ports;
- never-observed configured ports;
- review findings;
- operator holds;
- migration eligibility.

Do not dismiss hardware-specific findings merely because an earlier vJunos rehearsal allowed a lab limitation.

## Test 3 - Build and approve the migration intent

```bash
./py migrate.py <migration-id> build
```

Review the exact migration intent before approval.

Verify that:

- all required VLANs are preserved;
- endpoint ports are represented correctly;
- unused/template-default ports are identified correctly;
- management variables are correct;
- no unexpected operator holds exist;
- the approved plan references the expected analysis evidence.

The approval records migration intent. It does not itself authorize device writes.

## Test 4 - Prestage the replacement EX4400

Use the normal prestage path:

```bash
./py migrate.py <migration-id> prestage --oob-address <replacement-address>/<prefix>
```

Expected outcome:

```text
EX4400 pre-stage transaction: PASS
Commit confirmed validation: PASS
Final commit confirmation: PASS
```

This should exercise the real production prestage behavior:

- replacement identity binding;
- rendering;
- candidate review;
- commit-check;
- commit-confirmed;
- validation;
- final confirmation.

Do not generate the simulated post-cutover observation until prestage passes.

## Test 5 - Record the normal physical-cutover workflow checkpoint

Continue through the normal operator workflow:

```bash
./py migrate.py <migration-id> cutover
```

For this rehearsal, the acknowledgement is a **lab workflow gate**. It allows the state machine to continue through the same path used during a production migration.

It is not proof that client cables physically moved.

## Test 6 - Generate simulated EX4400 post-cutover placement from real EX4300 data

At the point where production would physically move the endpoint cables, generate a simulated post-cutover observation:

```bash
./py -m ex_migration_provisioner.postcutover_simulator_cli \
    <migration-id>
```

The simulator reads the approved migration evidence and creates replacement-side MAC/interface placement using those real source MAC addresses.

The default scenario uses two deterministic swap pairs:

```text
NORMAL_WITH_TWO_SWAPS
```

Useful options:

```text
--swap-pairs 0    all correlatable endpoints remain on same-position ports
--swap-pairs 1    one intentionally swapped pair
--swap-pairs 2    default; two intentionally swapped pairs
```

For the primary rehearsal, use the default two-swap scenario unless a different scenario is being tested deliberately.

The expected behavior is:

- most endpoints appear on the expected same-position EX4400 port;
- a small known set appears on intentionally different ports;
- MAC identity comes from the real EX4300 evidence;
- no device connection is made by the simulator;
- no device write is performed by the simulator.

Expected output includes:

```text
Post-cutover observation: VALID
Source: SIMULATED
Integrity: PASS
Device connections performed: no
Device writes performed: no
```

The observation is stored under:

```text
snapshots/migrations/<migration-id>/new-switch/postcutover-observations/<observation-id>/
```

with evidence such as:

```text
observation.json
mac-table.txt
interfaces-terse.txt
integrity.json
```

Record the observation ID.

## Test 7 - Discover and stage the QFX attachment

If QFX attachment and VLAN staging are part of the rehearsal, exercise them through the normal workflow.

The grouped `activate` path can satisfy missing QFX prerequisites automatically, or the QFX stages can be exercised separately when validating those transactions specifically.

Verify:

- both expected QFX devices are discovered;
- the EX4400 attachment is identified correctly;
- required VLAN changes match the approved migration plan;
- commit-check passes on both QFX devices;
- commit-confirmed validation passes;
- final confirmation succeeds.

Do not let the endpoint simulator replace QFX discovery or QFX staging. Those phases should remain real when the lab topology supports them.

## Test 8 - Preview endpoint correlation with no EX4400 endpoint writes

Replay the simulated observation through the normal operator-facing activation workflow:

```bash
./py migrate.py <migration-id> activate \
    --plan-only \
    --observation-id <observation-id>
```

`--observation-id` is a lab-only replay mechanism.

Verify:

- every same-position endpoint maps to its expected replacement interface;
- every intentional swap maps to the simulated destination interface;
- no endpoint is silently forced back to its original interface;
- missing/unexpected/ambiguous endpoints produce the expected hold behavior;
- EX4400 endpoint writes are not performed under `--plan-only`.

A clean scenario should show all expected endpoint intents as resolvable with no unexplained holds.

The plan-only run may persist immutable observation/correlation evidence, but it must not commit endpoint configuration or mark endpoint intents completed.

## Test 9 - Apply endpoint configuration to the replacement EX4400

After the mapping is reviewed and correct, replay the same observation without `--plan-only`:

```bash
./py migrate.py <migration-id> activate \
    --observation-id <observation-id>
```

This step performs the real endpoint configuration write to the replacement switch.

Review the candidate diff carefully.

The configured destination interfaces must match the MAC-derived simulated placement, including intentional swaps.

Expected result:

```text
EX4400 endpoint activation transaction: PASS
Commit-confirmed validation: PASS
Final confirmation: PASS
```

If no physical clients are connected to the replacement device, post-commit live MAC validation can legitimately report that expected MACs are not currently learned. Configuration validation remains the hard requirement for this simulated-cable rehearsal.

## Test 10 - Run post-cutover port-state comparison

To replay the same simulated observation into the port-state comparison:

```bash
./py -m ex_migration_provisioner.port_state_cli \
    <migration-id> \
    --observation-id <observation-id>
```

Review the comparison artifact and confirm that the expected interface-state/mapping differences are represented correctly.

## Test 11 - Generate and review the cabling report

Run the normal cabling-report workflow after endpoint mappings exist.

The intentionally swapped pairs should produce old/new interface differences requiring cabling or labeling attention.

This proves that facilities output is derived from completed endpoint mappings rather than from an assumption that every endpoint remains on the same numbered interface.

## Test 12 - Real plan-only recabling behavior

This is a separate production-behavior rehearsal and does **not** require the simulator.

During a real migration:

```bash
./py migrate.py <migration-id> activate --plan-only
```

If the live mapping shows misplaced client cables:

1. correct the physical cabling;
2. cause quiet endpoints to transmit/relearn if needed;
3. run `activate --plan-only` again;
4. because no `--observation-id` is supplied, collect a new live EX4400 observation;
5. repeat until the live mapping is correct;
6. run `activate` normally.

Do not replay an old observation ID after physically recabling when the goal is to discover the new state.

## Pass/fail checklist for the real-EX4300 rehearsal

Record each item for the lab run.

- [ ] Unit test suite passes.
- [ ] Real EX4300 discovery completes successfully.
- [ ] VC/member and interface inventory is correct.
- [ ] VLAN inventory is correct.
- [ ] Real EX4300 MAC/interface evidence is captured.
- [ ] Analyzer output is reasonable and review findings are understood.
- [ ] Migration intent is correct and approved.
- [ ] Replacement identity/prestage succeeds.
- [ ] Physical-cutover workflow checkpoint is recorded.
- [ ] QFX attachment discovery succeeds, if included.
- [ ] QFX VLAN staging succeeds, if included.
- [ ] Simulated observation is generated from the approved real EX4300 evidence.
- [ ] Expected same-position endpoints remain same-position.
- [ ] Intentional swapped endpoints appear on the expected alternate interfaces.
- [ ] Plan-only endpoint correlation passes with no unexplained holds.
- [ ] Candidate EX4400 endpoint configuration matches the simulated placement.
- [ ] EX4400 endpoint activation transaction passes.
- [ ] Port-state comparison is correct.
- [ ] Cabling report reflects intentional swaps.
- [ ] No simulator-specific correlation logic was required.

## Repeating the complete rehearsal

Migration artifacts and successful transactions are intentionally persistent.

Before a full repeat:

1. restore the source EX4300 to the intended test state if it was changed;
2. restore the replacement EX4400 to the intended pre-migration/base state;
3. restore the QFX pair to the expected pre-migration baseline;
4. use a new migration ID, or only in a disposable lab archive/remove the prior test artifacts;
5. rerun discovery from the beginning.

Never delete production migration evidence merely to make a workflow repeatable.

## What the real-EX4300 simulated-cable rehearsal still does not prove

Even with a physical EX4300 source, this test does not fully validate:

- the actual physical client cable move;
- endpoint relearning timing after real recabling;
- real silent-endpoint behavior on the replacement switch;
- production LLDP/LACP convergence timing;
- production optics/cabling faults;
- production management-path transition timing;
- every EX4400 VC/FPC hardware behavior unless the replacement side is also physical;
- every production rollback/failure timing condition.

Those require a full hardware rehearsal or the first controlled production migration.

## Additional fault-injection scenarios

After the normal/two-swap scenario passes end-to-end, useful deterministic scenarios include:

- no swaps;
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

These scenarios should continue to produce the normal post-cutover observation artifact. They must not introduce simulator-specific branches into the production correlation algorithm.

## Provenance requirement

Whenever simulated observation evidence is used, reports and operator review should distinguish clearly between real and simulated evidence:

```text
SOURCE EX4300 DISCOVERY: REAL
MIGRATION PLAN: REAL/APPROVED
REPLACEMENT PRESTAGE: REAL
PRE-ACTIVATION MAC/FORWARDING EVIDENCE: SIMULATED PLACEMENT USING REAL SOURCE MACS
CONFIGURATION TRANSACTION: REAL
POST-COMMIT CONFIG VALIDATION: REAL
POST-COMMIT LIVE MAC EVIDENCE: LIVE WHEN AVAILABLE
```

That distinction is essential when interpreting a successful rehearsal.
