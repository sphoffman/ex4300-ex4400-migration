# Guided operator workflow

The normal operator entry point is the repository-root `migrate` launcher.

```bash
./migrate <migration-id>
```

With no explicit phase, the launcher inspects immutable migration artifacts, displays current status, and offers to run the next safe action. Existing analyzer, planner, provisioner, QFX, endpoint, validation, and cleanup modules remain authoritative; the operator layer only orchestrates them and never bypasses their approvals or commit-confirmed safety checks.

## Migration inventory

When `data/ex4400_inventory.csv` contains a `READY` row for the migration ID, the guided workflow uses that row as the authoritative device-address inventory:

- `ex4300_ip` supplies the reachable old-switch address for discovery.
- `ex4400_ip` is the replacement EX4400 Virtual Chassis management (`vme`) address.
- `management_network` supplies the CIDR prefix used with the EX4400 VME/OOB address during pre-stage identity binding.

For example, a row with `ex4400_ip=172.16.198.19` and `management_network=172.16.198.0/24` supplies `172.16.198.19/24` to pre-stage automatically.

A row that exists but is not `READY` is not bypassed: the migration stops so a failed or dry-run baseline result cannot silently become authoritative. If no inventory file or no row exists for the migration ID, the existing interactive/explicit-address workflow remains available for compatibility. Explicit `--address` and `--oob-address` arguments continue to override automatic lookup.

## Repeatable discovery

With a `READY` inventory row, the migration ID is enough to locate the currently reachable EX4300:

```bash
./migrate sw1203 discover
```

Without an inventory row, the first discovery can still be supplied explicitly:

```bash
./migrate sw1203 discover --address 10.255.3.18
```

Each invocation creates one independent immutable discovery collection. Later runs can reuse the source address already recorded in discovery evidence.

Optional repeated collection is also supported:

```bash
./migrate sw1203 discover --count 3 --pause-minutes 60
```

Each collection remains a separate artifact. If a new collection is added after analysis or planning, `status` detects that the existing lineage does not cover all current discovery snapshots and routes the operator back through analysis and planning.

## Status and explicit phases

```bash
./migrate sw1203 status
./migrate sw1203 analyze
./migrate sw1203 build
./migrate sw1203 prestage
./migrate sw1203 cutover-ready
./migrate sw1203 cutover
./migrate sw1203 activate
./migrate sw1203 validate
./migrate sw1203 finalize
```

The phase commands group existing guarded operations. They stop immediately if an underlying command fails or the operator declines an approval.

When replacement identity has not yet been bound, `prestage` uses `ex4400_ip` plus `management_network` from the `READY` inventory row to derive the EX4400 VME/OOB CIDR automatically. The EX4400 `vme` interface is the Virtual Chassis management endpoint reached through the members' dedicated management ports; it is not treated as a separate in-band management address by the operator workflow.

`cutover` is an operator checkpoint only. It records a plan-bound acknowledgement that the physical cabling move is complete; it performs no device writes. Existing post-cutover QFX attachment artifacts can also prove that an older migration already passed that physical boundary.

## Historical MAC lookup

After migration, query the approved historical EX4300 evidence without connecting to either switch:

```bash
./migrate sw1203 mac 0011.2233.4455
```

Colon, hyphen, and Cisco dotted MAC formats are normalized. The lookup reports the old physical port, description, configured data VLAN, VLAN in which the MAC was actually observed, and supporting discovery snapshot IDs. A MAC observed on more than one old physical port is reported as `CONFLICTING_HISTORY` rather than guessed.

This distinction is intentional: for example, a phone MAC may have been observed in the voice VLAN while the physical access port's configured data VLAN was different.

## Launcher executable bit

The installed Python entry point is always available as:

```bash
ex-migration-operator <migration-id> status
```

The repository-root `migrate` file is a convenience launcher for the lab `py` wrapper. If a checkout does not preserve its executable bit, run this once:

```bash
chmod +x migrate
```
