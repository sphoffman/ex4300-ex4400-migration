# EX4400 baseline discovery and provisioning

`ex4400-baseline` prepares a replacement EX4400 before the EX4300-to-EX4400 migration workflow.

## What it does

1. Connects to the source EX4300.
2. Reads the Ethernet-switching table for the configured management VLAN.
3. Ignores MAC addresses learned through configured uplinks (normally `ae0`).
4. Requires exactly one locally learned physical-interface MAC, unless `--port` explicitly selects the source interface.
5. Connects to the configured router and resolves that MAC through ARP.
6. Optionally requires the resulting address to be inside the configured management subnet.
7. Connects to the discovered address and refuses to continue unless the device reports an EX4400 model.
8. Loads the approved static baseline as a merge, runs commit check, and commits.
9. Upserts `data/ex4400_inventory.csv`. `READY` is written only after a successful commit.

The same username and password are reused for the EX4300, router, and EX4400. The normal workflow prompts for both.

## Setup

Create the local configuration:

```bash
cp config/ex4400-baseline.example.json config/ex4400-baseline.json
```

Edit the management subnet and the management address of the router that owns the gateway ARP entry.

Install the approved static baseline:

```bash
cp templates/ex4400/baseline.set.example templates/ex4400/baseline.set
```

Replace the example statements with the real baseline. No Jinja variables or other template expansion are performed.

## Run

Normal automatic discovery:

```bash
pyez -m ex4400_baseline 10.255.1.23
```

If more than one local MAC exists in the management VLAN, explicitly select the EX4300 port:

```bash
pyez -m ex4400_baseline 10.255.1.23 --port ge-4/0/47
```

Validate the candidate without committing:

```bash
pyez -m ex4400_baseline 10.255.1.23 --dry-run
```

For unattended test automation, the username can be supplied with `--username` and the password can be read from an environment variable using `--password-env`.

## Inventory contract

The CSV key is `migration_id`, derived from the EX4300 hostname. Re-running the utility updates that row rather than appending a duplicate.

Important fields are:

- `migration_id`
- `ex4400_ip`
- `ex4400_mac`
- `ex4300_interface`
- `ex4400_model`
- `ex4400_serial`
- `status`

The migration workflow must require `status == READY` before using `ex4400_ip`.

A reader is provided for migration code:

```python
from pathlib import Path
from ex4400_baseline.core import lookup_inventory

row = lookup_inventory(
    Path("data/ex4400_inventory.csv"),
    migration_id,
    require_ready=True,
)
ex4400_ip = row["ex4400_ip"]
```

The utility changes an existing row to `IN_PROGRESS` as soon as the EX4300 hostname is known, and changes it to `FAILED` on a handled error. This prevents an older `READY` row from remaining authoritative after a failed re-run.

## Notes

The static baseline is deliberately loaded with merge semantics. This utility does not perform an overwrite/replace operation.

The currently existing migration provisioner binds an OOB `fxp0`/`mgmt_junos` identity. The address discovered here is the EX4400 `vme` address on the management VLAN. Those are different concepts, so this change publishes a clean inventory contract rather than incorrectly feeding the vme address into the existing OOB identity field.
