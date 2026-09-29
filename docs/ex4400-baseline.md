# EX4400 baseline discovery and provisioning

`ex4400-baseline` prepares a replacement EX4400 before the EX4300-to-EX4400 migration workflow.

For a complete explanation of which command form to use from the Linux host versus from inside the lab PyEZ container, see [`lab-pyez-usage.md`](lab-pyez-usage.md).

## What it does

1. Connects to the source EX4300.
2. Reads the Ethernet-switching table for the configured management VLAN.
3. Ignores MAC addresses learned through configured uplinks (normally `ae0`).
4. Requires exactly one locally learned physical-interface MAC, unless `--port` explicitly selects the source interface.
5. Connects to the configured router and resolves that MAC through ARP.
6. Optionally requires the resulting address to be inside the configured management subnet.
7. Connects to the discovered replacement switch and verifies that it is an allowed EX4400 target. Lab mode may accept the configured vJunos surrogate model.
8. Loads the approved static baseline as a merge, runs commit check, and commits.
9. Upserts `data/ex4400_inventory.csv`. `READY` is written only after a successful commit.

The EX4300 and gateway router share one credential prompt. After the EX4400 VME/OOB address is discovered, the utility prompts separately for the replacement EX4400 credentials because the replacement may still be using local authentication before RADIUS is installed.

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

## Run from the Linux host

The repository-managed `./py` wrapper is the preferred host-side launcher:

```bash
./py -m ex4400_baseline 10.255.1.23
```

If more than one local MAC exists in the management VLAN, explicitly select the EX4300 port:

```bash
./py -m ex4400_baseline 10.255.1.23 --port ge-4/0/47
```

Validate the candidate without committing:

```bash
./py -m ex4400_baseline 10.255.1.23 --dry-run
```

If a shell function named `py` is already defined and launches the same PyEZ container correctly, `py -m ...` can also be used. The repository `./py` wrapper is preferred because it carries the current Docker mount, `PYTHONPATH`, and UID/GID behavior with the repository.

Older examples that use `pyez -m ...` are obsolete; there is no project launcher named `pyez`.

## Run from inside PyEZ1

When the prompt is already inside the PyEZ container, for example:

```text
PyEZ1:~/scripts$
```

do not use the host-side `./py` wrapper. Python is already running in the correct container environment.

From the repository root:

```bash
cd ~/scripts
PYTHONPATH=src python -m ex4400_baseline 10.255.1.23
```

Dry run:

```bash
PYTHONPATH=src python -m ex4400_baseline 10.255.1.23 --dry-run
```

If several standalone module commands will be run in the same shell, export the source path once:

```bash
export PYTHONPATH="$PWD/src"
python -m ex4400_baseline --help
python -m ex4400_baseline 10.255.1.23 --dry-run
```

## Credentials

Normal interactive use prompts twice:

```text
EX4300/router username:
EX4300/router password:
...
EX4400 username:
EX4400 password:
```

For unattended test automation, the two credential sets can be supplied independently:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10 \
  --username radius-user \
  --password-env OLD_SWITCH_PASSWORD \
  --ex4400-username local-admin \
  --ex4400-password-env NEW_SWITCH_PASSWORD
```

The equivalent host-side form is:

```bash
./py -m ex4400_baseline 172.16.163.10 \
  --username radius-user \
  --password-env OLD_SWITCH_PASSWORD \
  --ex4400-username local-admin \
  --ex4400-password-env NEW_SWITCH_PASSWORD
```

## Inventory contract

The CSV key is `migration_id`, derived from the EX4300 hostname. Re-running the utility updates that migration's row rather than appending a duplicate, while rows for other migration IDs are retained.

Important fields include:

- `migration_id`
- `ex4300_ip`
- `ex4400_ip`
- `management_network`
- `ex4400_mac`
- `ex4300_interface`
- `ex4400_model`
- `ex4400_serial`
- `status`

The guided migration workflow uses a `READY` inventory row as the authoritative address source. It can obtain the existing EX4300 address from `ex4300_ip` and derive the replacement EX4400 VME/OOB address with prefix from `ex4400_ip` plus `management_network`.

A reader is also available to lower-level migration code:

```python
from pathlib import Path
from ex4400_baseline.core import lookup_inventory

row = lookup_inventory(
    Path("data/ex4400_inventory.csv"),
    migration_id,
    require_ready=True,
)
ex4300_ip = row["ex4300_ip"]
ex4400_ip = row["ex4400_ip"]
```

The utility changes an existing row to `IN_PROGRESS` as soon as the EX4300 hostname is known, and changes it to `FAILED` on a handled error. This prevents an older `READY` row from remaining authoritative after a failed re-run.

## Management-interface terminology

On an EX4400 Virtual Chassis, the VC management endpoint is the logical `vme` interface reached through the members' dedicated management ports. In this project, the address discovered by MAC-to-ARP resolution for the replacement switch is the EX4400 **VME/OOB management address** used during prestage identity binding.

This is separate from any later permanent in-band management interface such as an IRB carried across the production uplinks.

Older project text that called the EX4400 OOB management endpoint `fxp0` was using terminology more common on other Junos platforms. For EX4400 VC documentation and operator prompts, use **VME/OOB management**.

## Notes

The static baseline is deliberately loaded with merge semantics. This utility does not perform an overwrite/replace operation.

For the normal migration after baseline inventory has been created, use the guided operator workflow rather than launching lower-level provisioning modules directly:

```bash
./migrate <migration-id>
```

or, from inside PyEZ1:

```bash
python migrate.py <migration-id>
```
