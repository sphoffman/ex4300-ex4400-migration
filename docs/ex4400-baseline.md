# EX4400 baseline discovery and provisioning

`ex4400-baseline` prepares a replacement EX4400 before the EX4300-to-EX4400 migration workflow.

## What it does

1. Checks whether NETCONF/SSH is reachable on the source EX4300.
2. If TCP/830 is unavailable, connects to the source EX4300 over SSH/22 with the normal EX4300/router credentials, verifies the chassis identifies as an EX4300, adds only `set system services netconf ssh`, commits, and waits for TCP/830 to become reachable.
3. Connects to the source EX4300 with PyEZ/NETCONF.
4. Reads the Ethernet-switching table for the configured management VLAN.
5. Ignores MAC addresses learned through configured uplinks (normally `ae0`).
6. Requires exactly one locally learned physical-interface MAC, unless `--port` explicitly selects the source interface.
7. Connects to the configured router and resolves that MAC through ARP.
8. Optionally requires the resulting address to be inside the configured management subnet.
9. Connects to the discovered address and refuses to continue unless the device reports an EX4400 model.
10. Loads the approved static baseline as a merge, runs commit check, and commits.
11. Upserts `data/ex4400_inventory.csv`. `READY` is written only after a successful commit.

The EX4300 and gateway router share one credential prompt. After the EX4400 vme address is discovered, the utility prompts separately for the replacement EX4400 credentials because the replacement may still be using local authentication before RADIUS is installed.

### Automatic NETCONF prerequisite

The source EX4300 does not need NETCONF enabled ahead of time. If port 830 is already reachable, the prerequisite step is a no-op. If it is not reachable, the utility uses SSH/22 and the same EX4300/router username and password to enable NETCONF. RADIUS-backed SSH username/password authentication works normally as long as the account has permission to enter configuration mode and modify `system services`.

The bootstrap refuses to make the change unless `show chassis hardware` identifies the target as an EX4300. It does not modify any other EX4300 configuration.

Because NETCONF is required to perform the rest of baseline discovery, this prerequisite bootstrap may enable NETCONF even when `--dry-run` is used. `--dry-run` prevents the replacement EX4400 baseline from being committed; it does not disable the source-switch NETCONF prerequisite.

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

Validate the EX4400 candidate without committing its baseline:

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

### Separate EX4400 credentials

Normal interactive use prompts twice:

```text
EX4300/router username:
EX4300/router password:
...
EX4400 username:
EX4400 password:
```

For automation, the two credential sets can be supplied independently:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10 \
  --username radius-user \
  --password-env OLD_SWITCH_PASSWORD \
  --ex4400-username local-admin \
  --ex4400-password-env NEW_SWITCH_PASSWORD
```
