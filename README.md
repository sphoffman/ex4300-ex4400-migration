# EX Migration Discovery Collector

This is **Script 1 only** for the EX4300-to-EX4400 migration workflow. It is
read-only. It collects repeated operational observations, effective
configuration, structured XML, and raw CLI evidence into an immutable,
versioned snapshot. It does not load or commit configuration.

## Safety properties

- No configuration RPCs are implemented.
- Host-key verification is required by default.
- Passwords are read from an environment variable or an interactive prompt and
  are never written to the snapshot.
- Configuration collection is narrowly scoped; system authentication, RADIUS
  secrets, SNMP communities, private keys, and complete configuration dumps are
  never requested.
- Existing snapshot directories are never overwritten.
- Every raw artifact is SHA-256 hashed.
- A snapshot records partial/unsupported commands rather than silently omitting
  them.
- MAC addresses and interface names are normalized, but raw output is retained.
- Device types are not inferred from MAC OUIs.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
```

Ensure the device host key exists in the SSH known-hosts file before collecting.
Host-key checking can be disabled only with the conspicuous
`--no-host-key-check` lab option; production collection must not use it.

## Collect

### Using the Juniper PyEZ container

From the repository root, no host installation is required:

```bash
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --env EX_MIGRATION_PASSWORD \
  --env PYTHONPATH=/scripts/src \
  --volume "$PWD:/scripts" \
  --workdir /scripts \
  --entrypoint python \
  juniper/pyez \
  -m ex_migration_discovery.cli collect \
  --migration-id BLDG-A-IDF-101 \
  --host 10.0.0.15 \
  --username admin \
  --password-env EX_MIGRATION_PASSWORD \
  --output snapshots \
  --duration 120 \
  --interval 60 \
  --no-host-key-check
```

Use `--no-host-key-check` only in the lab, or mount a populated SSH known-hosts
file for verified operation.

```bash
export EX_MIGRATION_PASSWORD='temporary-password'

ex-migration-discovery collect \
  --migration-id BLDG-A-IDF-101 \
  --host 10.0.0.15 \
  --username admin \
  --password-env EX_MIGRATION_PASSWORD \
  --output snapshots \
  --duration 1800 \
  --interval 60
```

For an initial short lab check:

```bash
ex-migration-discovery collect \
  --migration-id BLDG-A-IDF-101 \
  --host 10.0.0.15 \
  --username admin \
  --password-env EX_MIGRATION_PASSWORD \
  --output snapshots \
  --duration 120 \
  --interval 60
```

The collector runs an initial static/configuration pass, then repeatedly samples
the MAC table, interface state, LLDP, LACP, DHCP security, and authentication
state. Unsupported commands are recorded in `errors.json` and do not erase the
rest of the snapshot.

## Output

Each run is grouped under a stable migration ID:

```text
snapshots/migrations/BLDG-A-IDF-101/
├── manifest.json
├── status.json
└── old-switch/collections/
    └── 20260904T190000Z_vQFX1_ab12cd34/
        ├── snapshot.json
        ├── report.md
        ├── integrity.json
        ├── errors.json
        └── raw/
```

`snapshot.json` has lifecycle state `COLLECTED`. Approval is deliberately not a
collector operation; a later review command will create a separate approval
record bound to the snapshot digest.

## Lab limitation

vJunos-switch does not reproduce every EX4300/EX4400 Virtual Chassis RPC, and
vJunosEvolved may omit production QFX Ethernet-segment operational commands.
Unsupported capabilities are recorded explicitly so lab success cannot be
mistaken for complete production-platform validation.
