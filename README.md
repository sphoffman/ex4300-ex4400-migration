# EX Migration Discovery Collector

Read-only discovery for staged EX4300-to-EX4400 migrations. The collector keeps
raw XML/text evidence and normalized state in immutable, per-migration snapshot
directories. It never loads or commits configuration.

## Identity and management

For an old hostname such as:

```text
home1-ex4300-vc-fd-dh4301
```

the collector derives migration ID `dh4301` and proposed replacement hostname
`home1-ex4400-vc-fd-dh4301`. An optional `--migration-id` is an assertion and
must match the derived value.

The normalized management profile distinguishes the NETCONF connection and
`fxp0`/`mgmt_junos` path from the production management VLAN, IRB, address, and
default route. Management VLAN 163 is the default policy and can be changed with
`--management-vlan`.

SNMP name, location, engine ID, SNMPv3 presence, and source-address statements
are collected through narrow queries. SNMP communities, authentication/privacy
keys, login passwords, and complete configuration dumps are not requested.

## Single-switch collection

Username and password are prompted when not otherwise supplied:

```bash
ex-migration-discovery collect \
  --host 10.0.0.15 \
  --output snapshots \
  --duration 120 \
  --interval 60
```

For the PyEZ container in the lab:

```bash
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --env PYTHONPATH=/scripts/src \
  --volume "$PWD:/scripts" \
  --workdir /scripts \
  --entrypoint python \
  juniper/pyez \
  -m ex_migration_discovery.cli collect \
  --host 10.0.0.15 \
  --output snapshots \
  --duration 120 \
  --interval 60 \
  --no-host-key-check
```

`--no-host-key-check` is for lab use only.

## Batch collection

Repeat `--host`:

```bash
ex-migration-discovery collect \
  --host 10.0.0.15 \
  --host 10.0.0.16 \
  --host 10.0.0.17
```

Or use an inventory:

```csv
old_address,new_fxp_address
10.0.0.15,10.200.10.10
10.0.0.16,10.200.10.11
10.0.0.17,10.200.10.12
```

```bash
ex-migration-discovery collect --inventory switches.csv
```

Credentials are obtained once per batch. A failed device is reported without
discarding successful collections from other devices, and the command exits
nonzero when any target fails.

## Output

```text
snapshots/migrations/<derived-migration-id>/
├── manifest.json
├── status.json
└── old-switch/collections/
    └── <timestamp>_<hostname>_<snapshot-id>/
        ├── snapshot.json
        ├── report.md
        ├── integrity.json
        ├── errors.json
        └── raw/
```

The normalized VLAN inventory retains configured-but-unobserved VLANs,
descriptions, IRB associations, observed MAC counts, and DHCP-trust evidence.
Non-management VLANs with IRBs and management identity inconsistencies are
reported for review rather than silently converted into provisioning input.
