# EX Migration Discovery Collector

Read-only discovery for staged EX4300-to-EX4400 migrations. The collector keeps
raw XML/text evidence and normalized state in immutable, per-migration snapshot
directories. It never loads or commits configuration.

## Identity and management

For an old hostname such as:

```text
site1-ex4300-vc-fd-room101
```

the collector derives migration ID `room101` and proposed replacement hostname
`site1-ex4400-vc-fd-room101`. An optional `--migration-id` is an assertion and
must match the derived value.

The normalized management profile distinguishes the NETCONF connection and
`fxp0`/`mgmt_junos` path from the production management VLAN, IRB, address, and
default route. Management VLAN 163 is the default policy and can be changed with
`--management-vlan`.

SNMP name, location, engine ID, and SNMPv3 presence are collected through narrow
queries. Source-address configuration is deliberately not collected: the
authoritative EX4400 template renders every required source address from the
discovered management IP. SNMP communities, authentication/privacy keys, login
passwords, and complete configuration dumps are not requested. Root-level
configuration retrieval is prohibited. A fail-closed content guard rejects any
command response containing credential-bearing configuration before it can be
written to a snapshot.

DHCP-security bindings and dot1x operational sessions are sampled only when the
corresponding configuration is present. `ethernet-switching-options` is queried
only as a fallback when the ELS `switch-options` hierarchy is unavailable.

## Single-switch collection

Username and password are prompted when not otherwise supplied:

```bash
ex-migration-discovery collect \
  --host 192.0.2.15 \
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
  --host 192.0.2.15 \
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
  --host 192.0.2.15 \
  --host 192.0.2.16 \
  --host 192.0.2.17
```

Or use an inventory:

```csv
old_address,new_fxp_address
192.0.2.15,198.51.100.10
192.0.2.16,198.51.100.11
192.0.2.17,198.51.100.12
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

## Offline analyzer

The normal guided workflow validates an explicitly selected immutable collection,
binds operator approval to its content digest, correlates endpoint evidence, and
writes deterministic analysis output without connecting to any device:

```bash
ex-migration-analyzer run dh4301
```

Omit the migration ID to be prompted. Paths and the default production policy
come from `config/site.json`. The attached production policy accepts schema 1.3
collections with a successful per-sample ledger; `lab-smoke-v1` is explicit and
not suitable for production approval. The analyzer never generates or applies
configuration.

Single-device discovery also accepts the address positionally:

```bash
ex-migration-discovery collect 10.100.163.10
```

The migration ID continues to be derived exclusively from the validated device
hostname.
