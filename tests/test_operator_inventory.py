import csv

import pytest

from ex_migration_operator import current_cli as cli


def _write_inventory(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "migration_id",
        "ex4300_ip",
        "ex4400_ip",
        "management_network",
        "status",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _settings(tmp_path, inventory):
    return {
        "snapshot_root": str(tmp_path / "snapshots"),
        "ex4400_inventory_csv": str(inventory),
    }


def test_discover_uses_ready_inventory_ex4300_address(monkeypatch, tmp_path):
    inventory = tmp_path / "data" / "ex4400_inventory.csv"
    _write_inventory(
        inventory,
        [
            {
                "migration_id": "sw1203",
                "ex4300_ip": "172.16.163.10",
                "ex4400_ip": "172.16.198.19",
                "management_network": "172.16.198.0/24",
                "status": "READY",
            }
        ],
    )
    settings = _settings(tmp_path, inventory)
    monkeypatch.setattr(cli.legacy, "_settings", lambda _path: settings)
    monkeypatch.setattr(cli.legacy, "source_address_from_evidence", lambda _root: None)

    calls = []
    monkeypatch.setattr(
        cli.legacy,
        "_dispatch",
        lambda migration_id, command, extra: calls.append(
            (migration_id, command, list(extra))
        )
        or 0,
    )

    assert cli._dispatch("sw1203", "discover", []) == 0
    assert calls == [
        (
            "sw1203",
            "discover",
            ["--address", "172.16.163.10"],
        )
    ]


def test_prestage_derives_vme_oob_cidr_from_inventory(monkeypatch, tmp_path):
    inventory = tmp_path / "data" / "ex4400_inventory.csv"
    _write_inventory(
        inventory,
        [
            {
                "migration_id": "sw1203",
                "ex4300_ip": "172.16.163.10",
                "ex4400_ip": "172.16.198.19",
                "management_network": "172.16.198.0/24",
                "status": "READY",
            }
        ],
    )
    settings = _settings(tmp_path, inventory)
    monkeypatch.setattr(cli.legacy, "_settings", lambda _path: settings)
    monkeypatch.setattr(cli, "workflow_status", lambda _root: {"identity": "PENDING"})

    calls = []
    monkeypatch.setattr(
        cli.legacy,
        "_dispatch",
        lambda migration_id, command, extra: calls.append(
            (migration_id, command, list(extra))
        )
        or 0,
    )

    assert cli._dispatch("sw1203", "prestage", []) == 0
    assert calls == [
        (
            "sw1203",
            "prestage",
            ["--oob-address", "172.16.198.19/24"],
        )
    ]


def test_non_ready_inventory_blocks_migration_address_use(tmp_path):
    inventory = tmp_path / "data" / "ex4400_inventory.csv"
    _write_inventory(
        inventory,
        [
            {
                "migration_id": "sw1203",
                "ex4300_ip": "172.16.163.10",
                "ex4400_ip": "172.16.198.19",
                "management_network": "172.16.198.0/24",
                "status": "DRY_RUN",
            }
        ],
    )
    with pytest.raises(cli.OperatorError, match="not READY"):
        cli._inventory_row(_settings(tmp_path, inventory), "sw1203")


def test_inventory_vme_address_must_be_inside_management_network():
    row = {
        "ex4400_ip": "172.16.199.19",
        "management_network": "172.16.198.0/24",
    }
    with pytest.raises(cli.OperatorError, match="not inside management network"):
        cli._inventory_ex4400_oob(row, "sw1203")
