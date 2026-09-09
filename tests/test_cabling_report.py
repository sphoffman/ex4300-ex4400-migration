import json

import pytest

from ex_migration_analyzer.core import sha256_file
from ex_migration_provisioner.cabling_report import (
    build_facilities_report,
    choose_endpoint_transactions,
    render_csv,
    render_markdown,
)
from ex_migration_provisioner.core import ProvisioningError


def _activated(old_interface, new_interface, description, vlan_id, vlan_name, mac):
    return {
        "old_interface": old_interface,
        "new_interface": new_interface,
        "description": description,
        "data_vlan_id": vlan_id,
        "data_vlan_name": vlan_name,
        "expected_macs": [mac],
        "observed_support": {mac: [new_interface]},
    }


def _selected(transaction_id, confirmed_at, activated, holds=None, plan_digest="a" * 64):
    transaction = {
        "transaction_id": transaction_id,
        "migration_id": "sw1203",
        "correlation_id": "corr-" + transaction_id,
        "activated": activated,
        "holds": list(holds or []),
        "commit": {
            "status": "COMMITTED_AND_CONFIRMED",
            "confirmed": True,
            "confirmed_at": confirmed_at,
        },
        "validation": {"result": "PASS"},
    }
    return {
        "transaction": transaction,
        "transaction_digest": ("d" if transaction_id == "tx1" else "e") * 64,
        "correlation": {
            "migration_id": "sw1203",
            "inputs": {"approved_plan_digest": plan_digest},
        },
        "correlation_digest": ("f" if transaction_id == "tx1" else "9") * 64,
        "approved_plan_digest": plan_digest,
    }


def test_report_aggregates_multiple_transactions_and_resolves_earlier_hold():
    first = _selected(
        "tx1",
        "2026-09-09T12:00:00Z",
        [
            _activated(
                "ge-0/0/12", "ge-0/0/12", "Printer-101", 200, "v200", "02:00:00:00:00:01"
            ),
            _activated(
                "ge-5/0/7", "ge-1/0/44", "Camera-527", 100, "v100", "02:00:00:00:00:02"
            ),
        ],
        holds=[{"old_interface": "ge-2/0/8", "reason": "NO_APPROVED_MAC_OBSERVED_POST_MOVE"}],
    )
    second = _selected(
        "tx2",
        "2026-09-09T12:30:00Z",
        [
            _activated(
                "ge-2/0/8", "ge-0/0/10", "Late-Phone", 100, "v100", "02:00:00:00:00:03"
            )
        ],
    )

    report = build_facilities_report([first, second], "a" * 64)
    assert report["schema_version"] == "1.1"
    assert [row["transaction_id"] for row in report["source_endpoint_transactions"]] == ["tx1", "tx2"]
    assert report["statistics"] == {
        "contributing_endpoint_transactions": 2,
        "activated_endpoint_intents": 3,
        "same_position_no_relabel": 1,
        "relabel_required": 2,
        "operator_holds": 0,
    }
    assert report["unresolved_operator_hold_interfaces"] == []
    assert [(row["old_interface"], row["new_interface"]) for row in report["rows"]] == [
        ("ge-2/0/8", "ge-0/0/10"),
        ("ge-5/0/7", "ge-1/0/44"),
    ]


def test_report_formats_include_only_relabel_rows_and_source_transaction():
    report = build_facilities_report([
        _selected(
            "tx1",
            "2026-09-09T12:00:00Z",
            [
                _activated(
                    "ge-0/0/12", "ge-0/0/12", "Printer-101", 200, "v200", "02:00:00:00:00:01"
                ),
                _activated(
                    "ge-5/0/7", "ge-1/0/44", "Camera-527", 100, "v100", "02:00:00:00:00:02"
                ),
            ],
        )
    ], "a" * 64)
    markdown = render_markdown(report)
    csv_text = render_csv(report)
    assert "`tx1`" in markdown
    assert "ge-5/0/7" in markdown
    assert "ge-1/0/44" in markdown
    assert "ge-0/0/12" not in markdown
    assert "ge-5/0/7" in csv_text
    assert "ge-0/0/12" not in csv_text
    assert "Camera-527" in csv_text
    assert "tx1" in csv_text


def test_report_fails_closed_on_conflicting_committed_mapping():
    first = _selected(
        "tx1",
        "2026-09-09T12:00:00Z",
        [_activated("ge-0/0/2", "ge-0/0/20", "Desk-A", 100, "v100", "02:00:00:00:00:01")],
    )
    second = _selected(
        "tx2",
        "2026-09-09T12:30:00Z",
        [_activated("ge-0/0/2", "ge-0/0/21", "Desk-A", 100, "v100", "02:00:00:00:00:01")],
    )
    with pytest.raises(ProvisioningError, match="conflicting mappings"):
        build_facilities_report([first, second], "a" * 64)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _write_history(migration_root, transaction_id, plan_digest, confirmed_at):
    correlation_id = "corr-" + transaction_id
    correlation_dir = migration_root / "endpoint-correlations" / correlation_id
    correlation = {
        "schema_version": "1.1",
        "correlation_id": correlation_id,
        "migration_id": migration_root.name,
        "inputs": {"approved_plan_digest": plan_digest},
    }
    _write_json(correlation_dir / "correlation.json", correlation)
    (correlation_dir / "mac-table.txt").write_text("mac evidence\n", encoding="utf-8")
    (correlation_dir / "interfaces-terse.txt").write_text("interface evidence\n", encoding="utf-8")
    _write_json(correlation_dir / "integrity.json", {
        "correlation.json": sha256_file(correlation_dir / "correlation.json"),
        "mac-table.txt": sha256_file(correlation_dir / "mac-table.txt"),
        "interfaces-terse.txt": sha256_file(correlation_dir / "interfaces-terse.txt"),
    })

    transaction_dir = migration_root / "endpoint-transactions" / transaction_id
    transaction = {
        "schema_version": "1.0",
        "transaction_id": transaction_id,
        "migration_id": migration_root.name,
        "correlation_id": correlation_id,
        "activated": [
            _activated(
                "ge-0/0/2", "ge-0/0/2", "Desk-A", 100, "v100", "02:00:00:00:00:01"
            )
        ],
        "holds": [],
        "commit": {
            "status": "COMMITTED_AND_CONFIRMED",
            "confirmed": True,
            "confirmed_at": confirmed_at,
        },
        "validation": {"result": "PASS"},
    }
    _write_json(transaction_dir / "transaction.json", transaction)
    (transaction_dir / "candidate.diff").write_text("candidate\n", encoding="utf-8")
    _write_json(transaction_dir / "integrity.json", {
        "transaction.json": sha256_file(transaction_dir / "transaction.json"),
        "candidate.diff": sha256_file(transaction_dir / "candidate.diff"),
    })


def test_auto_selection_aggregates_current_plan_and_skips_stale_plan(tmp_path):
    migration_root = tmp_path / "sw1203"
    current = "a" * 64
    stale = "b" * 64
    _write_history(migration_root, "current1", current, "2026-09-09T12:00:00Z")
    _write_history(migration_root, "stale1", stale, "2026-09-09T12:30:00Z")
    _write_history(migration_root, "current2", current, "2026-09-09T13:00:00Z")

    selected = choose_endpoint_transactions(migration_root, current)
    assert [item["transaction"]["transaction_id"] for item in selected] == ["current1", "current2"]

    with pytest.raises(ProvisioningError, match="different approved migration plan"):
        choose_endpoint_transactions(migration_root, current, "stale1")
