from __future__ import annotations

import csv
import io
from pathlib import Path

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

from .core import ProvisioningError


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _validate_transaction_dir(directory, migration_id):
    tx_path = directory / "transaction.json"
    diff_path = directory / "candidate.diff"
    integrity_path = directory / "integrity.json"
    _require(tx_path.is_file(), "missing endpoint transaction: %s" % tx_path)
    _require(diff_path.is_file(), "missing endpoint transaction diff: %s" % diff_path)
    _require(integrity_path.is_file(), "missing endpoint transaction integrity: %s" % integrity_path)
    integrity = read_json(integrity_path)
    _require(integrity.get("transaction.json") == sha256_file(tx_path), "endpoint transaction integrity failed: %s" % tx_path)
    _require(integrity.get("candidate.diff") == sha256_file(diff_path), "endpoint transaction diff integrity failed: %s" % diff_path)
    transaction = read_json(tx_path)
    _require(transaction.get("migration_id") == migration_id, "endpoint transaction migration ID mismatch")
    commit = transaction.get("commit", {})
    validation = transaction.get("validation", {})
    _require(commit.get("status") == "COMMITTED_AND_CONFIRMED", "endpoint transaction is not committed and confirmed")
    _require(commit.get("confirmed") is True, "endpoint transaction final confirmation is missing")
    _require(validation.get("result") == "PASS", "endpoint transaction validation did not pass")
    return {
        "transaction": transaction,
        "transaction_path": tx_path,
        "transaction_digest": sha256_file(tx_path),
    }


def choose_endpoint_transaction(migration_root, transaction_id=None):
    root = migration_root / "endpoint-transactions"
    if transaction_id:
        directory = root / str(transaction_id)
        _require(directory.is_dir(), "endpoint transaction %s was not found" % transaction_id)
        return _validate_transaction_dir(directory, migration_root.name)

    candidates = []
    if root.is_dir():
        for directory in root.iterdir():
            if not directory.is_dir():
                continue
            try:
                selected = _validate_transaction_dir(directory, migration_root.name)
            except ProvisioningError:
                continue
            tx = selected["transaction"]
            stamp = str(tx.get("commit", {}).get("confirmed_at") or tx.get("approved_at") or "")
            candidates.append((stamp, str(tx.get("transaction_id") or directory.name), selected))
    _require(candidates, "no integrity-valid committed-and-confirmed endpoint transaction was found")
    candidates.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def _mac_evidence(item):
    observed = item.get("observed_support") or {}
    return sorted(set(str(mac) for mac in observed) | set(str(mac) for mac in item.get("expected_macs", [])))


def build_facilities_report(transaction, transaction_digest):
    activated = sorted(
        transaction.get("activated", []),
        key=lambda item: (str(item.get("old_interface") or ""), str(item.get("new_interface") or "")),
    )
    moved = []
    unchanged = 0
    for item in activated:
        old_interface = str(item.get("old_interface") or "")
        new_interface = str(item.get("new_interface") or "")
        if old_interface == new_interface:
            unchanged += 1
            continue
        moved.append({
            "old_interface": old_interface,
            "new_interface": new_interface,
            "description": item.get("description"),
            "data_vlan_id": item.get("data_vlan_id"),
            "data_vlan_name": item.get("data_vlan_name"),
            "mac_evidence": _mac_evidence(item),
            "relabel_required": True,
            "reason": "PHYSICAL_INTERFACE_CHANGED",
        })

    body = {
        "schema_version": "1.0",
        "migration_id": transaction.get("migration_id"),
        "source_endpoint_transaction_id": transaction.get("transaction_id"),
        "source_endpoint_transaction_digest": transaction_digest,
        "source_confirmed_at": transaction.get("commit", {}).get("confirmed_at"),
        "rows": moved,
        "statistics": {
            "activated_endpoint_intents": len(activated),
            "same_position_no_relabel": unchanged,
            "relabel_required": len(moved),
            "operator_holds": len(transaction.get("holds", [])),
        },
    }
    report_id = sha256_bytes(canonical_bytes(body))[:16]
    result = dict(body)
    result["report_id"] = report_id
    return result


def render_markdown(report):
    stats = report["statistics"]
    lines = [
        "# Facilities Cable Relabel Report",
        "",
        "Migration: `%s`" % report["migration_id"],
        "",
        "Source endpoint transaction: `%s`" % report["source_endpoint_transaction_id"],
        "",
        "- Activated endpoint intents: %d" % stats["activated_endpoint_intents"],
        "- Same-position moves (no relabel): %d" % stats["same_position_no_relabel"],
        "- Relabel required: %d" % stats["relabel_required"],
        "- Operator holds not represented as completed moves: %d" % stats["operator_holds"],
        "",
    ]
    if not report["rows"]:
        lines.append("No completed endpoint moves require cable relabeling.")
        lines.append("")
        return "\n".join(lines)

    lines.extend([
        "| Old port | New port | Description | VLAN | MAC evidence | Action |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for row in report["rows"]:
        description = str(row.get("description") or "").replace("|", "\\|")
        vlan = "%s (%s)" % (row.get("data_vlan_name") or "", row.get("data_vlan_id"))
        macs = ", ".join(row.get("mac_evidence", []))
        lines.append(
            "| %s | %s | %s | %s | %s | RELABEL |"
            % (row["old_interface"], row["new_interface"], description, vlan, macs)
        )
    lines.append("")
    return "\n".join(lines)


def render_csv(report):
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "old_interface",
        "new_interface",
        "description",
        "data_vlan_id",
        "data_vlan_name",
        "mac_evidence",
        "relabel_required",
        "reason",
    ])
    for row in report["rows"]:
        writer.writerow([
            row["old_interface"],
            row["new_interface"],
            row.get("description") or "",
            row.get("data_vlan_id") if row.get("data_vlan_id") is not None else "",
            row.get("data_vlan_name") or "",
            ";".join(row.get("mac_evidence", [])),
            "yes" if row.get("relabel_required") else "no",
            row.get("reason") or "",
        ])
    return output.getvalue()


def write_facilities_report(migration_root, report):
    destination = migration_root / "facilities-reports" / report["report_id"]
    record_path = destination / "report.json"
    markdown_path = destination / "report.md"
    csv_path = destination / "report.csv"
    markdown = render_markdown(report)
    csv_text = render_csv(report)

    if record_path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("report.json") == sha256_file(record_path), "facilities report integrity failed")
        _require(integrity.get("report.md") == sha256_file(markdown_path), "facilities markdown integrity failed")
        _require(integrity.get("report.csv") == sha256_file(csv_path), "facilities CSV integrity failed")
        _require(read_json(record_path) == report, "existing facilities report ID has different content")
        _require(markdown_path.read_text(encoding="utf-8") == markdown, "existing facilities markdown changed")
        _require(csv_path.read_text(encoding="utf-8") == csv_text, "existing facilities CSV changed")
        return destination, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(record_path, report)
    markdown_path.write_text(markdown, encoding="utf-8")
    csv_path.write_text(csv_text, encoding="utf-8")
    atomic_json(destination / "integrity.json", {
        "report.json": sha256_file(record_path),
        "report.md": sha256_file(markdown_path),
        "report.csv": sha256_file(csv_path),
    })
    return destination, "CREATED"
