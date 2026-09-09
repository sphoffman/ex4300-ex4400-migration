from __future__ import annotations

import csv
import io

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


def _validate_correlation(migration_root, transaction):
    correlation_id = str(transaction.get("correlation_id") or "")
    _require(correlation_id, "committed endpoint transaction has no correlation ID")
    directory = migration_root / "endpoint-correlations" / correlation_id
    path = directory / "correlation.json"
    integrity_path = directory / "integrity.json"
    _require(path.is_file(), "missing endpoint correlation: %s" % path)
    _require(integrity_path.is_file(), "missing endpoint correlation integrity: %s" % integrity_path)
    integrity = read_json(integrity_path)
    _require(
        integrity.get("correlation.json") == sha256_file(path),
        "endpoint correlation integrity failed: %s" % path,
    )
    for name in ("mac-table.txt", "interfaces-terse.txt"):
        expected = integrity.get(name)
        if expected is None:
            continue
        evidence_path = directory / name
        _require(evidence_path.is_file(), "missing endpoint correlation evidence: %s" % evidence_path)
        _require(
            expected == sha256_file(evidence_path),
            "endpoint correlation evidence integrity failed: %s" % evidence_path,
        )
    correlation = read_json(path)
    _require(
        correlation.get("migration_id") == migration_root.name,
        "endpoint correlation migration ID mismatch",
    )
    plan_digest = str(correlation.get("inputs", {}).get("approved_plan_digest") or "")
    _require(plan_digest, "endpoint correlation has no approved-plan digest")
    return {
        "correlation": correlation,
        "correlation_path": path,
        "correlation_digest": sha256_file(path),
        "approved_plan_digest": plan_digest,
    }


def _validate_transaction_dir(directory, migration_root):
    tx_path = directory / "transaction.json"
    diff_path = directory / "candidate.diff"
    integrity_path = directory / "integrity.json"
    _require(tx_path.is_file(), "missing endpoint transaction: %s" % tx_path)
    _require(diff_path.is_file(), "missing endpoint transaction diff: %s" % diff_path)
    _require(integrity_path.is_file(), "missing endpoint transaction integrity: %s" % integrity_path)
    integrity = read_json(integrity_path)
    _require(
        integrity.get("transaction.json") == sha256_file(tx_path),
        "endpoint transaction integrity failed: %s" % tx_path,
    )
    _require(
        integrity.get("candidate.diff") == sha256_file(diff_path),
        "endpoint transaction diff integrity failed: %s" % diff_path,
    )
    transaction = read_json(tx_path)
    _require(
        transaction.get("migration_id") == migration_root.name,
        "endpoint transaction migration ID mismatch",
    )
    commit = transaction.get("commit", {})
    validation = transaction.get("validation", {})
    committed = (
        commit.get("status") == "COMMITTED_AND_CONFIRMED"
        and commit.get("confirmed") is True
        and validation.get("result") == "PASS"
    )
    if not committed:
        return None
    correlation = _validate_correlation(migration_root, transaction)
    return {
        "transaction": transaction,
        "transaction_path": tx_path,
        "transaction_digest": sha256_file(tx_path),
        "correlation": correlation["correlation"],
        "correlation_path": correlation["correlation_path"],
        "correlation_digest": correlation["correlation_digest"],
        "approved_plan_digest": correlation["approved_plan_digest"],
    }


def choose_endpoint_transactions(migration_root, approved_plan_digest, transaction_id=None):
    """Return committed/PASS endpoint transactions bound to the current approved plan.

    Automatic selection aggregates every eligible current-plan transaction. Historical
    transactions from other approved plans remain valid immutable history but do not
    contribute to the current facilities report. An explicitly selected stale-plan
    transaction fails closed instead of being silently accepted.
    """
    root = migration_root / "endpoint-transactions"
    if transaction_id:
        directory = root / str(transaction_id)
        _require(directory.is_dir(), "endpoint transaction %s was not found" % transaction_id)
        selected = _validate_transaction_dir(directory, migration_root)
        _require(selected is not None, "endpoint transaction is not committed-and-confirmed with PASS validation")
        _require(
            selected["approved_plan_digest"] == approved_plan_digest,
            "endpoint transaction is bound to a different approved migration plan",
        )
        return [selected]

    candidates = []
    if root.is_dir():
        for directory in sorted(root.iterdir(), key=lambda path: path.name):
            if not directory.is_dir():
                continue
            selected = _validate_transaction_dir(directory, migration_root)
            if selected is None:
                continue
            if selected["approved_plan_digest"] != approved_plan_digest:
                continue
            tx = selected["transaction"]
            stamp = str(tx.get("commit", {}).get("confirmed_at") or tx.get("approved_at") or "")
            candidates.append((stamp, str(tx.get("transaction_id") or directory.name), selected))
    _require(
        candidates,
        "no integrity-valid committed-and-confirmed endpoint transaction bound to the current approved migration plan was found",
    )
    candidates.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in candidates]


def _mac_evidence(item):
    observed = item.get("observed_support") or {}
    return sorted(
        set(str(mac) for mac in observed)
        | set(str(mac) for mac in item.get("expected_macs", []))
    )


def _normalized_mapping(item):
    return {
        "old_interface": str(item.get("old_interface") or ""),
        "new_interface": str(item.get("new_interface") or ""),
        "description": item.get("description"),
        "data_vlan_id": item.get("data_vlan_id"),
        "data_vlan_name": item.get("data_vlan_name"),
    }


def _mapping_matches(a, b):
    return _normalized_mapping(a) == _normalized_mapping(b)


def build_facilities_report(selected_transactions, approved_plan_digest):
    _require(selected_transactions, "facilities report requires at least one endpoint transaction")
    selected = sorted(
        list(selected_transactions),
        key=lambda value: (
            str(value["transaction"].get("commit", {}).get("confirmed_at") or value["transaction"].get("approved_at") or ""),
            str(value["transaction"].get("transaction_id") or ""),
        ),
    )

    by_old = {}
    by_new = {}
    evidence_by_old = {}
    sources_by_old = {}
    held_old = set()
    source_rows = []

    for value in selected:
        _require(
            value.get("approved_plan_digest") == approved_plan_digest,
            "endpoint transaction is bound to a different approved migration plan",
        )
        transaction = value["transaction"]
        transaction_id = str(transaction.get("transaction_id") or "")
        source_rows.append({
            "transaction_id": transaction_id,
            "transaction_digest": value["transaction_digest"],
            "correlation_id": transaction.get("correlation_id"),
            "correlation_digest": value["correlation_digest"],
            "confirmed_at": transaction.get("commit", {}).get("confirmed_at"),
        })
        for hold in transaction.get("holds", []):
            old_interface = str(hold.get("old_interface") or "")
            if old_interface:
                held_old.add(old_interface)

        for item in transaction.get("activated", []):
            old_interface = str(item.get("old_interface") or "")
            new_interface = str(item.get("new_interface") or "")
            _require(
                old_interface and new_interface,
                "committed endpoint transaction contains an incomplete mapping",
            )
            previous = by_old.get(old_interface)
            if previous is not None:
                _require(
                    _mapping_matches(previous, item),
                    "committed endpoint history contains conflicting mappings for %s" % old_interface,
                )
            else:
                claimed = by_new.get(new_interface)
                _require(
                    claimed is None or claimed == old_interface,
                    "committed endpoint history maps multiple old interfaces to %s" % new_interface,
                )
                by_old[old_interface] = dict(item)
                by_new[new_interface] = old_interface
            evidence_by_old.setdefault(old_interface, set()).update(_mac_evidence(item))
            sources_by_old.setdefault(old_interface, set()).add(transaction_id)

    completed_old = set(by_old)
    unresolved_holds = sorted(held_old - completed_old)
    moved = []
    unchanged = 0
    for old_interface in sorted(by_old):
        item = by_old[old_interface]
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
            "mac_evidence": sorted(evidence_by_old.get(old_interface, set())),
            "source_endpoint_transaction_ids": sorted(sources_by_old.get(old_interface, set())),
            "relabel_required": True,
            "reason": "PHYSICAL_INTERFACE_CHANGED",
        })

    body = {
        "schema_version": "1.1",
        "migration_id": selected[0]["transaction"].get("migration_id"),
        "source_approved_plan_digest": approved_plan_digest,
        "source_endpoint_transactions": source_rows,
        "rows": moved,
        "statistics": {
            "contributing_endpoint_transactions": len(source_rows),
            "activated_endpoint_intents": len(by_old),
            "same_position_no_relabel": unchanged,
            "relabel_required": len(moved),
            "operator_holds": len(unresolved_holds),
        },
        "unresolved_operator_hold_interfaces": unresolved_holds,
    }
    report_id = sha256_bytes(canonical_bytes(body))[:16]
    result = dict(body)
    result["report_id"] = report_id
    return result


def render_markdown(report):
    stats = report["statistics"]
    source_ids = [row["transaction_id"] for row in report["source_endpoint_transactions"]]
    lines = [
        "# Facilities Cable Relabel Report",
        "",
        "Migration: `%s`" % report["migration_id"],
        "",
        "Source endpoint transactions: %s" % ", ".join("`%s`" % value for value in source_ids),
        "",
        "- Contributing endpoint transactions: %d" % stats["contributing_endpoint_transactions"],
        "- Activated endpoint intents: %d" % stats["activated_endpoint_intents"],
        "- Same-position moves (no relabel): %d" % stats["same_position_no_relabel"],
        "- Relabel required: %d" % stats["relabel_required"],
        "- Unresolved operator holds not represented as completed moves: %d" % stats["operator_holds"],
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
        "source_endpoint_transaction_ids",
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
            ";".join(row.get("source_endpoint_transaction_ids", [])),
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
