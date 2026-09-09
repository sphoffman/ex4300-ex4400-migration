from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from ex_migration_analyzer.core import (
    AnalysisError,
    atomic_json,
    canonical_bytes,
    read_json,
    safe_artifact,
    sha256_bytes,
    sha256_file,
    validate_collection,
)
from ex_migration_discovery.parsers import parse_mac_table_text

from .core import ProvisioningError


_PHYSICAL = re.compile(r"^(?P<name>[a-z]+-\d+/\d+/\d+)\s+(?P<admin>up|down)\s+(?P<oper>up|down)(?:\s|$)")
_EDGE = re.compile(r"^ge-(?P<member>\d+)/0/(?P<port>\d+)$")
_STATE_ORDER = ("ACTIVE_MAC", "UP_SILENT", "LINK_DOWN", "ADMIN_DOWN", "NOT_OBSERVED")


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def parse_terse_states(text):
    result = {}
    for raw in str(text or "").splitlines():
        match = _PHYSICAL.match(raw.strip())
        if not match:
            continue
        result[match.group("name")] = {
            "admin_status": match.group("admin"),
            "oper_status": match.group("oper"),
        }
    return result


def classify_port_state(admin_status, oper_status, dynamic_mac_present):
    if admin_status == "down":
        return "ADMIN_DOWN"
    if admin_status == "up" and oper_status == "down":
        return "LINK_DOWN"
    if admin_status == "up" and oper_status == "up":
        return "ACTIVE_MAC" if dynamic_mac_present else "UP_SILENT"
    return "NOT_OBSERVED"


def _access_ports(snapshot):
    return sorted(
        str(item.get("physical_name"))
        for item in snapshot.get("interfaces", [])
        if item.get("physical_name")
        and item.get("effective_mode") == "access"
        and not item.get("ae_parent")
    )


def _dynamic_ports_by_stamp(snapshot):
    values = defaultdict(set)
    for item in snapshot.get("mac_observations", []):
        if item.get("mac_type") != "dynamic":
            continue
        stamp = str(item.get("observed_at") or "")
        interface = str(item.get("physical_interface") or "")
        if stamp and interface:
            values[stamp].add(interface)
    return values


def _terse_artifact(sample_run):
    for entry in sample_run.get("commands", []):
        if entry.get("command") == "show interfaces terse" and entry.get("status") == "SUCCESS":
            return entry.get("text_artifact")
    return None


def build_port_state_evidence(candidates, lineage=None):
    """Reconstruct per-sample old-switch access-port states from approved collections."""
    history = defaultdict(list)
    collection_refs = []
    total_samples = 0

    ordered = sorted(
        candidates,
        key=lambda item: (
            str(item["snapshot"].get("started_at") or ""),
            str(item["snapshot"].get("snapshot_id") or ""),
        ),
    )
    for candidate in ordered:
        snapshot = candidate["snapshot"]
        collection = Path(candidate["path"])
        snapshot_id = str(snapshot.get("snapshot_id") or "")
        collection_refs.append({
            "snapshot_id": snapshot_id,
            "collection_digest": candidate["envelope"]["collection_digest"],
        })
        access_ports = _access_ports(snapshot)
        dynamic_by_stamp = _dynamic_ports_by_stamp(snapshot)
        sample_runs = snapshot.get("sample_runs") or []
        for sample_run in sample_runs:
            artifact = _terse_artifact(sample_run)
            if not artifact:
                raise AnalysisError(
                    "approved discovery sample %s/%s has no successful show interfaces terse artifact"
                    % (snapshot_id, sample_run.get("sample_index"))
                )
            path = safe_artifact(collection, artifact)
            if not path.is_file():
                raise AnalysisError("approved discovery terse artifact is missing: %s" % artifact)
            states = parse_terse_states(path.read_text(encoding="utf-8"))
            stamp = str(sample_run.get("observed_at") or "")
            dynamic_ports = dynamic_by_stamp.get(stamp, set())
            for interface in access_ports:
                observed = states.get(interface)
                admin = observed.get("admin_status") if observed else None
                oper = observed.get("oper_status") if observed else None
                state = classify_port_state(admin, oper, interface in dynamic_ports)
                history[interface].append({
                    "snapshot_id": snapshot_id,
                    "sample_index": int(sample_run.get("sample_index", 0)),
                    "observed_at": stamp,
                    "admin_status": admin,
                    "oper_status": oper,
                    "state": state,
                })
            total_samples += 1

    ports = []
    for interface in sorted(history):
        samples = sorted(
            history[interface],
            key=lambda item: (item["observed_at"], item["snapshot_id"], item["sample_index"]),
        )
        counts = Counter(item["state"] for item in samples)
        non_missing = {item["state"] for item in samples if item["state"] != "NOT_OBSERVED"}
        stable_state = next(iter(non_missing)) if len(non_missing) == 1 else "VARIABLE"
        latest = samples[-1]
        ports.append({
            "interface": interface,
            "samples": len(samples),
            "counts": {state: int(counts.get(state, 0)) for state in _STATE_ORDER},
            "stable_state": stable_state,
            "latest_state": latest["state"],
            "latest_admin_status": latest["admin_status"],
            "latest_oper_status": latest["oper_status"],
            "first_observed_at": samples[0]["observed_at"],
            "latest_observed_at": latest["observed_at"],
            "history": samples,
        })

    body = {
        "schema_version": "1.0",
        "lineage": dict(lineage or {}),
        "collections": collection_refs,
        "total_sample_runs": total_samples,
        "ports": ports,
    }
    result = dict(body)
    result["evidence_digest"] = sha256_bytes(canonical_bytes(body))
    return result


def _approved_analysis(migration_root, plan):
    inputs = plan.get("inputs", {})
    analysis_id = str(inputs.get("analysis_id") or "")
    analysis_digest = str(inputs.get("analysis_digest") or "")
    _require(analysis_id and analysis_digest, "approved migration plan has no analysis lineage")
    path = Path(migration_root) / "analyses" / analysis_id / "analysis.json"
    _require(path.is_file(), "approved migration plan analysis artifact is missing")
    _require(sha256_file(path) == analysis_digest, "approved migration plan analysis digest does not match")
    analysis = read_json(path)
    _require(analysis.get("analysis_id") == analysis_id, "approved analysis ID mismatch")
    return analysis, path


def _collection_candidates(migration_root, analysis):
    evidence = analysis.get("composite_evidence") or {}
    refs = evidence.get("collections") or []
    if not refs:
        inputs = analysis.get("inputs", {})
        snapshot_id = inputs.get("snapshot_id")
        collection_digest = inputs.get("collection_digest")
        if snapshot_id and collection_digest:
            refs = [{"snapshot_id": snapshot_id, "collection_digest": collection_digest}]
    _require(refs, "approved analysis contains no discovery collection lineage")

    wanted = {str(item["snapshot_id"]): str(item["collection_digest"]) for item in refs}
    found = {}
    root = Path(migration_root) / "old-switch" / "collections"
    if root.is_dir():
        for directory in root.iterdir():
            if not directory.is_dir() or "_pending_" in directory.name:
                continue
            snapshot_path = directory / "snapshot.json"
            if not snapshot_path.is_file():
                continue
            try:
                preview = read_json(snapshot_path)
            except AnalysisError:
                continue
            snapshot_id = str(preview.get("snapshot_id") or "")
            if snapshot_id not in wanted:
                continue
            snapshot, envelope = validate_collection(directory)
            _require(
                envelope.get("collection_digest") == wanted[snapshot_id],
                "approved discovery collection digest mismatch for %s" % snapshot_id,
            )
            found[snapshot_id] = {
                "path": directory,
                "snapshot": snapshot,
                "envelope": envelope,
            }

    missing = sorted(set(wanted) - set(found))
    _require(not missing, "approved discovery collection(s) are missing: %s" % ", ".join(missing))
    return [found[str(item["snapshot_id"])] for item in refs]


def load_approved_port_state_evidence(migration_root, plan, approved_plan_digest):
    analysis, analysis_path = _approved_analysis(migration_root, plan)
    candidates = _collection_candidates(migration_root, analysis)
    return build_port_state_evidence(
        candidates,
        lineage={
            "migration_id": Path(migration_root).name,
            "approved_plan_id": plan.get("plan_id"),
            "approved_plan_digest": approved_plan_digest,
            "analysis_id": analysis.get("analysis_id"),
            "analysis_digest": sha256_file(analysis_path),
            "evidence_set_id": (analysis.get("composite_evidence") or {}).get("evidence_set_id"),
            "evidence_set_digest": (analysis.get("composite_evidence") or {}).get("evidence_set_digest"),
        },
    )


def _eligible_edge(interface, recovery_interface, uplink_interfaces=None):
    match = _EDGE.fullmatch(str(interface or ""))
    if not match:
        return False
    port = int(match.group("port"))
    excluded = {str(value) for value in (uplink_interfaces or [])}
    return 0 <= port <= 47 and interface != recovery_interface and interface not in excluded


def current_edge_states(terse_text, mac_table_text, recovery_interface, uplink_interfaces=None, observed_at=None):
    dynamic_ports = set()
    for row in parse_mac_table_text(
        mac_table_text or "",
        observed_at,
        "post-cutover-ex4400-port-state",
    ):
        if row.mac_type == "dynamic":
            dynamic_ports.add(str(row.physical_interface or ""))

    result = {}
    for interface, observed in parse_terse_states(terse_text).items():
        if not _eligible_edge(interface, recovery_interface, uplink_interfaces):
            continue
        result[interface] = {
            "interface": interface,
            "admin_status": observed["admin_status"],
            "oper_status": observed["oper_status"],
            "state": classify_port_state(
                observed["admin_status"],
                observed["oper_status"],
                interface in dynamic_ports,
            ),
        }
    return result


def build_port_state_comparison(
    migration_id,
    plan,
    approved_plan_digest,
    pre_evidence,
    terse_text,
    mac_table_text,
    recovery_interface,
    uplink_interfaces=None,
    completed=None,
    observed_at=None,
):
    pre_by_port = {item["interface"]: item for item in pre_evidence.get("ports", [])}
    current = current_edge_states(
        terse_text,
        mac_table_text,
        recovery_interface,
        uplink_interfaces=uplink_interfaces,
        observed_at=observed_at,
    )
    completed_by_old = dict((completed or {}).get("by_old", {}))
    completed_by_new = dict((completed or {}).get("by_new", {}))

    rows = []
    for intent in sorted(plan.get("port_intents", []), key=lambda item: str(item.get("old_interface") or "")):
        old_interface = str(intent.get("old_interface") or "")
        pre = pre_by_port.get(old_interface)
        mapping_source = None
        candidate = None
        reason = None

        if old_interface in completed_by_old:
            candidate = str(completed_by_old[old_interface].get("new_interface") or "")
            mapping_source = "CONFIRMED_ENDPOINT_TRANSACTION"
        elif _eligible_edge(old_interface, recovery_interface, uplink_interfaces):
            claimed = completed_by_new.get(old_interface)
            if claimed and claimed != old_interface:
                reason = "SAME_POSITION_ALREADY_CLAIMED_BY_CONFIRMED_MAPPING"
            elif old_interface in current:
                candidate = old_interface
                mapping_source = "SAME_PHYSICAL_POSITION_ADVISORY"
            else:
                reason = "SAME_POSITION_NOT_PRESENT_ON_EX4400"
        else:
            reason = "SAME_POSITION_NOT_ELIGIBLE_ON_EX4400"

        current_row = current.get(candidate) if candidate else None
        pre_state = pre.get("latest_state") if pre else None
        current_state = current_row.get("state") if current_row else None
        state_match = (pre_state == current_state) if pre_state and current_state else None

        if mapping_source == "CONFIRMED_ENDPOINT_TRANSACTION":
            confidence = "CONFIRMED_MAPPING"
        elif mapping_source == "SAME_PHYSICAL_POSITION_ADVISORY" and state_match is True:
            confidence = (
                "CORROBORATING_STATE_MATCH"
                if pre and pre.get("stable_state") == pre_state
                else "ADVISORY_STATE_MATCH"
            )
        elif mapping_source == "SAME_PHYSICAL_POSITION_ADVISORY" and state_match is False:
            confidence = "ADVISORY_STATE_MISMATCH"
        else:
            confidence = "UNRESOLVED"

        rows.append({
            "old_interface": old_interface,
            "description": intent.get("description"),
            "planned_action": intent.get("planned_action"),
            "configured_data_vlan_id": intent.get("configured_data_vlan_id"),
            "pre_migration": None if pre is None else {
                "samples": pre["samples"],
                "counts": pre["counts"],
                "stable_state": pre["stable_state"],
                "latest_state": pre["latest_state"],
                "latest_admin_status": pre["latest_admin_status"],
                "latest_oper_status": pre["latest_oper_status"],
                "latest_observed_at": pre["latest_observed_at"],
            },
            "candidate_new_interface": candidate,
            "mapping_source": mapping_source,
            "candidate_reason": reason,
            "post_migration": current_row,
            "state_match": state_match,
            "confidence": confidence,
            "authorization": "ADVISORY_ONLY" if mapping_source == "SAME_PHYSICAL_POSITION_ADVISORY" else "AUDIT_ONLY",
        })

    advisory = [row for row in rows if row["mapping_source"] == "SAME_PHYSICAL_POSITION_ADVISORY"]
    pre_latest = Counter(
        row["pre_migration"]["latest_state"]
        for row in rows
        if row.get("pre_migration")
    )
    body = {
        "schema_version": "1.0",
        "migration_id": migration_id,
        "approved_plan_id": plan.get("plan_id"),
        "approved_plan_digest": approved_plan_digest,
        "pre_migration_evidence_digest": pre_evidence.get("evidence_digest"),
        "observed_at": observed_at,
        "current_observation": {
            "interfaces_terse_sha256": sha256_bytes(str(terse_text or "").encode("utf-8")),
            "mac_table_sha256": sha256_bytes(str(mac_table_text or "").encode("utf-8")),
        },
        "rows": rows,
        "statistics": {
            "ports": len(rows),
            "confirmed_mappings": sum(1 for row in rows if row["mapping_source"] == "CONFIRMED_ENDPOINT_TRANSACTION"),
            "same_position_advisories": len(advisory),
            "same_position_state_matches": sum(1 for row in advisory if row["state_match"] is True),
            "same_position_state_mismatches": sum(1 for row in advisory if row["state_match"] is False),
            "unresolved_candidates": sum(1 for row in rows if not row["candidate_new_interface"]),
            "pre_latest_state_counts": {state: int(pre_latest.get(state, 0)) for state in _STATE_ORDER},
        },
    }
    result = dict(body)
    result["comparison_id"] = sha256_bytes(canonical_bytes(body))[:16]
    return result


def render_port_state_markdown(comparison):
    stats = comparison["statistics"]
    lines = [
        "# Port State Comparison",
        "",
        "Migration: `%s`" % comparison["migration_id"],
        "",
        "- Confirmed endpoint mappings: %d" % stats["confirmed_mappings"],
        "- Same-position advisory candidates: %d" % stats["same_position_advisories"],
        "- Same-position state matches: %d" % stats["same_position_state_matches"],
        "- Same-position state mismatches: %d" % stats["same_position_state_mismatches"],
        "- Unresolved candidates: %d" % stats["unresolved_candidates"],
        "",
        "State-only same-position matches are advisory evidence and never authorize VLAN assignment.",
        "",
        "| Old port | Pre state | New candidate | Post state | Mapping basis | Match | Confidence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in comparison["rows"]:
        pre = (row.get("pre_migration") or {}).get("latest_state") or ""
        post = (row.get("post_migration") or {}).get("state") or ""
        match = "yes" if row.get("state_match") is True else "no" if row.get("state_match") is False else ""
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %s |"
            % (
                row["old_interface"],
                pre,
                row.get("candidate_new_interface") or "",
                post,
                row.get("mapping_source") or row.get("candidate_reason") or "",
                match,
                row["confidence"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def write_port_state_comparison(migration_root, comparison, terse_text, mac_table_text):
    destination = Path(migration_root) / "port-state-comparisons" / comparison["comparison_id"]
    record = destination / "comparison.json"
    markdown = destination / "report.md"
    terse = destination / "ex4400-interfaces-terse.txt"
    mac = destination / "ex4400-mac-table.txt"
    rendered = render_port_state_markdown(comparison)

    if record.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("comparison.json") == sha256_file(record), "port-state comparison integrity failed")
        _require(integrity.get("report.md") == sha256_file(markdown), "port-state report integrity failed")
        _require(integrity.get("ex4400-interfaces-terse.txt") == sha256_file(terse), "port-state terse evidence integrity failed")
        _require(integrity.get("ex4400-mac-table.txt") == sha256_file(mac), "port-state MAC evidence integrity failed")
        _require(read_json(record) == comparison, "existing port-state comparison ID has different content")
        return destination, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(record, comparison)
    markdown.write_text(rendered, encoding="utf-8")
    terse.write_text(str(terse_text or ""), encoding="utf-8")
    mac.write_text(str(mac_table_text or ""), encoding="utf-8")
    atomic_json(destination / "integrity.json", {
        "comparison.json": sha256_file(record),
        "report.md": sha256_file(markdown),
        "ex4400-interfaces-terse.txt": sha256_file(terse),
        "ex4400-mac-table.txt": sha256_file(mac),
    })
    return destination, "CREATED"
