from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .core import AnalysisError, analyze, atomic_json, canonical_bytes, evaluate_policy, read_json, render_report, sha256_bytes, sha256_file, utc_now, validate_collection


def load_settings(path):
    defaults = {"snapshot_root": "snapshots", "analysis_policy": "policies/production-old-v1.json"}
    if path.is_file(): defaults.update(read_json(path))
    local_path = path.with_name("site.local.json")
    if local_path.is_file(): defaults.update(read_json(local_path))
    if os.environ.get("EX_MIGRATION_ANALYSIS_POLICY"):
        defaults["analysis_policy"] = os.environ["EX_MIGRATION_ANALYSIS_POLICY"]
    return defaults


def collection_directories(root, migration_id):
    path = root / "migrations" / migration_id / "old-switch" / "collections"
    return sorted((item for item in path.iterdir() if item.is_dir()), reverse=True) if path.is_dir() else []


def readable_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%b %-d, %Y %H:%M UTC")
    except (AttributeError, TypeError, ValueError):
        return value or "unknown"


def inspect_candidates(directories, policy, policy_digest):
    complete, incomplete, rejected = [], [], []
    for directory in directories:
        if "_pending_" in directory.name or not (directory / "snapshot.json").is_file():
            incomplete.append(directory); continue
        try:
            snapshot, envelope = validate_collection(directory)
            preview = analyze(snapshot, envelope, policy, policy_digest, "PREVIEW", __version__)
            blockers, _reviews = evaluate_policy(snapshot, policy)
            complete.append({"path": directory, "snapshot": snapshot, "envelope": envelope, "preview": preview, "blockers": blockers})
        except AnalysisError as exc:
            rejected.append((directory, str(exc)))
    return complete, incomplete, rejected


def prepare_history(candidates):
    """Attach deterministic all-candidate coverage without changing any snapshot."""
    eligible = [candidate for candidate in candidates if not candidate["blockers"]]
    catalog = {}
    for candidate in eligible:
        snapshot_id = candidate["snapshot"]["snapshot_id"]
        for mac, vlan, port in endpoint_observations(candidate):
            key = (mac, vlan, port)
            catalog.setdefault(key, []).append(snapshot_id)
    catalog_rows = [
        {"mac": key[0], "vlan_id": int(key[1]), "interface": key[2], "snapshot_ids": sorted(set(snapshot_ids))}
        for key, snapshot_ids in sorted(catalog.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
    ]
    history = {
        "catalog": catalog_rows,
        "catalog_digest": sha256_bytes(canonical_bytes(catalog_rows)),
        "supporting_snapshots": sorted(
            ({"snapshot_id": item["snapshot"]["snapshot_id"], "collection_digest": item["envelope"]["collection_digest"]} for item in eligible),
            key=lambda item: item["snapshot_id"],
        ),
    }
    all_identities = {(mac, port) for mac, _vlan, port in catalog}
    for candidate in candidates:
        observed = endpoint_observations(candidate)
        observed_identities = {(mac, port) for mac, _vlan, port in observed}
        missing = all_identities - observed_identities
        candidate["historical_coverage"] = len(observed_identities & all_identities)
        candidate["historical_total"] = len(all_identities)
        candidate["historically_missing"] = sorted(
            ((mac, ",".join(sorted(vlan for item_mac, vlan, item_port in catalog if (item_mac, item_port) == (mac, port))), port) for mac, port in missing),
            key=lambda item: (item[2], item[0], item[1]),
        )
        candidate["history"] = history
    return history


def candidate_rank(candidate):
    snapshot = candidate["snapshot"]; policy = snapshot.get("collection_policy", {})
    review_count = sum(1 for finding in candidate["preview"]["findings"] if finding["severity"] == "REVIEW")
    return (not bool(candidate["blockers"]), candidate.get("historical_coverage", 0), -len(candidate.get("historically_missing", [])), int(policy.get("duration_seconds", 0)), int(policy.get("samples", 0)), -review_count, snapshot.get("completed_at", ""))


def show_candidate(index, candidate, recommended, policy_id):
    snapshot = candidate["snapshot"]; preview = candidate["preview"]; collection_policy = snapshot.get("collection_policy", {})
    endpoint_ports = sum(1 for port in preview["ports"] if port["unique_macs"])
    successful = sum(1 for run in snapshot.get("sample_runs", []) if all(entry.get("status") == "SUCCESS" for entry in run.get("commands", [])))
    marker = " (recommended)" if recommended else ""
    print("  [%d] %s%s" % (index, readable_time(snapshot.get("started_at")), marker))
    print("      Host: %s" % (snapshot.get("device", {}).get("hostname") or "unknown"))
    print("      Snapshot: %s | %ss | %s/%s successful samples" % (snapshot.get("snapshot_id"), collection_policy.get("duration_seconds", 0), successful, collection_policy.get("samples", 0)))
    print("      Endpoints: %s unique MACs on %s access ports | Findings: %s" % (preview["statistics"]["unique_endpoint_macs"], endpoint_ports, len(preview["findings"])))
    print("      Historical coverage: %s/%s | Missing known observations: %s" % (candidate.get("historical_coverage", 0), candidate.get("historical_total", 0), len(candidate.get("historically_missing", []))))
    for mac, vlan, port in candidate.get("historically_missing", []):
        print("        Missing: %s %s VLAN %s" % (port, mac, vlan))
    print("      Policy %s: %s" % (policy_id, "ELIGIBLE" if not candidate["blockers"] else "NOT ELIGIBLE"))
    if candidate["blockers"]: print("      Blockers: %s" % "; ".join(code for code, _message in candidate["blockers"]))


def choose_candidate(candidates, incomplete, rejected, policy, interactive):
    if incomplete:
        print("Incomplete collections ignored: %d" % len(incomplete))
        for path in incomplete: print("  - %s" % path.name)
        print()
    if rejected:
        print("Corrupt or unreadable collections rejected: %d" % len(rejected))
        for path, error in rejected: print("  - %s: %s" % (path.name, error))
        print()
    if not candidates: raise AnalysisError("no complete, integrity-valid old-switch collections were found")
    prepare_history(candidates)
    ranked = sorted(candidates, key=candidate_rank, reverse=True)
    eligible = [candidate for candidate in ranked if not candidate["blockers"]]
    if not eligible:
        print("Completed snapshots:")
        for index, candidate in enumerate(ranked, 1): show_candidate(index, candidate, False, policy["policy_id"])
        raise AnalysisError("no snapshot is approvable under %s" % policy["policy_id"])
    recommended = eligible[0]
    print("Completed snapshots:")
    for index, candidate in enumerate(ranked, 1): show_candidate(index, candidate, candidate is recommended, policy["policy_id"])
    if len(eligible) == 1:
        print("\nOnly one eligible snapshot; selecting it automatically."); return recommended, False
    if not interactive: return recommended, False
    default_index = ranked.index(recommended) + 1
    answer = input("\nSelect baseline [%d]: " % default_index).strip() or str(default_index)
    try: selected = ranked[int(answer) - 1]
    except (ValueError, IndexError): raise AnalysisError("invalid snapshot selection")
    if selected["blockers"]: raise AnalysisError("selected snapshot is not eligible under %s" % policy["policy_id"])
    return selected, selected is not recommended


def show_analysis_summary(candidate):
    snapshot = candidate["snapshot"]; preview = candidate["preview"]; policy = snapshot["collection_policy"]
    print("\n%s baseline analysis" % ("Selected" if candidate.get("operator_override") else "Recommended"))
    print("  Collected: %s through %s" % (readable_time(snapshot["started_at"]), readable_time(snapshot["completed_at"])))
    print("  Snapshot: %s" % snapshot["snapshot_id"])
    print("  Observation: %s seconds / %s samples" % (policy.get("duration_seconds"), policy.get("samples")))
    print("  Unique endpoint MACs: %s" % preview["statistics"]["unique_endpoint_macs"])
    print("  Excluded infrastructure observations: %s" % preview["statistics"]["excluded_observations"])
    print("  Result: %s" % preview["result"]); print("  Findings:")
    if preview["findings"]:
        for finding in preview["findings"]: print("    - %s [%s]: %s" % (finding["subject"], finding["code"], finding["message"]))
    else: print("    - None")


def endpoint_observations(candidate):
    """Return stable (MAC, VLAN, port) tuples used by the analysis preview."""
    access_ports = {port.get("interface") for port in candidate["preview"].get("ports", [])}
    observations = set()
    for item in candidate["snapshot"].get("mac_observations", []):
        interface = item.get("physical_interface")
        mac = item.get("mac")
        vlan = item.get("vlan", {}).get("vlan_id")
        if interface in access_ports and mac and vlan is not None:
            observations.add((mac, str(vlan), interface))
    return observations


def find_approval(migration_root, candidate, policy_digest):
    approvals = migration_root / "old-switch" / "approvals"
    preview_digest = sha256_bytes(canonical_bytes(candidate["preview"]))
    if approvals.is_dir():
        for path in sorted(approvals.glob("*/approval.json")):
            value = read_json(path)
            if value.get("collection_digest") == candidate["envelope"]["collection_digest"] and value.get("policy_digest") == policy_digest and value.get("analysis_preview_digest") == preview_digest and value.get("historical_evidence_catalog_digest") == candidate["history"]["catalog_digest"] and value.get("supporting_snapshots") == candidate["history"]["supporting_snapshots"]: return value, path
    return None, None


def approve(migration_root, candidate, policy, policy_digest, interactive, override_reason=None):
    existing, path = find_approval(migration_root, candidate, policy_digest)
    if existing: return existing, sha256_file(path), False
    if not interactive: raise AnalysisError("no matching approval exists; interactive approval is required")
    print("\nCollection digest: sha256:%s" % candidate["envelope"]["collection_digest"])
    if input("Use this snapshot and analysis as the approved old-switch baseline? [y/N]: ").strip().lower() not in ("y", "yes"): raise AnalysisError("baseline was not approved")
    approval = {
        "schema_version": "1.1", "migration_id": candidate["snapshot"]["migration_id"], "snapshot_id": candidate["snapshot"]["snapshot_id"],
        "snapshot_schema_version": candidate["snapshot"]["schema_version"], "snapshot_sha256": candidate["envelope"]["snapshot_sha256"],
        "collection_digest": candidate["envelope"]["collection_digest"], "analysis_preview_digest": sha256_bytes(canonical_bytes(candidate["preview"])),
        "historical_evidence_catalog_digest": candidate["history"]["catalog_digest"], "supporting_snapshots": candidate["history"]["supporting_snapshots"],
        "policy_id": policy["policy_id"], "policy_digest": policy_digest, "approved_by": getpass.getuser(), "approved_at": utc_now(),
        "reason": override_reason or "Selected recommended analyzer baseline", "waivers": [],
    }
    approval["approval_id"] = sha256_bytes(canonical_bytes(approval))[:16]
    path = migration_root / "old-switch" / "approvals" / approval["approval_id"] / "approval.json"
    atomic_json(path, approval); return approval, sha256_file(path), True


def write_analysis(migration_root, analysis):
    destination = migration_root / "analyses" / analysis["analysis_id"]; output = destination / "analysis.json"
    if output.is_file():
        if read_json(output) != analysis: raise AnalysisError("existing analysis ID has different content")
        integrity = read_json(destination / "integrity.json")
        if sha256_file(output) != integrity.get("analysis.json") or sha256_file(destination / "report.md") != integrity.get("report.md"): raise AnalysisError("existing analysis output failed integrity validation")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False); atomic_json(output, analysis)
    (destination / "report.md").write_text(render_report(analysis), encoding="utf-8")
    atomic_json(destination / "integrity.json", {"analysis.json": sha256_file(output), "report.md": sha256_file(destination / "report.md")})
    return destination, "CREATED"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline EX migration analyzer"); parser.add_argument("command", choices=("run",)); parser.add_argument("migration_id", nargs="?")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json")); parser.add_argument("--policy", type=Path); parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args(argv); interactive = not args.non_interactive
    migration_id = args.migration_id or (input("Migration ID: ").strip() if interactive else "")
    if not safe_id(migration_id): parser.error("a path-safe migration ID is required")
    try:
        settings = load_settings(args.settings); root = Path(settings["snapshot_root"]); policy_path = args.policy or Path(settings["analysis_policy"])
        policy = read_json(policy_path); policy_digest = sha256_bytes(canonical_bytes(policy)); migration_root = root / "migrations" / migration_id
        candidates, incomplete, rejected = inspect_candidates(collection_directories(root, migration_id), policy, policy_digest)
        candidate, overridden = choose_candidate(candidates, incomplete, rejected, policy, interactive)
        if candidate["snapshot"]["migration_id"] != migration_id: raise AnalysisError("selected snapshot migration ID does not match requested migration")
        candidate["operator_override"] = overridden; show_analysis_summary(candidate); override_reason = None
        if overridden:
            override_reason = input("Reason for choosing a non-recommended snapshot: ").strip()
            if not override_reason: raise AnalysisError("an override reason is required")
        _approval, approval_digest, created = approve(migration_root, candidate, policy, policy_digest, interactive, override_reason)
        result = analyze(candidate["snapshot"], candidate["envelope"], policy, policy_digest, approval_digest, __version__, candidate["history"])
        destination, action = write_analysis(migration_root, result)
        print("\nApproval: %s" % ("CREATED" if created else "EXISTING")); print("Analysis: %s (%s)" % (result["result"], action)); print("Report: %s" % (destination / "report.md")); return 0
    except AnalysisError as exc:
        print("ERROR: %s" % exc, file=sys.stderr); return 2


def safe_id(value):
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value or ""))


if __name__ == "__main__": sys.exit(main())
