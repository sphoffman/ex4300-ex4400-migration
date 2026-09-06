from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import __version__
from .core import (
    AnalysisError, analyze, atomic_json, canonical_bytes, read_json, render_report,
    evaluate_policy, sha256_bytes, sha256_file, utc_now, validate_collection,
)


def load_settings(path):
    defaults = {
        "snapshot_root": "snapshots",
        "analysis_policy": "policies/production-old-v1.json",
    }
    if path.is_file():
        defaults.update(read_json(path))
    return defaults


def collections_for(root, migration_id):
    path = root / "migrations" / migration_id / "old-switch" / "collections"
    return sorted((item for item in path.iterdir() if item.is_dir()), reverse=True) if path.is_dir() else []


def select_collection(candidates, policy, interactive):
    inspected = []
    for candidate in candidates:
        try:
            snapshot, envelope = validate_collection(candidate)
            inspected.append((candidate, snapshot, envelope, None))
        except AnalysisError as exc:
            inspected.append((candidate, None, None, str(exc)))
    valid = [item for item in inspected if item[1] is not None]
    if not valid:
        raise AnalysisError("no integrity-valid old-switch collections were found")
    if not interactive:
        if len(valid) != 1:
            raise AnalysisError("non-interactive selection requires exactly one valid collection")
        return valid[0][:3]
    print("Available integrity-valid snapshots:")
    for index, (path, snapshot, _envelope, _error) in enumerate(valid, 1):
        cp = snapshot["collection_policy"]
        print("  [%d] %s  samples=%s duration=%ss schema=%s" % (
            index, path.name, cp.get("samples"), cp.get("duration_seconds"), snapshot["schema_version"],
        ))
    answer = input("Select snapshot [1]: ").strip() or "1"
    try:
        return valid[int(answer) - 1][:3]
    except (ValueError, IndexError):
        raise AnalysisError("invalid snapshot selection")


def approval_for(migration_root, snapshot, envelope, policy, policy_digest, interactive, operator, reason):
    approvals = migration_root / "old-switch" / "approvals"
    if approvals.is_dir():
        for path in sorted(approvals.glob("*/approval.json")):
            value = read_json(path)
            if value.get("collection_digest") == envelope["collection_digest"] and value.get("policy_digest") == policy_digest:
                return value, sha256_file(path), False
    if not interactive:
        raise AnalysisError("no matching approval exists; interactive approval is required")
    print("Collection digest: sha256:%s" % envelope["collection_digest"])
    if input("Approve this snapshot as the old-switch migration baseline? [y/N]: ").strip().lower() not in ("y", "yes"):
        raise AnalysisError("snapshot was not approved")
    operator = operator or input("Operator [%s]: " % getpass.getuser()).strip() or getpass.getuser()
    reason = reason or input("Reason [Approved migration baseline]: ").strip() or "Approved migration baseline"
    approval = {
        "schema_version": "1.0", "migration_id": snapshot["migration_id"],
        "snapshot_id": snapshot["snapshot_id"], "snapshot_schema_version": snapshot["schema_version"],
        "snapshot_sha256": envelope["snapshot_sha256"], "collection_digest": envelope["collection_digest"],
        "policy_id": policy["policy_id"], "policy_digest": policy_digest,
        "approved_by": operator, "approved_at": utc_now(), "reason": reason, "waivers": [],
    }
    approval["approval_id"] = sha256_bytes(canonical_bytes(approval))[:16]
    path = approvals / approval["approval_id"] / "approval.json"
    atomic_json(path, approval)
    return approval, sha256_file(path), True


def write_analysis(migration_root, analysis):
    destination = migration_root / "analyses" / analysis["analysis_id"]
    output = destination / "analysis.json"
    if output.is_file():
        existing = read_json(output)
        if existing != analysis:
            raise AnalysisError("existing analysis ID has different content")
        integrity = read_json(destination / "integrity.json")
        if sha256_file(output) != integrity.get("analysis.json") or sha256_file(destination / "report.md") != integrity.get("report.md"):
            raise AnalysisError("existing analysis output failed integrity validation")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(output, analysis)
    (destination / "report.md").write_text(render_report(analysis), encoding="utf-8")
    atomic_json(destination / "integrity.json", {
        "analysis.json": sha256_file(output), "report.md": sha256_file(destination / "report.md"),
    })
    return destination, "CREATED"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline EX migration analyzer")
    parser.add_argument("command", choices=("run",))
    parser.add_argument("migration_id", nargs="?")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--operator")
    parser.add_argument("--reason")
    args = parser.parse_args(argv)
    interactive = not args.non_interactive
    migration_id = args.migration_id or (input("Migration ID: ").strip() if interactive else "")
    if not re_safe_id(migration_id):
        parser.error("a path-safe migration ID is required")
    try:
        settings = load_settings(args.settings)
        root = Path(settings["snapshot_root"])
        policy_path = args.policy or Path(settings["analysis_policy"])
        policy = read_json(policy_path)
        policy_digest = sha256_bytes(canonical_bytes(policy))
        migration_root = root / "migrations" / migration_id
        _path, snapshot, envelope = select_collection(collections_for(root, migration_id), policy, interactive)
        if snapshot["migration_id"] != migration_id:
            raise AnalysisError("selected snapshot migration ID does not match requested migration")
        blockers, _reviews = evaluate_policy(snapshot, policy)
        if blockers:
            detail = "; ".join("%s: %s" % item for item in blockers)
            raise AnalysisError("selected snapshot is not approvable under %s: %s" % (policy["policy_id"], detail))
        _approval, approval_digest, created = approval_for(
            migration_root, snapshot, envelope, policy, policy_digest,
            interactive, args.operator, args.reason,
        )
        result = analyze(snapshot, envelope, policy, policy_digest, approval_digest, __version__)
        destination, action = write_analysis(migration_root, result)
        print("Approval: %s" % ("CREATED" if created else "EXISTING"))
        print("Analysis: %s (%s)" % (result["result"], action))
        print("Report: %s" % (destination / "report.md"))
        return 0
    except AnalysisError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


def re_safe_id(value):
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value or ""))


if __name__ == "__main__":
    sys.exit(main())
