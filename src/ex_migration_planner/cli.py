from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from ex_migration_analyzer.cli import load_settings, readable_time, safe_id
from ex_migration_analyzer.core import AnalysisError, atomic_json, canonical_bytes, read_json, sha256_bytes, sha256_file, utc_now

from . import __version__
from .core import PlanError, build_plan, render_plan_report


def _verify_integrity(directory, required):
    integrity_path = directory / "integrity.json"
    if not integrity_path.is_file(): raise PlanError("missing integrity record: %s" % directory)
    integrity = read_json(integrity_path)
    for name in required:
        path = directory / name
        if not path.is_file() or sha256_file(path) != integrity.get(name): raise PlanError("integrity validation failed: %s" % path)


def _approval_exists(migration_root, expected_digest):
    return any(sha256_file(path) == expected_digest for path in (migration_root / "old-switch" / "approvals").glob("*/approval.json"))


def accepted_analyses(migration_root):
    candidates = []
    for analysis_path in sorted((migration_root / "analyses").glob("*/analysis.json")):
        directory = analysis_path.parent
        try:
            _verify_integrity(directory, ("analysis.json", "report.md"))
            analysis = read_json(analysis_path); analysis_digest = sha256_file(analysis_path)
            if analysis.get("template_variables", {}).get("migration_id") != migration_root.name: continue
            if not _approval_exists(migration_root, analysis.get("inputs", {}).get("approval_digest")): continue
            reviews = []
            for review_path in directory.glob("reviews/*/review.json"):
                _verify_integrity(review_path.parent, ("review.json",)); review = read_json(review_path)
                review_findings = [item for item in analysis.get("findings", []) if item.get("severity") == "REVIEW"]
                findings_digest = sha256_bytes(canonical_bytes(review_findings))
                review_matches = (
                    review.get("analysis_digest") == analysis_digest
                    and review.get("analysis_id") == analysis.get("analysis_id")
                    and review.get("findings_digest") == findings_digest
                    and review.get("policy_digest") == analysis.get("inputs", {}).get("policy_digest")
                )
                if review_matches and review.get("result") == "ACCEPTED":
                    reviews.append((review.get("reviewed_at", ""), review, review_path, sha256_file(review_path)))
            reviews.sort(reverse=True, key=lambda item: item[0]); selected = reviews[0] if reviews else None
            needs_review = any(item.get("severity") == "REVIEW" for item in analysis.get("findings", []))
            if needs_review and not selected: continue
            candidates.append({"analysis": analysis, "analysis_digest": analysis_digest, "review": selected[1] if selected else None, "review_digest": selected[3] if selected else None, "reviewed_at": selected[0] if selected else ""})
        except (AnalysisError, PlanError):
            continue
    return sorted(candidates, key=lambda item: (item["reviewed_at"], item["analysis"]["analysis_id"]), reverse=True)


def choose_analysis(candidates, interactive):
    if not candidates: raise PlanError("no integrity-valid analysis with an accepted finding review was found")
    if len(candidates) == 1: return candidates[0]
    print("Approved analyses:")
    for index, candidate in enumerate(candidates, 1):
        analysis = candidate["analysis"]; marker = " (recommended)" if index == 1 else ""
        print("  [%d] Analysis %s | snapshot %s | reviewed %s%s" % (index, analysis["analysis_id"], analysis["inputs"]["snapshot_id"], readable_time(candidate["reviewed_at"]), marker))
    if not interactive: return candidates[0]
    answer = input("Select analysis [1]: ").strip() or "1"
    try: return candidates[int(answer) - 1]
    except (ValueError, IndexError): raise PlanError("invalid analysis selection")


def write_plan(migration_root, plan):
    destination = migration_root / "plans" / plan["plan_id"]; plan_path = destination / "plan.json"
    if plan_path.is_file():
        _verify_integrity(destination, ("plan.json", "report.md"))
        if read_json(plan_path) != plan: raise PlanError("existing plan ID has different content")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False); atomic_json(plan_path, plan)
    (destination / "report.md").write_text(render_plan_report(plan), encoding="utf-8")
    atomic_json(destination / "integrity.json", {"plan.json": sha256_file(plan_path), "report.md": sha256_file(destination / "report.md")})
    return destination, "CREATED"


def approve_plan(destination, plan, interactive):
    plan_path = destination / "plan.json"; plan_digest = sha256_file(plan_path)
    for path in destination.glob("approvals/*/approval.json"):
        value = read_json(path); integrity = read_json(path.parent / "integrity.json")
        if value.get("plan_digest") == plan_digest and sha256_file(path) == integrity.get("approval.json"): return value, "EXISTING"
    if not interactive: raise PlanError("no matching plan approval exists; interactive approval is required")
    print("\nPlan summary"); print("  Plan: %s" % plan["plan_id"]); print("  Eligibility: %s" % plan["eligibility"]["status"])
    print("  VLANs: %d (%d configured but unobserved)" % (plan["statistics"]["configured_vlans"], plan["statistics"]["configured_unobserved_vlans"]))
    print("  Endpoint correlations: %d | Operator holds: %d" % (plan["statistics"]["correlate_after_move"], plan["statistics"]["operator_holds"]))
    print("  Configuration rendering and device writes: DISABLED")
    if input("Approve this offline migration intent plan? [y/N]: ").strip().lower() not in ("y", "yes"): raise PlanError("plan was not approved")
    reason = input("Reason [Approved migration intent]: ").strip() or "Approved migration intent"
    approval = {"schema_version": "1.0", "migration_id": plan["migration_id"], "plan_id": plan["plan_id"], "plan_digest": plan_digest, "input_analysis_digest": plan["inputs"]["analysis_digest"], "production_eligible": plan["eligibility"]["production_eligible"], "approved_by": getpass.getuser(), "approved_at": utc_now(), "reason": reason}
    approval["approval_id"] = sha256_bytes(canonical_bytes(approval)); approval["approval_id"] = approval["approval_id"][:16]
    path = destination / "approvals" / approval["approval_id"] / "approval.json"; atomic_json(path, approval)
    atomic_json(path.parent / "integrity.json", {"approval.json": sha256_file(path)}); return approval, "CREATED"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline EX migration intent planner"); parser.add_argument("command", choices=("build",)); parser.add_argument("migration_id", nargs="?")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json")); parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args(argv); interactive = not args.non_interactive
    migration_id = args.migration_id or (input("Migration ID: ").strip() if interactive else "")
    if not safe_id(migration_id): parser.error("a path-safe migration ID is required")
    try:
        settings = load_settings(args.settings); migration_root = Path(settings["snapshot_root"]) / "migrations" / migration_id
        candidate = choose_analysis(accepted_analyses(migration_root), interactive)
        plan = build_plan(candidate["analysis"], candidate["analysis_digest"], candidate["review"], candidate["review_digest"], __version__)
        destination, action = write_plan(migration_root, plan); _approval, approval_action = approve_plan(destination, plan, interactive)
        print("\nPlan: %s (%s)" % (plan["plan_id"], action)); print("Plan approval: %s" % approval_action)
        print("Eligibility: %s" % plan["eligibility"]["status"]); print("Report: %s" % (destination / "report.md")); return 0
    except (AnalysisError, PlanError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr); return 2


if __name__ == "__main__": sys.exit(main())
