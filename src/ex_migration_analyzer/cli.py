from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .composite import build_composite_evidence
from .core import (
    AnalysisError,
    analyze,
    atomic_json,
    canonical_bytes,
    evaluate_policy,
    read_json,
    render_report,
    sha256_bytes,
    sha256_file,
    utc_now,
    validate_collection,
)


_DISPLAY_TIMEZONE = "America/New_York"


def load_settings(path):
    defaults = {
        "snapshot_root": "snapshots",
        "analysis_policy": "policies/production-old-v1.json",
        "display_timezone": "America/New_York",
    }
    if path.is_file():
        defaults.update(read_json(path))
    local_path = path.with_name("site.local.json")
    if local_path.is_file():
        defaults.update(read_json(local_path))
    if os.environ.get("EX_MIGRATION_ANALYSIS_POLICY"):
        defaults["analysis_policy"] = os.environ["EX_MIGRATION_ANALYSIS_POLICY"]
    if os.environ.get("EX_MIGRATION_DISPLAY_TIMEZONE"):
        defaults["display_timezone"] = os.environ["EX_MIGRATION_DISPLAY_TIMEZONE"]
    return defaults


def set_display_timezone(value):
    global _DISPLAY_TIMEZONE
    _DISPLAY_TIMEZONE = str(value or "America/New_York")


def collection_directories(root, migration_id):
    path = root / "migrations" / migration_id / "old-switch" / "collections"
    return sorted((item for item in path.iterdir() if item.is_dir()), reverse=True) if path.is_dir() else []


def _as_local(value):
    old_tz = os.environ.get("TZ")
    try:
        os.environ["TZ"] = _DISPLAY_TIMEZONE
        if hasattr(time, "tzset"):
            time.tzset()
        return datetime.fromtimestamp(value.timestamp()).astimezone()
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        if hasattr(time, "tzset"):
            time.tzset()


def readable_time(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        local = _as_local(parsed)
        return "%s (%s UTC)" % (
            local.strftime("%b %-d, %Y %H:%M %Z"),
            parsed.strftime("%b %-d, %Y %H:%M"),
        )
    except (AttributeError, TypeError, ValueError, OSError):
        return value or "unknown"


def inspect_candidates(directories, policy, policy_digest):
    complete, incomplete, rejected = [], [], []
    for directory in directories:
        if "_pending_" in directory.name or not (directory / "snapshot.json").is_file():
            incomplete.append(directory)
            continue
        try:
            snapshot, envelope = validate_collection(directory)
            preview = analyze(snapshot, envelope, policy, policy_digest, "PREVIEW", __version__)
            blockers, _reviews = evaluate_policy(snapshot, policy)
            complete.append({
                "path": directory,
                "snapshot": snapshot,
                "envelope": envelope,
                "preview": preview,
                "blockers": blockers,
            })
        except AnalysisError as exc:
            rejected.append((directory, str(exc)))
    return complete, incomplete, rejected


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


def prepare_history(candidates):
    """Backward-compatible historical catalog helper used by tests and old artifacts."""
    eligible = [candidate for candidate in candidates if not candidate["blockers"]]
    catalog = {}
    for candidate in eligible:
        snapshot_id = candidate["snapshot"]["snapshot_id"]
        for mac, vlan, port in endpoint_observations(candidate):
            key = (mac, vlan, port)
            catalog.setdefault(key, []).append(snapshot_id)
    catalog_rows = [
        {
            "mac": key[0],
            "vlan_id": int(key[1]),
            "interface": key[2],
            "snapshot_ids": sorted(set(snapshot_ids)),
        }
        for key, snapshot_ids in sorted(catalog.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
    ]
    history = {
        "catalog": catalog_rows,
        "catalog_digest": sha256_bytes(canonical_bytes(catalog_rows)),
        "supporting_snapshots": sorted(
            (
                {
                    "snapshot_id": item["snapshot"]["snapshot_id"],
                    "collection_digest": item["envelope"]["collection_digest"],
                }
                for item in eligible
            ),
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
            (
                (
                    mac,
                    ",".join(sorted(vlan for item_mac, vlan, item_port in catalog if (item_mac, item_port) == (mac, port))),
                    port,
                )
                for mac, port in missing
            ),
            key=lambda item: (item[2], item[0], item[1]),
        )
        candidate["history"] = history
    return history


def candidate_rank(candidate):
    """Retained for compatibility; composite analysis no longer selects a baseline."""
    snapshot = candidate["snapshot"]
    policy = snapshot.get("collection_policy", {})
    review_count = sum(1 for finding in candidate["preview"]["findings"] if finding["severity"] == "REVIEW")
    return (
        not bool(candidate["blockers"]),
        candidate.get("historical_coverage", 0),
        -len(candidate.get("historically_missing", [])),
        int(policy.get("duration_seconds", 0)),
        int(policy.get("samples", 0)),
        -review_count,
        snapshot.get("completed_at", ""),
    )


def _show_collection_issues(candidates, incomplete, rejected, policy):
    ineligible = [candidate for candidate in candidates if candidate["blockers"]]
    if incomplete:
        print("Incomplete collections ignored: %d" % len(incomplete))
        for path in incomplete:
            print("  - %s" % path.name)
    if rejected:
        print("Corrupt or unreadable collections rejected: %d" % len(rejected))
        for path, error in rejected:
            print("  - %s: %s" % (path.name, error))
    if ineligible:
        print("Policy-ineligible collections excluded: %d" % len(ineligible))
        for candidate in sorted(ineligible, key=lambda item: item["snapshot"].get("completed_at", "")):
            print(
                "  - %s | %s | %s"
                % (
                    candidate["snapshot"]["snapshot_id"],
                    readable_time(candidate["snapshot"].get("started_at")),
                    ", ".join(code for code, _message in candidate["blockers"]),
                )
            )
    if incomplete or rejected or ineligible:
        print()


def _apply_composite_metadata(result, composite):
    findings = list(result.get("findings", [])) + list(composite.get("findings", []))
    result["findings"] = sorted(
        findings,
        key=lambda item: (item.get("severity", ""), item.get("code", ""), item.get("subject", "")),
    )
    if any(item.get("severity") == "BLOCKER" for item in result["findings"]):
        result["result"] = "BLOCKED"
    elif any(item.get("severity") == "REVIEW" for item in result["findings"]):
        result["result"] = "REVIEW_REQUIRED"
    else:
        result["result"] = "READY"
    evidence = composite["evidence"]
    result["inputs"].update({
        "input_kind": "COMPOSITE_EVIDENCE_SET",
        "evidence_set_id": evidence["evidence_set_id"],
        "evidence_set_digest": evidence["evidence_set_digest"],
        "supporting_snapshots": [
            {
                "snapshot_id": item["snapshot_id"],
                "collection_digest": item["collection_digest"],
            }
            for item in evidence["collections"]
        ],
    })
    result["composite_evidence"] = evidence
    for port in result.get("ports", []):
        if port.get("unique_macs"):
            port["observation_history"] = "OBSERVED_IN_EVIDENCE_SET"
    return result


def _analyze_composite(composite, policy, policy_digest, approval_digest):
    result = analyze(
        composite["snapshot"],
        composite["envelope"],
        policy,
        policy_digest,
        approval_digest,
        __version__,
        composite["history"],
    )
    return _apply_composite_metadata(result, composite)


def show_composite_summary(composite, preview):
    evidence = composite["evidence"]
    consistency = evidence["configuration_consistency"]
    endpoints = evidence["endpoint_statistics"]
    print("Discovery evidence")
    print("  Eligible collections: %d" % len(evidence["collections"]))
    print(
        "  Observation span: %s through %s"
        % (
            readable_time(evidence["observation_span"]["started_at"]),
            readable_time(evidence["observation_span"]["completed_at"]),
        )
    )
    print("  Evidence set: %s" % evidence["evidence_set_id"])
    print("  Configuration consistency:")
    print("    Device identity: %s" % consistency["device_identity"])
    print("    Management:      %s" % consistency["management"])
    print("    Interfaces:      %s" % consistency["interfaces"])
    print("    VLANs:           %s" % consistency["vlans"])
    print("    Voice policy:    %s" % consistency["voice_policy"])
    print("    Junos version:   %s" % consistency["junos_version"])
    print("  Endpoint evidence:")
    print("    Unique MACs:                 %d" % endpoints["unique_macs"])
    print("    Consistent MAC/port IDs:     %d" % endpoints["consistent_mac_port_identities"])
    print("    Historical MAC conflicts:    %d" % endpoints["conflicting_macs"])
    print("  Composite analysis: %s" % preview["result"])
    if preview.get("findings"):
        print("  Findings: %d" % len(preview["findings"]))
        for finding in preview["findings"]:
            print(
                "    - %s [%s]: %s"
                % (finding["subject"], finding["code"], finding["message"])
            )
    else:
        print("  Findings: None")


def write_evidence_set(migration_root, evidence):
    destination = migration_root / "old-switch" / "evidence-sets" / evidence["evidence_set_id"]
    output = destination / "evidence.json"
    if output.is_file():
        if read_json(output) != evidence:
            raise AnalysisError("existing evidence-set ID has different content")
        integrity = read_json(destination / "integrity.json")
        if sha256_file(output) != integrity.get("evidence.json"):
            raise AnalysisError("existing evidence set failed integrity validation")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(output, evidence)
    atomic_json(destination / "integrity.json", {"evidence.json": sha256_file(output)})
    return destination, "CREATED"


def find_approval(migration_root, evidence, preview, policy_digest):
    approvals = migration_root / "old-switch" / "approvals"
    preview_digest = sha256_bytes(canonical_bytes(preview))
    if approvals.is_dir():
        for path in sorted(approvals.glob("*/approval.json")):
            value = read_json(path)
            if (
                value.get("evidence_set_digest") == evidence["evidence_set_digest"]
                and value.get("policy_digest") == policy_digest
                and value.get("analysis_preview_digest") == preview_digest
            ):
                return value, path
    return None, None


def approve(migration_root, evidence, preview, policy, policy_digest, interactive):
    existing, path = find_approval(migration_root, evidence, preview, policy_digest)
    if existing:
        return existing, sha256_file(path), False
    if not interactive:
        raise AnalysisError("no matching composite evidence approval exists; interactive approval is required")
    print("\nEvidence-set digest: sha256:%s" % evidence["evidence_set_digest"])
    answer = input("Use this composite discovery evidence set as the approved old-switch analysis input? [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        raise AnalysisError("composite discovery evidence set was not approved")
    approval = {
        "schema_version": "1.2",
        "input_kind": "COMPOSITE_EVIDENCE_SET",
        "migration_id": evidence["migration_id"],
        "evidence_set_id": evidence["evidence_set_id"],
        "evidence_set_digest": evidence["evidence_set_digest"],
        "supporting_snapshots": [
            {
                "snapshot_id": item["snapshot_id"],
                "collection_digest": item["collection_digest"],
            }
            for item in evidence["collections"]
        ],
        "analysis_preview_digest": sha256_bytes(canonical_bytes(preview)),
        "policy_id": policy["policy_id"],
        "policy_digest": policy_digest,
        "approved_by": getpass.getuser(),
        "approved_at": utc_now(),
        "reason": "Approved composite discovery evidence set",
        "waivers": [],
    }
    approval["approval_id"] = sha256_bytes(canonical_bytes(approval))[:16]
    path = migration_root / "old-switch" / "approvals" / approval["approval_id"] / "approval.json"
    atomic_json(path, approval)
    return approval, sha256_file(path), True


def write_analysis(migration_root, analysis):
    destination = migration_root / "analyses" / analysis["analysis_id"]
    output = destination / "analysis.json"
    if output.is_file():
        if read_json(output) != analysis:
            raise AnalysisError("existing analysis ID has different content")
        integrity = read_json(destination / "integrity.json")
        if (
            sha256_file(output) != integrity.get("analysis.json")
            or sha256_file(destination / "report.md") != integrity.get("report.md")
        ):
            raise AnalysisError("existing analysis output failed integrity validation")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(output, analysis)
    (destination / "report.md").write_text(render_report(analysis), encoding="utf-8")
    atomic_json(
        destination / "integrity.json",
        {
            "analysis.json": sha256_file(output),
            "report.md": sha256_file(destination / "report.md"),
        },
    )
    return destination, "CREATED"


def finding_choices(finding, analysis, policy):
    if finding["code"] == "VIRTUAL_CHASSIS_UNSUPPORTED" and not policy.get("production_eligible", True):
        return ["ACKNOWLEDGED_LAB_LIMITATION", "REQUIRES_INVESTIGATION", "BLOCKED"]
    if finding["code"] in (
        "INTERFACE_CONFIGURATION_CHANGED",
        "VLAN_CONFIGURATION_CHANGED",
        "VOICE_POLICY_CHANGED",
        "JUNOS_VERSION_CHANGED",
    ):
        return ["ACCEPT_LATEST_CONFIGURATION", "REQUIRES_INVESTIGATION", "BLOCKED"]
    port = next(
        (item for item in analysis.get("ports", []) if item["interface"] == finding["subject"]),
        None,
    )
    if (
        finding["code"] == "CONFIGURED_NO_MAC"
        and port
        and port.get("observation_history") == "HISTORICALLY_OBSERVED"
    ):
        return ["ACCEPT_HISTORICAL_EVIDENCE", "ACTIVE_PROBE_REQUESTED", "REQUIRES_INVESTIGATION", "BLOCKED"]
    if finding["code"] in ("CONFIGURED_NO_MAC", "ACTIVE_UNASSIGNED_SILENT"):
        return ["REQUIRES_INVESTIGATION", "ACTIVE_PROBE_REQUESTED", "BLOCKED"]
    return ["REQUIRES_INVESTIGATION", "BLOCKED"]


def find_existing_review(destination, analysis_digest, findings_digest, policy_digest):
    reviews = destination / "reviews"
    if reviews.is_dir():
        for path in sorted(reviews.glob("*/review.json"), reverse=True):
            value = read_json(path)
            if (
                value.get("analysis_digest") == analysis_digest
                and value.get("findings_digest") == findings_digest
                and value.get("policy_digest") == policy_digest
            ):
                return value, path
    return None, None


def review_findings(destination, analysis, policy, policy_digest, interactive):
    findings = [item for item in analysis["findings"] if item["severity"] == "REVIEW"]
    if not findings:
        return None, "NOT_REQUIRED"
    analysis_path = destination / "analysis.json"
    analysis_digest = sha256_file(analysis_path)
    findings_digest = sha256_bytes(canonical_bytes(findings))
    existing, _path = find_existing_review(destination, analysis_digest, findings_digest, policy_digest)
    if existing:
        return existing, "EXISTING"
    if not interactive:
        raise AnalysisError("review-required findings have no matching disposition record")
    print("\nFinding review")
    decisions = []
    for index, finding in enumerate(findings, 1):
        choices = finding_choices(finding, analysis, policy)
        print(
            "  [%d/%d] %s [%s]: %s"
            % (index, len(findings), finding["subject"], finding["code"], finding["message"])
        )
        for number, choice in enumerate(choices, 1):
            marker = " (recommended)" if number == 1 else ""
            print("        %d. %s%s" % (number, choice, marker))
        answer = input("      Disposition [1]: ").strip() or "1"
        try:
            disposition = choices[int(answer) - 1]
        except (ValueError, IndexError):
            raise AnalysisError("invalid finding disposition")
        note = ""
        if disposition in ("REQUIRES_INVESTIGATION", "BLOCKED"):
            note = input("      Note: ").strip()
            if not note:
                raise AnalysisError("a note is required for %s" % disposition)
        decisions.append({
            "finding_digest": sha256_bytes(canonical_bytes(finding)),
            "severity": finding["severity"],
            "code": finding["code"],
            "subject": finding["subject"],
            "disposition": disposition,
            "note": note or None,
        })
    dispositions = {item["disposition"] for item in decisions}
    review_result = (
        "BLOCKED"
        if "BLOCKED" in dispositions
        else "ACTION_REQUIRED"
        if dispositions & {"REQUIRES_INVESTIGATION", "ACTIVE_PROBE_REQUESTED"}
        else "ACCEPTED"
    )
    review = {
        "schema_version": "1.0",
        "migration_id": analysis["template_variables"]["migration_id"],
        "analysis_id": analysis["analysis_id"],
        "analysis_digest": analysis_digest,
        "findings_digest": findings_digest,
        "historical_evidence_catalog_digest": analysis.get("historical_evidence", {}).get("catalog_digest"),
        "evidence_set_digest": analysis.get("inputs", {}).get("evidence_set_digest"),
        "policy_id": policy["policy_id"],
        "policy_digest": policy_digest,
        "decisions": decisions,
        "result": review_result,
        "production_eligible": bool(policy.get("production_eligible", True))
        and "ACKNOWLEDGED_LAB_LIMITATION" not in dispositions
        and review_result == "ACCEPTED",
        "reviewed_by": getpass.getuser(),
        "reviewed_at": utc_now(),
    }
    review["review_id"] = sha256_bytes(canonical_bytes(review))[:16]
    review_path = destination / "reviews" / review["review_id"] / "review.json"
    atomic_json(review_path, review)
    atomic_json(review_path.parent / "integrity.json", {"review.json": sha256_file(review_path)})
    return review, "CREATED"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline EX migration analyzer")
    parser.add_argument("command", choices=("run",))
    parser.add_argument("migration_id", nargs="?")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args(argv)
    interactive = not args.non_interactive
    migration_id = args.migration_id or (input("Migration ID: ").strip() if interactive else "")
    if not safe_id(migration_id):
        parser.error("a path-safe migration ID is required")
    try:
        settings = load_settings(args.settings)
        set_display_timezone(settings.get("display_timezone"))
        root = Path(settings["snapshot_root"])
        policy_path = args.policy or Path(settings["analysis_policy"])
        policy = read_json(policy_path)
        policy_digest = sha256_bytes(canonical_bytes(policy))
        migration_root = root / "migrations" / migration_id
        candidates, incomplete, rejected = inspect_candidates(
            collection_directories(root, migration_id), policy, policy_digest
        )
        _show_collection_issues(candidates, incomplete, rejected, policy)
        composite = build_composite_evidence(candidates, policy, policy_digest)
        if composite["evidence"]["migration_id"] != migration_id:
            raise AnalysisError("composite evidence migration ID does not match requested migration")
        evidence_dir, evidence_action = write_evidence_set(migration_root, composite["evidence"])
        preview = _analyze_composite(composite, policy, policy_digest, "PREVIEW")
        show_composite_summary(composite, preview)
        print("  Evidence record: %s (%s)" % (evidence_dir / "evidence.json", evidence_action))

        _approval, approval_digest, created = approve(
            migration_root,
            composite["evidence"],
            preview,
            policy,
            policy_digest,
            interactive,
        )
        result = _analyze_composite(composite, policy, policy_digest, approval_digest)
        destination, action = write_analysis(migration_root, result)
        review, review_action = review_findings(destination, result, policy, policy_digest, interactive)

        print("\nApproval: %s" % ("CREATED" if created else "EXISTING"))
        print("Analysis: %s (%s)" % (result["result"], action))
        if review:
            print(
                "Finding review: %s (%s) | production eligible: %s"
                % (review["result"], review_action, str(review["production_eligible"]).lower())
            )
            print(
                "Review record: %s"
                % (destination / "reviews" / review["review_id"] / "review.json")
            )
        else:
            print("Finding review: NOT_REQUIRED")
        print("Report: %s" % (destination / "report.md"))
        return 0
    except AnalysisError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


def safe_id(value):
    import re

    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+", value or ""))


if __name__ == "__main__":
    sys.exit(main())
