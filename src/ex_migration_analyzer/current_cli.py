from __future__ import annotations

"""Current analyzer entry point with operator-friendly silent-port review semantics.

Historical endpoint evidence is evidence, not an operator exception.  A configured
port that is silent in the current composite but has a prior approved MAC history
is therefore accepted automatically.  Configured/up ports that have never been
observed still require an operator disposition, but are reviewed as one group so
the operator does not have to enter the same decision/note for every port.
"""

import getpass
import sys

from . import cli as legacy
from .core import AnalysisError, atomic_json, canonical_bytes, sha256_bytes, sha256_file, utc_now


def _decision(finding, disposition, note=None):
    return {
        "finding_digest": sha256_bytes(canonical_bytes(finding)),
        "severity": finding["severity"],
        "code": finding["code"],
        "subject": finding["subject"],
        "disposition": disposition,
        "note": note or None,
    }


def _port(analysis, subject):
    return next(
        (item for item in analysis.get("ports", []) if item.get("interface") == subject),
        None,
    )


def _historically_observed(finding, analysis):
    if finding.get("code") != "CONFIGURED_NO_MAC":
        return False
    port = _port(analysis, finding.get("subject"))
    return bool(port and port.get("observation_history") == "HISTORICALLY_OBSERVED")


def _grouped_silent(finding, analysis):
    if finding.get("code") not in ("CONFIGURED_NO_MAC", "ACTIVE_UNASSIGNED_SILENT"):
        return False
    return not _historically_observed(finding, analysis)


def review_findings(destination, analysis, policy, policy_digest, interactive):
    findings = [item for item in analysis["findings"] if item["severity"] == "REVIEW"]
    if not findings:
        return None, "NOT_REQUIRED"

    analysis_path = destination / "analysis.json"
    analysis_digest = sha256_file(analysis_path)
    findings_digest = sha256_bytes(canonical_bytes(findings))
    existing, _path = legacy.find_existing_review(
        destination, analysis_digest, findings_digest, policy_digest
    )
    if existing:
        return existing, "EXISTING"
    if not interactive:
        raise AnalysisError("review-required findings have no matching disposition record")

    print("\nFinding review")
    decisions = []

    historical = [item for item in findings if _historically_observed(item, analysis)]
    if historical:
        print(
            "  Historical endpoint evidence automatically resolves %d configured/silent port%s:"
            % (len(historical), "" if len(historical) == 1 else "s")
        )
        for finding in historical:
            print("    - %s" % finding["subject"])
            decisions.append(_decision(finding, "ACCEPT_HISTORICAL_EVIDENCE"))

    silent = [item for item in findings if _grouped_silent(item, analysis)]
    if silent:
        print(
            "\n  Configured/silent ports with no historical MAC evidence: %d"
            % len(silent)
        )
        for finding in silent:
            print("    - %s [%s]" % (finding["subject"], finding["code"]))
        choices = ["REQUIRES_INVESTIGATION", "ACTIVE_PROBE_REQUESTED", "BLOCKED"]
        for number, choice in enumerate(choices, 1):
            marker = " (recommended)" if number == 1 else ""
            print("        %d. %s%s" % (number, choice, marker))
        answer = input("      Disposition for all listed silent ports [1]: ").strip() or "1"
        try:
            disposition = choices[int(answer) - 1]
        except (ValueError, IndexError):
            raise AnalysisError("invalid finding disposition")
        note = ""
        if disposition in ("REQUIRES_INVESTIGATION", "BLOCKED"):
            note = input("      Note for this silent-port group: ").strip()
            if not note:
                raise AnalysisError("a note is required for %s" % disposition)
        for finding in silent:
            decisions.append(_decision(finding, disposition, note))

    handled = {id(item) for item in historical + silent}
    remaining = [item for item in findings if id(item) not in handled]
    for index, finding in enumerate(remaining, 1):
        choices = legacy.finding_choices(finding, analysis, policy)
        print(
            "\n  [%d/%d] %s [%s]: %s"
            % (index, len(remaining), finding["subject"], finding["code"], finding["message"])
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
        decisions.append(_decision(finding, disposition, note))

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
    legacy.review_findings = review_findings
    return legacy.main(argv)


if __name__ == "__main__":
    sys.exit(main())
