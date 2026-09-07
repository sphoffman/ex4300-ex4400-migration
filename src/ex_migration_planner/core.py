from __future__ import annotations

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes


class PlanError(RuntimeError):
    pass


def build_plan(analysis, analysis_digest, review, review_digest, planner_version):
    if analysis.get("result") == "BLOCKED":
        raise PlanError("blocked analysis cannot produce a migration plan")
    review_findings = [item for item in analysis.get("findings", []) if item.get("severity") == "REVIEW"]
    if review_findings and (not review or review.get("result") != "ACCEPTED"):
        raise PlanError("all review-required findings must have an accepted digest-bound review")
    if review and review.get("analysis_digest") != analysis_digest:
        raise PlanError("finding review is not bound to this analysis digest")
    if review and review.get("analysis_id") not in (None, analysis.get("analysis_id")):
        raise PlanError("finding review analysis ID does not match")

    variables = analysis["template_variables"]
    migration_id = variables["migration_id"]
    production_eligible = bool(review.get("production_eligible")) if review else bool(analysis.get("inputs", {}).get("policy_production_eligible", False)) and analysis.get("result") == "READY"
    reasons = [] if production_eligible else ["input evidence is not proven production eligible"]
    vlans = []
    management_vlan = variables.get("management_vlan_id")
    for vlan in variables.get("configured_vlans", []):
        vlans.append({
            "name": vlan["name"], "vlan_id": vlan.get("vlan_id"), "classification": "TEMPLATE_VARIABLE",
            "observed": bool(vlan.get("observed") or vlan.get("observed_mac_count", 0)), "irb_interface": vlan.get("irb_interface"),
        })

    accepted_history = {
        item.get("subject") for item in (review or {}).get("decisions", [])
        if item.get("code") == "CONFIGURED_NO_MAC" and item.get("disposition") == "ACCEPT_HISTORICAL_EVIDENCE"
    }
    port_intents = []
    for port in analysis.get("ports", []):
        disposition = port["disposition"]
        if disposition == "UNUSED_ACCESS_PORT": action = "LEAVE_TEMPLATE_DEFAULT"
        elif disposition == "CONFIGURED_NO_MAC" and port["interface"] in accepted_history: action = "CORRELATE_AFTER_CABLE_MOVE"
        elif disposition in ("CONFIGURED_NO_MAC", "ACTIVE_UNASSIGNED_SILENT", "CORRELATION_BLOCKED"): action = "HOLD_FOR_OPERATOR_RESOLUTION"
        else: action = "CORRELATE_AFTER_CABLE_MOVE"
        port_intents.append({
            "old_interface": port["interface"], "new_interface": None, "description": port.get("description"),
            "configured_data_vlan_id": port.get("configured_data_vlan_id"), "observed_data_vlan_ids": port.get("observed_data_vlan_ids", []),
            "endpoint_macs": port.get("unique_macs", []), "historical_observations": port.get("historical_observations", []),
            "analysis_disposition": disposition, "planned_action": action,
            "classification": "ENDPOINT_CORRELATION" if action == "CORRELATE_AFTER_CABLE_MOVE" else "VALIDATION_ONLY",
        })

    inputs = {
        "analysis_id": analysis["analysis_id"], "analysis_digest": analysis_digest, "snapshot_id": analysis["inputs"]["snapshot_id"],
        "collection_digest": analysis["inputs"]["collection_digest"], "snapshot_approval_digest": analysis["inputs"]["approval_digest"],
        "finding_review_digest": review_digest, "analysis_policy_digest": analysis["inputs"]["policy_digest"],
    }
    key = {"inputs": inputs, "planner_version": planner_version}
    plan = {
        "schema_version": "1.0", "plan_id": sha256_bytes(canonical_bytes(key))[:16], "migration_id": migration_id,
        "planner_version": planner_version, "inputs": inputs,
        "eligibility": {"status": "PRODUCTION_ELIGIBLE" if production_eligible else "LAB_ONLY", "production_eligible": production_eligible, "reasons": reasons},
        "template_variables": variables, "vlan_intents": vlans, "port_intents": port_intents,
        "phase_intents": {
            "pre_stage": {"status": "INTENT_ONLY", "include": ["AUTHORITATIVE_EX4400_BOILERPLATE", "TEMPLATE_VARIABLES", "ALL_CONFIGURED_VLANS", "MANAGEMENT_IRB", "DEFAULT_ROUTE", "AE0_MANAGEMENT_TRANSPORT"], "exclude": ["ENDPOINT_DESCRIPTIONS", "ENDPOINT_DATA_VLAN_ASSIGNMENTS"]},
            "post_move": {"status": "INTENT_ONLY", "include": ["OBSERVE_NEW_PORT_MACS", "CORRELATE_APPROVED_ENDPOINT_HISTORY", "APPLY_UNAMBIGUOUS_ENDPOINT_INTENT"], "hold": ["SILENT_ENDPOINTS", "AMBIGUOUS_ENDPOINTS", "CONFLICTING_EVIDENCE"]},
        },
        "qfx_intent": {"status": "REQUIRES_FUTURE_SITE_POLICY", "operator_supplied_ports_allowed": False, "required_non_management_vlan_ids": sorted(v["vlan_id"] for v in vlans if v["vlan_id"] not in (None, management_vlan)), "requirements": ["DISCOVER_LOCAL_PORTS_WITH_LLDP_AND_LACP", "REQUIRE_PHYSICAL_PORT_SYMMETRY", "VERIFY_DETERMINISTIC_AE_AND_ESI", "ADD_VLANS_ONLY_AFTER_VALIDATION"]},
        "safety": {"configuration_rendering_allowed": False, "device_connections_allowed": False, "device_writes_allowed": False, "collections_mutable": False, "stale_if_any_input_digest_changes": True},
        "statistics": {"configured_vlans": len(vlans), "configured_unobserved_vlans": sum(1 for v in vlans if not v["observed"] and v["vlan_id"] != management_vlan), "access_ports": len(port_intents), "correlate_after_move": sum(1 for p in port_intents if p["planned_action"] == "CORRELATE_AFTER_CABLE_MOVE"), "template_default_ports": sum(1 for p in port_intents if p["planned_action"] == "LEAVE_TEMPLATE_DEFAULT"), "operator_holds": sum(1 for p in port_intents if p["planned_action"] == "HOLD_FOR_OPERATOR_RESOLUTION")},
    }
    return plan


def render_plan_report(plan):
    lines = ["# Migration intent plan: %s" % plan["migration_id"], "", "- Plan: `%s`" % plan["plan_id"], "- Eligibility: **%s**" % plan["eligibility"]["status"], "- Rendering/device writes: **DISABLED**", "", "## VLAN intent", "", "| VLAN | ID | Observed | IRB |", "|---|---:|---|---|"]
    for vlan in plan["vlan_intents"]:
        lines.append("| %s | %s | %s | %s |" % (vlan["name"], vlan["vlan_id"] or "", "yes" if vlan["observed"] else "no", vlan["irb_interface"] or ""))
    lines += ["", "## Endpoint intent", "", "| Old port | VLAN | MACs | Action |", "|---|---:|---:|---|"]
    for port in plan["port_intents"]:
        lines.append("| %s | %s | %d | %s |" % (port["old_interface"], port["configured_data_vlan_id"] or "", len(port["endpoint_macs"]), port["planned_action"]))
    lines += ["", "## Safety boundary", "", "This artifact records deterministic intent only. It cannot render or apply configuration and cannot connect to devices."]
    return "\n".join(lines) + "\n"
