from __future__ import annotations

import re

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from .core import ProvisioningError
from .prestage import validate_pre_cutover_site_policy


_AE_PARENT = re.compile(
    r"(?m)^set interfaces (?P<physical>\S+) (?:ether-options|gigether-options) "
    r"802\.3ad (?P<ae>ae\d+)\s*$"
)
_SYSTEM_ID = re.compile(
    r"(?im)^set interfaces (?P<ae>ae\d+) aggregated-ether-options lacp "
    r"system-id (?P<value>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*$"
)
_VLAN_DEF = re.compile(
    r"(?m)^set (?:routing-instances \S+ )?vlans (?P<name>\S+) "
    r"vlan-id (?P<id>\d+)\s*$"
)
_VLAN_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<ae>ae\d+) unit 0 family ethernet-switching "
    r"vlan members (?P<value>\S+)\s*$"
)
_LACP_CONFIGURED = re.compile(
    r"(?m)^set interfaces (?P<ae>ae\d+) aggregated-ether-options lacp(?:\s|$)"
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _ae_number(name):
    match = re.fullmatch(r"ae(\d+)", str(name or ""))
    if not match:
        return None
    return int(match.group(1))


def _allowed_ports(policy):
    result = set()
    for ports in policy.get("stage_port_pools", {}).values():
        result.update(ports)
    return result


def _configured_ae(config_text, physical):
    matches = [
        match.group("ae")
        for match in _AE_PARENT.finditer(config_text or "")
        if match.group("physical") == physical
    ]
    return matches[0] if len(matches) == 1 else None


def _system_id(config_text, ae):
    matches = [
        match.group("value").lower()
        for match in _SYSTEM_ID.finditer(config_text or "")
        if match.group("ae") == ae
    ]
    return matches[0] if len(matches) == 1 else None


def _vlan_definitions(*config_texts):
    by_name = {}
    for config_text in config_texts:
        for match in _VLAN_DEF.finditer(config_text or ""):
            by_name.setdefault(match.group("name"), set()).add(int(match.group("id")))
    resolved = {
        name: next(iter(ids))
        for name, ids in by_name.items()
        if len(ids) == 1
    }
    ambiguous = {
        name: sorted(ids)
        for name, ids in by_name.items()
        if len(ids) > 1
    }
    return resolved, ambiguous


def _vlan_ids(vlan_configs, ae_config, ae):
    names, ambiguous = _vlan_definitions(*vlan_configs)
    tokens = [
        match.group("value")
        for match in _VLAN_MEMBER.finditer(ae_config or "")
        if match.group("ae") == ae
    ]
    if "all" in tokens:
        return None, ["all"], ambiguous
    ids = []
    unresolved = []
    for token in tokens:
        if token.isdigit():
            ids.append(int(token))
        elif token in ambiguous:
            unresolved.append("%s(ambiguous:%s)" % (
                token,
                ",".join(str(value) for value in ambiguous[token]),
            ))
        elif token in names:
            ids.append(names[token])
        else:
            unresolved.append(token)
    return sorted(set(ids)), sorted(set(unresolved)), ambiguous


def _lacp_operational(text, physical):
    value = text or ""
    return (
        physical in value
        and re.search(r"(?i)\bcollecting\b", value) is not None
        and re.search(r"(?i)\bdistributing\b", value) is not None
    )


def _lldp_summary_neighbors(text):
    result = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Local Interface"):
            continue
        fields = line.split(None, 4)
        if len(fields) != 5:
            continue
        local, parent, chassis_id, remote_port, system_name = fields
        result.append({
            "local_interface": local,
            "parent_interface": parent,
            "chassis_id": chassis_id,
            "remote_port_id": remote_port,
            "remote_system_name": system_name.strip(),
        })
    return result


def _target_neighbors(lldp_text, expected_hostname):
    expected = str(expected_hostname).strip().lower()
    return [
        item
        for item in _lldp_summary_neighbors(lldp_text)
        if str(item.get("remote_system_name") or "").strip().lower() == expected
    ]


def observe_qfx_attachment(dev, device_policy, policy, expected_ex_hostname, host_key):
    facts = getattr(dev, "facts", {}) or {}
    observed_hostname = str(facts.get("hostname") or "")
    observed_model = str(facts.get("model") or "")

    lldp_text = dev.cli("show lldp neighbors", warning=False) or ""
    neighbors = _target_neighbors(lldp_text, expected_ex_hostname)
    unique_neighbor = neighbors[0] if len(neighbors) == 1 else None
    physical = str(unique_neighbor.get("local_interface") or "") if unique_neighbor else ""
    lldp_parent = str(unique_neighbor.get("parent_interface") or "") if unique_neighbor else ""

    allowed = _allowed_ports(policy)
    excluded = set(policy.get("excluded_interfaces", []))
    physical_config = ""
    ae = None
    ae_config = ""
    lacp_text = ""
    top_level_vlan_config = ""
    routing_instance_vlan_config = ""
    system_id = None
    vlan_ids = None
    unresolved_vlans = []
    ambiguous_vlans = {}

    if physical:
        physical_config = dev.cli(
            "show configuration interfaces %s | display set" % physical,
            warning=False,
        ) or ""
        ae = _configured_ae(physical_config, physical)
    if ae:
        ae_config = dev.cli(
            "show configuration interfaces %s | display set" % ae,
            warning=False,
        ) or ""
        lacp_text = dev.cli(
            "show lacp interfaces %s extensive" % ae,
            warning=False,
        ) or ""
        top_level_vlan_config = dev.cli(
            "show configuration vlans | display set",
            warning=False,
        ) or ""
        routing_instance_vlan_config = dev.cli(
            'show configuration routing-instances | display set | match " vlan-id "',
            warning=False,
        ) or ""
        system_id = _system_id(ae_config, ae)
        vlan_ids, unresolved_vlans, ambiguous_vlans = _vlan_ids(
            (top_level_vlan_config, routing_instance_vlan_config),
            ae_config,
            ae,
        )

    ae_number = _ae_number(ae)
    ae_pool = policy["ae_pool"]
    required_vlans = set(policy["precutover_qfx_baseline"]["required_vlan_ids"])
    legacy_temp_id = int(policy.get("temporary_recovery_vlan", {}).get("vlan_id", 3999))
    observed_vlan_set = set(vlan_ids or [])
    baseline_ok = (
        vlan_ids is not None
        and not unresolved_vlans
        and required_vlans <= observed_vlan_set
        and (observed_vlan_set - required_vlans) <= {legacy_temp_id}
    )
    force_up_present = bool(
        ae and re.search(
            r"(?m)^set interfaces %s aggregated-ether-options lacp force-up\s*$"
            % re.escape(ae),
            ae_config,
        )
    )
    lacp_configured = bool(
        ae and any(
            match.group("ae") == ae
            for match in _LACP_CONFIGURED.finditer(ae_config)
        )
    )
    esi_auto = bool(
        ae and re.search(
            r"(?m)^set interfaces %s esi auto-derive type-1-lacp\s*$"
            % re.escape(ae),
            ae_config,
        )
    )
    esi_all_active = bool(
        ae and re.search(
            r"(?m)^set interfaces %s esi all-active\s*$" % re.escape(ae),
            ae_config,
        )
    )

    checks = {
        "qfx_hostname_matches": observed_hostname.lower()
        == str(device_policy["expected_hostname"]).lower(),
        "qfx_model_matches": observed_model.lower()
        == str(device_policy["expected_model"]).lower(),
        "exactly_one_target_lldp_neighbor": len(neighbors) == 1,
        "physical_interface_allowed": bool(physical) and physical in allowed,
        "physical_interface_not_excluded": bool(physical) and physical not in excluded,
        "physical_maps_to_one_ae": bool(ae),
        "lldp_parent_matches_configured_ae": bool(ae)
        and bool(lldp_parent)
        and lldp_parent == ae,
        "ae_in_allowed_range": ae_number is not None
        and ae_pool["ae_min"] <= ae_number <= ae_pool["ae_max"],
        "lacp_configured": lacp_configured,
        "lacp_force_up_absent": not force_up_present,
        "lacp_system_id_present": bool(system_id),
        "esi_auto_derive_type_1_lacp": esi_auto,
        "esi_all_active": esi_all_active,
        "baseline_vlan_names_unambiguous": not ambiguous_vlans,
        # The permanent management VLAN is required. A legacy 3999 observed
        # from earlier lab runs is tolerated but has no active write semantics.
        "baseline_vlans_exact": baseline_ok,
        "lacp_collecting_distributing": bool(ae)
        and _lacp_operational(lacp_text, physical),
    }

    return {
        "role": device_policy["role"],
        "management_address": device_policy["management_address"],
        "ssh_host_key_sha256": host_key,
        "expected_qfx_hostname": device_policy["expected_hostname"],
        "expected_qfx_model": device_policy["expected_model"],
        "observed_qfx_hostname": observed_hostname,
        "observed_qfx_model": observed_model,
        "expected_ex_hostname": expected_ex_hostname,
        "lldp_match_count": len(neighbors),
        "physical_interface": physical or None,
        "remote_port_id": unique_neighbor.get("remote_port_id") if unique_neighbor else None,
        "ae_interface": ae,
        "lacp_system_id": system_id,
        "baseline_vlan_ids": vlan_ids,
        "unresolved_vlan_members": unresolved_vlans,
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def discover_qfx_attachment(policy, expected_ex_hostname, devices, host_keys, observed_at=None):
    validate_pre_cutover_site_policy(policy)
    observations = []
    for device_policy in policy["qfx_pair"]:
        role = device_policy["role"]
        _require(role in devices, "missing connected QFX device for role %s" % role)
        _require(role in host_keys, "missing QFX host-key observation for role %s" % role)
        observations.append(
            observe_qfx_attachment(
                devices[role],
                device_policy,
                policy,
                expected_ex_hostname,
                host_keys[role],
            )
        )

    by_role = {item["role"]: item for item in observations}
    a = by_role["qfx-a"]
    b = by_role["qfx-b"]
    pair_checks = {
        "same_target_ex_hostname": (
            a["expected_ex_hostname"].lower() == b["expected_ex_hostname"].lower()
            == str(expected_ex_hostname).lower()
        ),
        "physical_interface_symmetry": bool(a["physical_interface"])
        and a["physical_interface"] == b["physical_interface"],
        "ae_symmetry": bool(a["ae_interface"])
        and a["ae_interface"] == b["ae_interface"],
        "lacp_system_id_symmetry": bool(a["lacp_system_id"])
        and a["lacp_system_id"] == b["lacp_system_id"],
    }
    passed = all(item["result"] == "PASS" for item in observations) and all(
        pair_checks.values()
    )
    return {
        "schema_version": "1.0",
        "observed_at": observed_at or utc_now(),
        "expected_ex_hostname": expected_ex_hostname,
        "devices": observations,
        "pair_checks": pair_checks,
        "result": "PASS" if passed else "FAIL",
    }


def build_attachment_artifact(
    migration_id,
    plan_id,
    plan_digest,
    site_policy_id,
    site_policy_digest,
    discovery,
    approved_at,
):
    _require(discovery.get("result") == "PASS", "QFX attachment discovery did not pass")
    stable_devices = []
    for item in sorted(discovery["devices"], key=lambda value: value["role"]):
        stable_devices.append({
            "role": item["role"],
            "management_address": item["management_address"],
            "ssh_host_key_sha256": item["ssh_host_key_sha256"],
            "observed_qfx_hostname": item["observed_qfx_hostname"],
            "observed_qfx_model": item["observed_qfx_model"],
            "physical_interface": item["physical_interface"],
            "remote_port_id": item["remote_port_id"],
            "ae_interface": item["ae_interface"],
            "lacp_system_id": item["lacp_system_id"],
            "baseline_vlan_ids": item["baseline_vlan_ids"],
        })
    key = {
        "migration_id": migration_id,
        "plan_digest": plan_digest,
        "site_policy_digest": site_policy_digest,
        "expected_ex_hostname": discovery["expected_ex_hostname"],
        "devices": stable_devices,
    }
    attachment_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "attachment_id": attachment_id,
        "migration_id": migration_id,
        "observed_at": discovery["observed_at"],
        "approved_at": approved_at,
        "plan": {"plan_id": plan_id, "plan_digest": plan_digest},
        "site_policy": {
            "site_policy_id": site_policy_id,
            "site_policy_digest": site_policy_digest,
        },
        "expected_ex_hostname": discovery["expected_ex_hostname"],
        "devices": stable_devices,
        "pair_checks": discovery["pair_checks"],
        "result": "PASS",
        "safety": {
            "read_only_discovery": True,
            "qfx_writes_authorized": False,
            "ex4400_writes_authorized": False,
            "force_up_allowed": False,
            "operator_supplied_ports_used": False,
            "assignment_source": "LLDP+EXISTING_QFX_AE+LACP+ESI+MGMT_BASELINE",
        },
    }


def write_attachment(migration_root, value):
    _require(value.get("result") == "PASS", "QFX attachment artifact did not pass")
    destination = migration_root / "qfx-attachments" / value["attachment_id"]
    path = destination / "attachment.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("attachment.json") == sha256_file(path), "QFX attachment integrity failed")
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(value)
        comparable_existing.pop("approved_at", None)
        comparable_new.pop("approved_at", None)
        _require(comparable_existing == comparable_new, "existing QFX attachment ID has different content")
        return destination, existing, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {"attachment.json": sha256_file(path)})
    return destination, value, "CREATED"
