from ex_migration_provisioner.current_policy import (
    derive_required_qfx_vlans,
    render_variables,
    validate_site_policy,
)
from ex_migration_site.cli import _build_site_discovery, _stage_statements
from ex_migration_site.core import build_profile


def _policy():
    return {
        "schema_version": "1.2",
        "site_policy_id": "campus-abc",
        "site_id": "campus",
        "environment": "lab",
        "production_eligible": False,
        "qfx_pair": [
            {"role": "qfx-a", "management_address": "10.0.0.1", "expected_hostname": "BD-1", "expected_model": "QFX5700"},
            {"role": "qfx-b", "management_address": "10.0.0.2", "expected_hostname": "BD-2", "expected_model": "QFX5700"},
        ],
        "stage_port_pools": {"site-verified": ["et-0/0/3", "et-0/0/4"]},
        "excluded_interfaces": [],
        "ae_pool": {"method": "discover-from-existing-qfx-config", "ae_min": 0, "ae_max": 1, "migration_assignment_prebound": False},
        "management_vlan": {"name": "MGMT", "vlan_id": 163},
        # Compatibility metadata only; not part of active QFX behavior.
        "temporary_recovery_vlan": {"name": "TEMP-RECOVERY", "vlan_id": 3999},
        "prestage_access_vlan": {"name": "TEMP-ACCESS", "vlan_id": 3998},
        "precutover_qfx_baseline": {"required_vlan_ids": [163], "lacp_mode": "active", "force_up": False},
        "esi": {"method": "auto-derive-type-1-lacp", "all_active": True},
        "validation": {
            "attachment_discovered_post_cutover": True,
            "require_interface_symmetry": True,
            "require_lldp": True,
            "require_lacp_partner": True,
            "require_matching_ae": True,
            "require_matching_lacp_system_id": True,
            "operator_supplied_ports_allowed": False,
        },
        "source_site_inventory": {"inventory_id": "abc", "inventory_digest": "0" * 64, "path": "snapshots/site/campus/inventories/abc/inventory.json"},
    }


def _plan():
    return {
        "plan_id": "plan1",
        "migration_id": "sw1203",
        "template_variables": {
            "migration_id": "sw1203",
            "management_vlan_id": 163,
            "management_vlan_name": "MGMT",
            "voice_vlan_name": "voip-sw1203",
            "voice_vlan_id": 1111,
            "configured_vlans": [
                {"name": "v100", "vlan_id": 100},
                {"name": "MGMT", "vlan_id": 163},
                {"name": "voip-sw1203", "vlan_id": 1111},
            ],
        },
        "vlan_intents": [
            {"name": "v100", "vlan_id": 100},
            {"name": "MGMT", "vlan_id": 163},
            {"name": "voip-sw1203", "vlan_id": 1111},
        ],
        "port_intents": [
            {"planned_action": "CORRELATE_AFTER_CABLE_MOVE", "configured_data_vlan_id": 100},
        ],
    }


def _profile():
    return build_profile(
        "campus",
        "lab",
        "10.0.0.1",
        "10.0.0.2",
        {"name": "MGMT", "vlan_id": 163},
        {"name": "TEMP-RECOVERY", "vlan_id": 3999},
        {"name": "TEMP-ACCESS", "vlan_id": 3998},
        [],
    )


def _preprovisioned_config(include_second=True, include_legacy_3999=False):
    lines = [
        "set interfaces et-0/0/3 ether-options 802.3ad ae0",
        "set interfaces ae0 esi auto-derive type-1-lacp",
        "set interfaces ae0 esi all-active",
        "set interfaces ae0 aggregated-ether-options lacp active",
        "set interfaces ae0 aggregated-ether-options lacp system-id 00:01:02:03:04:00",
        "set interfaces ae0 unit 0 family ethernet-switching interface-mode trunk",
    ]
    if include_legacy_3999:
        lines.append("set interfaces ae0 unit 0 family ethernet-switching vlan members TEMP-RECOVERY")
    if include_second:
        lines.extend([
            "set interfaces et-0/0/4 ether-options 802.3ad ae1",
            "set interfaces ae1 esi auto-derive type-1-lacp",
            "set interfaces ae1 esi all-active",
            "set interfaces ae1 aggregated-ether-options lacp active",
            "set interfaces ae1 aggregated-ether-options lacp system-id 00:01:02:03:04:01",
            "set interfaces ae1 unit 0 family ethernet-switching interface-mode trunk",
        ])
        if include_legacy_3999:
            lines.append("set interfaces ae1 unit 0 family ethernet-switching vlan members TEMP-RECOVERY")
    return "\n".join(lines) + "\n"


def _observations(include_second=True, include_legacy_3999=False):
    vlan_text = "\n".join([
        "set vlans MGMT vlan-id 163",
        "set vlans TEMP-RECOVERY vlan-id 3999",
    ])
    config = _preprovisioned_config(include_second=include_second, include_legacy_3999=include_legacy_3999)
    mappings = {"et-0/0/3": "ae0"}
    if include_second:
        mappings["et-0/0/4"] = "ae1"
    values = []
    for role, address, hostname in (("qfx-a", "10.0.0.1", "BD-1"), ("qfx-b", "10.0.0.2", "BD-2")):
        values.append({
            "role": role,
            "management_address": address,
            "ssh_host_key_sha256": "SHA256:test-%s" % role,
            "hostname": hostname,
            "model": "QFX5700",
            "serial_number": role,
            "interfaces": ["et-0/0/3", "et-0/0/4"],
            "ae_map": dict(mappings),
            "interface_config": {},
            "interface_config_text": config,
            "vlan_config_text": vlan_text,
        })
    return values


def test_generated_policy_has_no_site_wide_voice_vlan():
    policy = _policy()
    assert validate_site_policy(policy) is policy
    assert "voice_vlan" not in policy
    assert policy["precutover_qfx_baseline"]["required_vlan_ids"] == [163]


def test_render_and_qfx_derivation_use_migration_voice_vlan():
    variables = render_variables(
        _plan(),
        _policy(),
        {"environment": "lab", "virtual_chassis": {"member_count": 1, "members": []}},
    )
    assert variables["voice_vlan"] == "voip-sw1203"
    assert variables["voice_vlan_id"] == 1111
    assert next(v for v in variables["configured_vlans"] if v["vlan_id"] == 1111)["classification"] == "voice"
    assert "temporary_recovery_vlan" not in variables
    assert "temporary_recovery_vlan_name" not in variables
    assert "temporary_recovery_vlan_id" not in variables

    derived = derive_required_qfx_vlans(_plan(), _policy())
    assert derived["voice_vlan_id"] == 1111
    assert derived["required_vlan_ids"] == [100, 1111]


def test_site_discovery_requires_existing_symmetric_et_to_ae_mapping():
    discovery = _build_site_discovery(
        _profile(),
        _observations(),
        observed_at="2026-09-10T00:00:00Z",
    )
    assert [(x["physical_interface"], x["ae_interface"]) for x in discovery["attachment_inventory"]] == [
        ("et-0/0/3", "ae0"),
        ("et-0/0/4", "ae1"),
    ]
    assert all(x["mapping_source"] == "PREPROVISIONED_SYMMETRIC" for x in discovery["attachment_inventory"])
    assert all(x["current_vlan_ids"] == {"qfx-a": [], "qfx-b": []} for x in discovery["attachment_inventory"])
    assert discovery["baseline_vlan_ids"] == [163]


def test_site_discovery_tolerates_preexisting_legacy_3999_without_requiring_it():
    discovery = _build_site_discovery(
        _profile(),
        _observations(include_legacy_3999=True),
        observed_at="2026-09-10T00:00:00Z",
    )
    assert discovery["baseline_vlan_ids"] == [163]
    assert all(
        x["current_vlan_ids"] == {"qfx-a": [3999], "qfx-b": [3999]}
        for x in discovery["attachment_inventory"]
    )


def test_site_discovery_does_not_create_missing_ae_mapping():
    discovery = _build_site_discovery(
        _profile(),
        _observations(include_second=False),
        observed_at="2026-09-10T00:00:00Z",
    )
    assert [(x["physical_interface"], x["ae_interface"]) for x in discovery["attachment_inventory"]] == [
        ("et-0/0/3", "ae0"),
    ]
    blocked = {x["physical_interface"]: x["reason"] for x in discovery["blocked_interfaces"]}
    assert blocked["et-0/0/4"] == "NOT_PREPROVISIONED_TO_AE"


def test_site_stage_can_only_add_management_vlan_membership():
    discovery = _build_site_discovery(
        _profile(),
        _observations(),
        observed_at="2026-09-10T00:00:00Z",
    )
    statements = _stage_statements(_profile(), discovery)
    assert statements == [
        "set interfaces ae0 unit 0 family ethernet-switching vlan members MGMT",
        "set interfaces ae1 unit 0 family ethernet-switching vlan members MGMT",
    ]
    assert not any("3999" in statement or "TEMP-RECOVERY" in statement for statement in statements)
    forbidden = ("802.3ad", "lacp", "system-id", "esi ", "interface-mode trunk")
    assert not any(token in statement for token in forbidden for statement in statements)
