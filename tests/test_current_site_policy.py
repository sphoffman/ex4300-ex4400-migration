from ex_migration_provisioner.current_policy import (
    derive_required_qfx_vlans,
    render_variables,
    validate_site_policy,
)
from ex_migration_site.core import build_active_policy, build_profile, build_site_discovery, stage_statements


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
        "stage_port_pools": {"site-staged": ["et-0/0/3", "et-0/0/4"]},
        "excluded_interfaces": [],
        "ae_pool": {"method": "discover-from-existing-qfx-config", "ae_min": 0, "ae_max": 1, "migration_assignment_prebound": False},
        "management_vlan": {"name": "MGMT", "vlan_id": 163},
        "temporary_recovery_vlan": {"name": "TEMP-RECOVERY", "vlan_id": 3999},
        "prestage_access_vlan": {"name": "TEMP-ACCESS", "vlan_id": 3998},
        "precutover_qfx_baseline": {"required_vlan_ids": [163, 3999], "lacp_mode": "active", "force_up": False},
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


def test_generated_policy_has_no_site_wide_voice_vlan():
    policy = _policy()
    assert validate_site_policy(policy) is policy
    assert "voice_vlan" not in policy


def test_render_and_qfx_derivation_use_migration_voice_vlan():
    variables = render_variables(
        _plan(),
        _policy(),
        {"environment": "lab", "virtual_chassis": {"member_count": 1, "members": []}},
    )
    assert variables["voice_vlan"] == "voip-sw1203"
    assert variables["voice_vlan_id"] == 1111
    assert next(v for v in variables["configured_vlans"] if v["vlan_id"] == 1111)["classification"] == "voice"

    derived = derive_required_qfx_vlans(_plan(), _policy())
    assert derived["voice_vlan_id"] == 1111
    assert derived["required_vlan_ids"] == [100, 1111]


def test_site_discovery_proposes_symmetric_et_to_ae_and_baseline_has_no_voice():
    profile = build_profile(
        "campus",
        "lab",
        "10.0.0.1",
        "10.0.0.2",
        {"name": "MGMT", "vlan_id": 163},
        {"name": "TEMP-RECOVERY", "vlan_id": 3999},
        {"name": "TEMP-ACCESS", "vlan_id": 3998},
        [],
        0,
        3,
    )
    vlan_text = "\n".join([
        "set vlans MGMT vlan-id 163",
        "set vlans TEMP-RECOVERY vlan-id 3999",
    ])
    observations = []
    for role, address, hostname in (("qfx-a", "10.0.0.1", "BD-1"), ("qfx-b", "10.0.0.2", "BD-2")):
        observations.append({
            "role": role,
            "management_address": address,
            "ssh_host_key_sha256": "SHA256:test-%s" % role,
            "hostname": hostname,
            "model": "QFX5700",
            "serial_number": role,
            "interfaces": ["et-0/0/3", "et-0/0/4"],
            "ae_map": {},
            "interface_config": {},
            "interface_config_text": "",
            "vlan_config_text": vlan_text,
        })
    discovery = build_site_discovery(profile, observations, observed_at="2026-09-10T00:00:00Z")
    assert [(x["physical_interface"], x["ae_interface"]) for x in discovery["attachment_inventory"]] == [
        ("et-0/0/3", "ae0"),
        ("et-0/0/4", "ae1"),
    ]
    statements = stage_statements(profile, discovery)
    assert any("vlan members MGMT" in value for value in statements)
    assert any("vlan members TEMP-RECOVERY" in value for value in statements)
    assert all("1111" not in value and "voice" not in value.lower() for value in statements)
