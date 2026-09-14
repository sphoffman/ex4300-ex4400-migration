from ex_migration_provisioner.recovery_cleanup import (
    ex_cleanup_statements,
    ex_recovery_state,
    inverse_statements,
    qfx_cleanup_statements,
    qfx_vlan_ids,
    validate_post_cleanup,
    validate_pre_cleanup,
)


def _plan():
    return {
        "port_intents": [
            {"old_interface": "ge-0/0/2", "planned_action": "CORRELATE_AFTER_CABLE_MOVE"},
            {"old_interface": "ge-0/0/10", "planned_action": "LEAVE_TEMPLATE_DEFAULT"},
        ]
    }


def _live():
    return {"ge-0/0/2": {"old_interface": "ge-0/0/2", "new_interface": "ge-0/0/2"}}


def _qfx_state(ids):
    return {
        "vlan_ids": ids,
        "unresolved": [],
        "definitions": {
            "v100": 100,
            "v163": 163,
            "v200": 200,
            "voip": 1111,
            "TEMP-RECOVERY": 3999,
        },
        "topology_result": "PASS",
    }


def test_cleanup_statements_preserve_historical_recovery_configuration_when_explicitly_required():
    assert ex_cleanup_statements("ge-0/0/47", "TEMP-RECOVERY") == [
        "set interfaces ge-0/0/47 disable",
    ]
    assert ex_cleanup_statements(
        "ge-0/0/47",
        "TEMP-RECOVERY",
        recovery_port_already_disabled=True,
    ) == []
    assert qfx_cleanup_statements("ae2", "TEMP-RECOVERY") == [
        "delete interfaces ae2 unit 0 family ethernet-switching vlan members TEMP-RECOVERY"
    ]


def test_current_cleanup_never_manages_external_temp_management():
    assert ex_cleanup_statements(
        "EXTERNAL",
        "EXTERNAL-TEMP-MGMT",
        recovery_required=False,
    ) == []
    assert qfx_cleanup_statements(
        "ae2",
        "EXTERNAL-TEMP-MGMT",
        recovery_required=False,
    ) == []


def test_inverse_statements_handles_mixed_set_delete():
    assert inverse_statements([
        "delete interfaces ae0 unit 0 family ethernet-switching vlan members all",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members v100",
    ]) == [
        "delete interfaces ae0 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ae0 unit 0 family ethernet-switching vlan members all",
    ]


def test_qfx_vlan_state_resolves_members_and_preserves_definition_inventory():
    ae = "\n".join([
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v163",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v100",
    ])
    vlans = "\n".join([
        "set routing-instances MAC-VRF-1 vlans v163 vlan-id 163",
        "set routing-instances MAC-VRF-1 vlans TEMP-RECOVERY vlan-id 3999",
        "set routing-instances MAC-VRF-1 vlans v100 vlan-id 100",
    ])
    value = qfx_vlan_ids(ae, vlans, "ae2")
    assert value["vlan_ids"] == [100, 163, 3999]
    assert value["definitions"]["TEMP-RECOVERY"] == 3999


def test_ex_recovery_state_remains_available_for_historical_artifacts():
    before = "\n".join([
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "set vlans default vlan-id 3998",
    ])
    state = ex_recovery_state(before, "ge-0/0/47", "TEMP-RECOVERY", 3999, 3998)
    assert state["recovery_port_disabled"] is False
    assert state["recovery_port_membership_present"] is True
    assert state["recovery_vlan_definition_present"] is True

    after = "\n".join([
        "set interfaces ge-0/0/47 disable",
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "set vlans default vlan-id 3998",
    ])
    state = ex_recovery_state(after, "ge-0/0/47", "TEMP-RECOVERY", 3999, 3998)
    assert state["recovery_port_disabled"] is True
    assert state["recovery_port_membership_present"] is True
    assert state["recovery_vlan_definition_present"] is True
    assert state["holding_default_vlan_present"] is True


def test_historical_pre_cleanup_requires_recovery_membership_on_both_qfxs():
    ex_state = {
        "recovery_port_disabled": False,
        "recovery_port_membership_present": True,
        "recovery_vlan_definition_present": True,
        "holding_default_vlan_present": True,
        "unexpected_other_recovery_memberships": [],
    }
    qfx = {
        "qfx-a": _qfx_state([100, 163, 200, 1111, 3999]),
        "qfx-b": _qfx_state([100, 163, 200, 1111, 3999]),
    }
    value = validate_pre_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS", "blockers": []},
    )
    assert value["result"] == "PASS"

    qfx["qfx-b"] = _qfx_state([100, 163, 200, 1111])
    value = validate_pre_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS", "blockers": []},
    )
    assert value["result"] == "FAIL"


def test_current_pre_cleanup_ignores_temp_management_state():
    ex_state = {
        "recovery_port_disabled": False,
        "recovery_port_membership_present": True,
        "recovery_vlan_definition_present": True,
        "holding_default_vlan_present": True,
        "unexpected_other_recovery_memberships": [],
    }
    qfx = {
        "qfx-a": _qfx_state([100, 163, 200, 1111]),
        "qfx-b": _qfx_state([100, 163, 200, 1111, 3999]),
    }
    value = validate_pre_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS", "blockers": []},
        recovery_required=False,
    )
    assert value["result"] == "PASS"
    assert not any("recovery" in key for key in value["checks"])


def test_historical_post_cleanup_requires_disabled_preserved_local_recovery_attachment():
    ex_state = {
        "recovery_port_disabled": True,
        "recovery_port_membership_present": True,
        "recovery_vlan_definition_present": True,
        "holding_default_vlan_present": True,
        "unexpected_other_recovery_memberships": [],
    }
    qfx = {
        "qfx-a": _qfx_state([100, 163, 200, 1111]),
        "qfx-b": _qfx_state([100, 163, 200, 1111]),
    }
    value = validate_post_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS"},
    )
    assert value["result"] == "PASS"
    assert value["checks"]["ex_recovery_port_disabled"] is True
    assert value["checks"]["ex_recovery_port_membership_preserved"] is True
    assert value["checks"]["ex_recovery_vlan_definition_preserved"] is True


def test_current_post_cleanup_ignores_temp_management_state():
    ex_state = {
        "recovery_port_disabled": False,
        "recovery_port_membership_present": True,
        "recovery_vlan_definition_present": True,
        "holding_default_vlan_present": True,
        "unexpected_other_recovery_memberships": ["anything"],
    }
    qfx = {
        "qfx-a": _qfx_state([100, 163, 200, 1111, 3999]),
        "qfx-b": _qfx_state([100, 163, 200, 1111]),
    }
    value = validate_post_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS"},
        recovery_required=False,
    )
    assert value["result"] == "PASS"
    assert not any("recovery" in key for key in value["checks"])
