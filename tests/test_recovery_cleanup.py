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


def test_cleanup_statements_are_scope_limited():
    assert ex_cleanup_statements("ge-0/0/47", "TEMP-RECOVERY") == [
        "delete interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "delete vlans TEMP-RECOVERY",
    ]
    assert qfx_cleanup_statements("ae2", "TEMP-RECOVERY") == [
        "delete interfaces ae2 unit 0 family ethernet-switching vlan members TEMP-RECOVERY"
    ]


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


def test_ex_recovery_state_before_and_after_cleanup():
    before = "\n".join([
        "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
        "set vlans TEMP-RECOVERY vlan-id 3999",
        "set vlans default vlan-id 3998",
    ])
    state = ex_recovery_state(before, "ge-0/0/47", "TEMP-RECOVERY", 3999, 3998)
    assert state["recovery_port_membership_present"] is True
    assert state["recovery_vlan_definition_present"] is True
    after = "set vlans default vlan-id 3998\n"
    state = ex_recovery_state(after, "ge-0/0/47", "TEMP-RECOVERY", 3999, 3998)
    assert state["recovery_port_membership_present"] is False
    assert state["recovery_vlan_definition_present"] is False
    assert state["holding_default_vlan_present"] is True


def test_pre_cleanup_requires_recovery_membership_on_both_qfxs():
    ex_state = {
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


def test_post_cleanup_requires_membership_removed_but_definition_preserved():
    ex_state = {
        "recovery_port_membership_present": False,
        "recovery_vlan_definition_present": False,
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

    qfx["qfx-a"]["definitions"].pop("TEMP-RECOVERY")
    value = validate_post_cleanup(
        _plan(), _live(), ex_state, qfx, 163, 3999, "TEMP-RECOVERY",
        [100, 200, 1111], {"result": "PASS"},
    )
    assert value["result"] == "FAIL"
