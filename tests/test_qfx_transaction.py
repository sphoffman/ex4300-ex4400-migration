from ex_migration_provisioner.qfx_stage_cli import _rollback_pair
from ex_migration_provisioner.qfx_transaction import (
    build_transaction,
    validate_post_commit_pair,
)


TARGET = "home1-ex4400-vc-fd-sw1203"


def qfx_plan():
    statements = [
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v100",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members v200",
        "set interfaces ae2 unit 0 family ethernet-switching vlan members voip",
    ]
    return {
        "migration_id": "sw1203",
        "qfx_plan_id": "1" * 16,
        "devices": [
            {
                "role": "qfx-a",
                "management_address": "10.255.3.14",
                "physical_interface": "et-0/0/5",
                "ae_interface": "ae2",
                "statements": list(statements),
            },
            {
                "role": "qfx-b",
                "management_address": "10.255.3.15",
                "physical_interface": "et-0/0/5",
                "ae_interface": "ae2",
                "statements": list(statements),
            },
        ],
    }


class FakeDevice:
    def __init__(self, target=TARGET):
        self.target = target

    def cli(self, command, warning=False):
        if command == "show lldp neighbors detail":
            return "\n".join([
                "LLDP Neighbor Information:",
                "Local Interface    : et-0/0/5",
                "Parent Interface   : -",
                "Port ID            : ae0",
                "System name        : %s" % self.target,
                "",
            ])
        if command == "show configuration interfaces et-0/0/5 | display set":
            return "set interfaces et-0/0/5 ether-options 802.3ad ae2\n"
        if command == "show configuration interfaces ae2 | display set":
            return "\n".join([
                "set interfaces ae2 aggregated-ether-options lacp system-id 00:01:02:03:04:02",
                "set interfaces ae2 esi auto-derive type-1-lacp",
                "set interfaces ae2 esi all-active",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members v163",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members TEMP-RECOVERY",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members v100",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members v200",
                "set interfaces ae2 unit 0 family ethernet-switching vlan members voip",
                "",
            ])
        if command == "show lacp interfaces ae2 extensive":
            return "Aggregated interface: ae2\n et-0/0/5 Collecting Distributing\n"
        raise AssertionError("unexpected command: %s" % command)


class FakeConfig:
    def __init__(self):
        self.calls = []

    def rollback(self, rb_id=None):
        self.calls.append(("rollback", rb_id))

    def load(self, payload, format=None, merge=None):
        self.calls.append(("load", payload, format, merge))

    def commit_check(self):
        self.calls.append(("commit_check",))
        return True

    def commit(self, **kwargs):
        self.calls.append(("commit", kwargs))
        return True


def test_transaction_id_is_deterministic_for_same_pair_diffs():
    diffs = {"qfx-a": "same\n", "qfx-b": "same\n"}
    a = build_transaction(qfx_plan(), diffs, "2026-09-08T18:00:00Z", 10)
    b = build_transaction(qfx_plan(), diffs, "2026-09-08T18:01:00Z", 10)
    assert a["transaction_id"] == b["transaction_id"]
    assert a["safety"]["rollback_both_on_failure"] is True


def test_post_commit_pair_requires_lldp_mapping_vlan_membership_and_lacp():
    result = validate_post_commit_pair(
        {"qfx-a": FakeDevice(), "qfx-b": FakeDevice()},
        qfx_plan(),
        TARGET,
    )
    assert result["result"] == "PASS"
    assert all(item["result"] == "PASS" for item in result["devices"])


def test_post_commit_pair_fails_if_lldp_peer_changes():
    result = validate_post_commit_pair(
        {"qfx-a": FakeDevice(target="wrong-switch"), "qfx-b": FakeDevice()},
        qfx_plan(),
        TARGET,
    )
    assert result["result"] == "FAIL"
    assert result["devices"][0]["checks"]["lldp_target_on_bound_physical_interface"] is False


def test_pending_commit_failure_rolls_back_both_with_rollback_one(tmp_path):
    plan = qfx_plan()
    diffs = {"qfx-a": "same\n", "qfx-b": "same\n"}
    tx = build_transaction(plan, diffs, "2026-09-08T18:00:00Z", 10)
    configs = {"qfx-a": FakeConfig(), "qfx-b": FakeConfig()}
    errors = _rollback_pair(
        configs,
        plan,
        committed_roles=["qfx-a", "qfx-b"],
        final_confirmed_roles=[],
        transaction=tx,
        migration_root=tmp_path,
        candidate_diffs=diffs,
    )
    assert errors == []
    assert ("rollback", 1) in configs["qfx-a"].calls
    assert ("rollback", 1) in configs["qfx-b"].calls
    assert tx["status"] == "ROLLED_BACK"


def test_final_confirmation_split_uses_compensating_delete_on_confirmed_side(tmp_path):
    plan = qfx_plan()
    diffs = {"qfx-a": "same\n", "qfx-b": "same\n"}
    tx = build_transaction(plan, diffs, "2026-09-08T18:00:00Z", 10)
    configs = {"qfx-a": FakeConfig(), "qfx-b": FakeConfig()}
    errors = _rollback_pair(
        configs,
        plan,
        committed_roles=["qfx-a", "qfx-b"],
        final_confirmed_roles=["qfx-a"],
        transaction=tx,
        migration_root=tmp_path,
        candidate_diffs=diffs,
    )
    assert errors == []
    loads = [call for call in configs["qfx-a"].calls if call[0] == "load"]
    assert len(loads) == 1
    assert "delete interfaces ae2 unit 0 family ethernet-switching vlan members v100" in loads[0][1]
    assert ("rollback", 1) in configs["qfx-b"].calls
    assert tx["status"] == "ROLLED_BACK"
