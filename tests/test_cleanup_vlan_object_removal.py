from ex_migration_provisioner.recovery_cleanup import (
    complete_stale_vlan_object_deletes,
    inverse_statements,
)


def test_proven_unused_vlan_gets_final_object_delete_after_owned_leaves():
    leaf_deletes = [
        "delete vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST interface ae0.0",
        "delete vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST overrides trusted",
        "delete vlans UNUSED-TEST vlan-id 300",
    ]
    hardening = {
        "stale_vlans": {
            "delete": [
                {
                    "name": "UNUSED-TEST",
                    "vlan_id": 300,
                    "reason": "PROVEN_UNUSED_DATA_VLAN",
                }
            ]
        }
    }

    statements = complete_stale_vlan_object_deletes(leaf_deletes, hardening)

    assert statements[:-1] == leaf_deletes
    assert statements[-1] == "delete vlans UNUSED-TEST"


def test_stale_vlan_object_delete_keeps_exact_leaf_restore_information():
    leaf_deletes = [
        "delete vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST interface ae0.0",
        "delete vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST overrides trusted",
        "delete vlans UNUSED-TEST vlan-id 300",
    ]
    hardening = {
        "stale_vlans": {
            "delete": [{"name": "UNUSED-TEST", "vlan_id": 300}]
        }
    }

    statements = complete_stale_vlan_object_deletes(leaf_deletes, hardening)
    restore = inverse_statements(statements)

    assert restore[0] == "set vlans UNUSED-TEST"
    assert "set vlans UNUSED-TEST vlan-id 300" in restore
    assert (
        "set vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST interface ae0.0"
        in restore
    )
    assert (
        "set vlans UNUSED-TEST forwarding-options dhcp-security group DHCP_TRUST overrides trusted"
        in restore
    )


def test_no_proven_unused_vlan_leaves_statements_unchanged():
    statements = ["set interfaces ge-0/0/10 disable"]
    value = complete_stale_vlan_object_deletes(
        statements,
        {"stale_vlans": {"delete": []}},
    )
    assert value == statements
