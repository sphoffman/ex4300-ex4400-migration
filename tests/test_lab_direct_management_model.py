from ex_migration_provisioner.endpoint_stage import resolve_postcutover_access


def test_lab_direct_management_keeps_vjunos_model_allowance():
    profile = {
        "schema_version": "1.0",
        "environment": "lab",
        "postcutover_ex_access": {
            "mode": "direct-management",
            "port": 830,
        },
    }

    access = resolve_postcutover_access(profile, "172.16.163.20")

    assert access == {
        "environment": "lab",
        "mode": "direct-management",
        "logical_address": "172.16.163.20",
        "transport_address": "172.16.163.20",
        "port": 830,
        "allow_vjunos_switch": True,
    }


def test_production_direct_management_does_not_allow_vjunos_model():
    profile = {
        "schema_version": "1.0",
        "environment": "production",
        "postcutover_ex_access": {
            "mode": "direct-management",
            "port": 830,
        },
    }

    access = resolve_postcutover_access(profile, "172.16.163.20")

    assert access["transport_address"] == "172.16.163.20"
    assert access["allow_vjunos_switch"] is False
