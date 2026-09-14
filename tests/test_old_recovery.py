from ex_migration_provisioner import old_recovery_cli
from ex_migration_provisioner import temp_management_cli


def test_legacy_old_recovery_command_routes_to_temp_management():
    assert old_recovery_cli.main is temp_management_cli.main
    assert old_recovery_cli.run is temp_management_cli.run


def test_temp_management_replaces_vme_recovery_model():
    module_text = __import__(
        "inspect"
    ).getsource(temp_management_cli)
    assert "vme.0" not in module_text
    assert "mgmt_junos" not in module_text
    assert "replacement EX4400 fxp0" in module_text
    assert "temporary-management" in module_text
