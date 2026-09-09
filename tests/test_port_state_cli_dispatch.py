from ex_migration_provisioner import cli, port_state_cli


def test_main_cli_dispatches_port_state(monkeypatch):
    seen = {}

    def fake_main(argv):
        seen["argv"] = list(argv)
        return 17

    monkeypatch.setattr(port_state_cli, "main", fake_main)
    assert cli.main(["port-state", "sw1203"]) == 17
    assert seen["argv"] == ["sw1203"]
