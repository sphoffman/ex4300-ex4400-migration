from __future__ import annotations

import importlib.util
from pathlib import Path


def _launcher():
    path = Path("migrate.py")
    spec = importlib.util.spec_from_file_location("migrate_python_launcher", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_python_launcher_routes_initial_discovery_help_without_credentials(monkeypatch):
    launcher = _launcher()

    def unexpected_prompt(*_args, **_kwargs):
        raise AssertionError("help must not prompt for credentials")

    monkeypatch.setattr("builtins.input", unexpected_prompt)
    monkeypatch.setattr(launcher.getpass, "getpass", unexpected_prompt)

    module, args, error = launcher._route(["discover", "--help"])
    assert error is None
    assert module == "ex_migration_operator.initial_discovery"
    assert args == ["--help"]


def test_python_launcher_routes_site_commands():
    launcher = _launcher()
    module, args, error = launcher._route(["site-status", "--settings", "config/site.json"])
    assert error is None
    assert module == "ex_migration_site.cli"
    assert args == ["site-status", "--settings", "config/site.json"]


def test_python_launcher_routes_per_migration_commands():
    launcher = _launcher()
    module, args, error = launcher._route(["sw1203", "status"])
    assert error is None
    assert module == "ex_migration_operator.current_cli"
    assert args == ["sw1203", "status"]


def test_python_launcher_rejects_bare_migration_command(capsys):
    launcher = _launcher()
    module, args, error = launcher._route(["status"])
    assert module is None
    assert args is None
    assert error == 2
    assert "migration command, not a migration ID" in capsys.readouterr().err
