import importlib.util
from pathlib import Path


def _load_launcher():
    path = Path(__file__).resolve().parents[1] / "migrate.py"
    spec = importlib.util.spec_from_file_location("migrate_launcher_policy_test", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_python_launcher_routes_site_init_through_policy_module():
    module = _load_launcher()
    routed, args, error = module._route(["site-init", "--help"])
    assert error is None
    assert routed == "ex_migration_operator.policy_cli"
    assert args == ["site-init", "--help"]


def test_python_launcher_routes_migration_through_policy_module():
    module = _load_launcher()
    routed, args, error = module._route(["dh4301", "status"])
    assert error is None
    assert routed == "ex_migration_operator.policy_cli"
    assert args == ["dh4301", "status"]
