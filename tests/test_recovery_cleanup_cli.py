import ex_migration_provisioner.recovery_cleanup_cli as cleanup_cli
from ex_migration_provisioner.recovery_cleanup_cli import _device_credentials, _normalize_diff, _parser


def test_cleanup_cli_parser_supports_plan_only():
    args = _parser().parse_args(["sw1203", "--plan-only"])
    assert args.migration_id == "sw1203"
    assert args.plan_only is True
    assert args.confirm_minutes == 10


def test_cleanup_cli_parser_supports_shared_credentials():
    args = _parser().parse_args([
        "sw1203",
        "--username", "radius-user",
        "--password-env", "RADIUS_PASSWORD",
    ])
    assert args.username == "radius-user"
    assert args.password_env == "RADIUS_PASSWORD"


def test_cleanup_reuses_one_shared_credential_prompt(monkeypatch):
    calls = []

    def fake_credentials(username, password_env, label):
        calls.append((username, password_env, label))
        return "radius-user", "radius-password"

    monkeypatch.setattr(cleanup_cli, "_credentials", fake_credentials)
    args = _parser().parse_args(["sw1203"])
    values = _device_credentials(args)
    assert values == (
        "radius-user",
        "radius-password",
        "radius-user",
        "radius-password",
    )
    assert calls == [(None, None, "EX/QFX")]


def test_cleanup_per_device_credentials_still_override_shared(monkeypatch):
    calls = []

    def fake_credentials(username, password_env, label):
        calls.append((username, password_env, label))
        return username, "%s-password" % label

    monkeypatch.setattr(cleanup_cli, "_credentials", fake_credentials)
    args = _parser().parse_args([
        "sw1203",
        "--username", "radius-user",
        "--qfx-username", "qfx-override",
    ])
    values = _device_credentials(args)
    assert values[0] == "radius-user"
    assert values[2] == "qfx-override"
    assert calls == [
        ("radius-user", None, "EX4400"),
        ("qfx-override", None, "QFX"),
    ]


def test_cleanup_diff_normalization():
    assert _normalize_diff("") == ""
    assert _normalize_diff("abc") == "abc\n"
    assert _normalize_diff("abc\n") == "abc\n"
