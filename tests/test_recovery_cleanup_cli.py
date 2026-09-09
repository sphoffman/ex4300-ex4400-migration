from ex_migration_provisioner.recovery_cleanup_cli import _normalize_diff, _parser


def test_cleanup_cli_parser_supports_plan_only():
    args = _parser().parse_args(["sw1203", "--plan-only"])
    assert args.migration_id == "sw1203"
    assert args.plan_only is True
    assert args.confirm_minutes == 10


def test_cleanup_diff_normalization():
    assert _normalize_diff("") == ""
    assert _normalize_diff("abc") == "abc\n"
    assert _normalize_diff("abc\n") == "abc\n"
