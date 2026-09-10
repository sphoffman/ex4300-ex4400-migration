from pathlib import Path


def test_bare_migration_resume_routes_to_site_status_when_active_policy_missing():
    text = Path("migrate").read_text(encoding="utf-8")
    assert '[[ "$module" == "ex_migration_operator.current_cli" && ${#args[@]} -eq 1 ]]' in text
    assert '[[ ! -f config/qfx-site-policy.active.json ]]' in text
    assert 'module="ex_migration_site.cli"' in text
    assert 'args=("site-status")' in text
    assert "waiting on site readiness" in text
