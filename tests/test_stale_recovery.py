from ex_migration_provisioner import cli


def test_template_change_recovery_reuses_bootstrap_identity():
    exc = cli._stale_recovery_error("sw1203", ["template_digest"])
    text = str(exc)
    assert "template_digest changed" in text
    assert "prepare sw1203" in text
    assert "render sw1203" in text
    assert "new render ID" in text
    assert "existing approved bootstrap identity may be reused" in text
    assert "Discovery, analyzer, and planner do not need to be rerun" in text
    assert "do not edit or delete" in text


def test_bootstrap_change_recovery_requires_new_identity():
    exc = cli._stale_recovery_error(
        "sw1203",
        ["template_digest", "bootstrap_profile_digest"],
    )
    text = str(exc)
    assert "bootstrap_profile_digest" in text
    assert "prepare sw1203" in text
    assert "render sw1203" in text
    assert "identify sw1203" in text
    assert "newly approved identity" in text
    assert "may be reused" not in text
