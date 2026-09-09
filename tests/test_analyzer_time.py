from ex_migration_analyzer.cli import readable_time, set_display_timezone


def test_readable_time_shows_site_local_and_utc():
    set_display_timezone("America/New_York")
    value = readable_time("2026-09-09T01:15:33Z")
    assert "Sep 8, 2026 21:15 EDT" in value
    assert "Sep 9, 2026 01:15 UTC" in value
