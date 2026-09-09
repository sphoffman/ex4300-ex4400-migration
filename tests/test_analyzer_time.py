from ex_migration_analyzer.cli import readable_time, set_display_timezone


EASTERN_POSIX_TZ = "EST5EDT,M3.2.0,M11.1.0"


def test_readable_time_shows_site_local_and_utc_in_summer():
    set_display_timezone(EASTERN_POSIX_TZ)
    value = readable_time("2026-09-09T01:15:33Z")
    assert "Sep 8, 2026 21:15 EDT" in value
    assert "Sep 9, 2026 01:15 UTC" in value


def test_readable_time_shows_site_local_and_utc_in_winter():
    set_display_timezone(EASTERN_POSIX_TZ)
    value = readable_time("2026-12-09T01:15:33Z")
    assert "Dec 8, 2026 20:15 EST" in value
    assert "Dec 9, 2026 01:15 UTC" in value
