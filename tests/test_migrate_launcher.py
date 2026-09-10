from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_reserved_migration_command_cannot_be_treated_as_migration_id():
    result = subprocess.run(
        ["bash", str(ROOT / "migrate"), "status"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 2
    assert "'status' is a migration command, not a migration ID" in result.stderr
    assert "./migrate <migration-id> status" in result.stderr
    assert "./migrate site-status" in result.stderr
