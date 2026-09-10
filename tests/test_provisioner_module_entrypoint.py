import subprocess
import sys


def test_provisioner_module_entrypoint_executes_main():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ex_migration_provisioner.cli",
            "prepare",
            "--help",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "EX4400 pre-cutover package" in result.stdout
    assert "--site-policy" in result.stdout
