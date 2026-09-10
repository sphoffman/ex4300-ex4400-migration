import json

from ex_migration_operator import current_artifacts
from ex_migration_analyzer.core import sha256_file


def _write_package(root, package_id, schema_version):
    directory = root / "packages" / package_id
    directory.mkdir(parents=True)
    path = directory / "package.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "package_id": package_id,
                "migration_id": root.name,
                "created_at": "2026-09-09T00:00:00Z",
                "inputs": {},
            },
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    (directory / "integrity.json").write_text(
        json.dumps({"package.json": sha256_file(path)}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_operator_accepts_only_current_package_schema(tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    _write_package(root, "old-package", "1.0")
    _write_package(root, "current-package", "1.1")

    candidates = current_artifacts.package_candidates(root)

    assert [item["package"]["package_id"] for item in candidates] == [
        "current-package"
    ]
