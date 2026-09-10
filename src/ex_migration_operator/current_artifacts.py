from __future__ import annotations

from ex_migration_analyzer.core import read_json
from ex_migration_provisioner import cli_base as base


CURRENT_PACKAGE_SCHEMA_VERSION = "1.1"


def package_candidates(migration_root):
    """Read only the current provisioning-package schema.

    The project is still under development and migration artifacts are expected to
    be regenerated after schema changes. Older package layouts are intentionally
    ignored rather than adapted.
    """
    candidates = []
    for package_path in sorted((migration_root / "packages").glob("*/package.json")):
        directory = package_path.parent
        try:
            base._verify_integrity(directory, ("package.json",))
            package = read_json(package_path)
            if package.get("schema_version") != CURRENT_PACKAGE_SCHEMA_VERSION:
                continue
            if package.get("migration_id") != migration_root.name:
                continue
            candidates.append({
                "package": package,
                "package_path": package_path,
                "directory": directory,
            })
        except (base.AnalysisError, base.ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (
            item["package"].get("created_at", ""),
            item["package"].get("package_id", ""),
        ),
        reverse=True,
    )


def choose_package(migration_root, package_id=None):
    candidates = package_candidates(migration_root)
    if package_id:
        candidates = [
            item for item in candidates
            if item["package"].get("package_id") == package_id
        ]
    if not candidates:
        suffix = " %s" % package_id if package_id else ""
        raise base.ProvisioningError(
            "no current-schema integrity-valid provisioning package%s was found"
            % suffix
        )
    return candidates[0]
