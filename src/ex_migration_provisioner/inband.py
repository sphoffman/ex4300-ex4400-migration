from __future__ import annotations

import ipaddress
import shlex
from pathlib import Path

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from .core import ProvisioningError


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def validate_environment_profile(profile):
    _require(profile.get("schema_version") == "1.0", "unsupported environment profile schema")
    environment = str(profile.get("environment") or "")
    _require(environment in ("lab", "production"), "environment profile must be lab or production")
    validation = profile.get("inband_validation") or {}
    mode = validation.get("mode")
    _require(mode in ("lab-probe", "direct-netconf"), "unsupported in-band validation mode")
    target_port = int(validation.get("target_port", 830))
    timeout = int(validation.get("timeout_seconds", 5))
    _require(1 <= target_port <= 65535, "invalid in-band validation target port")
    _require(1 <= timeout <= 60, "invalid in-band validation timeout")

    if mode == "lab-probe":
        _require(environment == "lab", "lab-probe mode is permitted only by a lab environment profile")
        probe = validation.get("probe") or {}
        _require(str(probe.get("host") or "").strip(), "lab-probe host is required")
        _require(str(probe.get("username") or "").strip(), "lab-probe username is required")
        probe_port = int(probe.get("port", 22))
        _require(1 <= probe_port <= 65535, "invalid lab-probe SSH port")
        _require(
            probe.get("host_key_verification") == "accept-ephemeral-lab-key",
            "lab probe must explicitly declare ephemeral host-key handling",
        )
    return profile


def qfx_transaction_candidates(migration_root):
    values = []
    root = migration_root / "qfx-transactions"
    for path in sorted(root.glob("*/transaction.json")):
        directory = path.parent
        try:
            integrity = read_json(directory / "integrity.json")
            if integrity.get("transaction.json") != sha256_file(path):
                continue
            tx = read_json(path)
            if tx.get("migration_id") != migration_root.name:
                continue
            if tx.get("status") != "COMMITTED_AND_CONFIRMED":
                continue
            if tx.get("validation", {}).get("result") != "PASS":
                continue
            values.append({
                "transaction": tx,
                "transaction_path": path,
                "directory": directory,
            })
        except (OSError, ValueError):
            continue
    return sorted(
        values,
        key=lambda item: (
            item["transaction"].get("confirmed_at", ""),
            item["transaction"].get("transaction_id", ""),
        ),
        reverse=True,
    )


def _qfx_transaction_plan_digest(migration_root, transaction):
    qfx_plan_id = str(transaction.get("qfx_plan_id") or "").strip()
    _require(qfx_plan_id, "QFX transaction has no QFX VLAN plan ID")
    directory = migration_root / "qfx-vlan-plans" / qfx_plan_id
    path = directory / "plan.json"
    _require(path.is_file(), "QFX transaction references a missing VLAN plan")
    integrity = read_json(directory / "integrity.json")
    _require(
        integrity.get("plan.json") == sha256_file(path),
        "QFX VLAN plan integrity validation failed",
    )
    plan = read_json(path)
    _require(plan.get("migration_id") == migration_root.name, "QFX VLAN plan migration ID mismatch")
    _require(plan.get("result") == "PASS", "QFX VLAN plan did not pass")
    digest = str(plan.get("inputs", {}).get("migration_plan_digest") or "").strip()
    _require(digest, "QFX VLAN plan has no migration-plan lineage")
    return digest


def _current_approved_plan_digest(migration_root):
    try:
        from . import cli_base
        return str(cli_base.choose_approved_plan(migration_root)["plan_digest"])
    except (KeyError, ProvisioningError):
        return None


def choose_qfx_transaction(migration_root, transaction_id=None, approved_plan_digest=None):
    values = qfx_transaction_candidates(migration_root)
    if transaction_id:
        values = [
            item for item in values
            if item["transaction"].get("transaction_id") == transaction_id
        ]

    if approved_plan_digest is None:
        approved_plan_digest = _current_approved_plan_digest(migration_root)

    if approved_plan_digest is not None:
        approved_plan_digest = str(approved_plan_digest)
        compatible = []
        stale = []
        for item in values:
            try:
                plan_digest = _qfx_transaction_plan_digest(
                    migration_root,
                    item["transaction"],
                )
            except (OSError, ValueError, ProvisioningError):
                if transaction_id:
                    raise
                continue
            if plan_digest == approved_plan_digest:
                compatible.append(item)
            else:
                stale.append(item)
        if transaction_id and stale and not compatible:
            raise ProvisioningError(
                "QFX transaction %s is bound to a different approved migration plan"
                % transaction_id
            )
        values = compatible

    if not values:
        suffix = " %s" % transaction_id if transaction_id else ""
        if approved_plan_digest is not None:
            raise ProvisioningError(
                "no integrity-valid committed-and-confirmed QFX transaction%s bound to the current approved migration plan was found"
                % suffix
            )
        raise ProvisioningError(
            "no integrity-valid committed-and-confirmed QFX transaction%s was found" % suffix
        )
    return values[0]


def pinned_fingerprint(identity):
    value = str(
        identity.get("observed", {})
        .get("connection", {})
        .get("ssh_host_key_sha256")
        or ""
    )
    _require(value.startswith("SHA256:"), "approved EX4400 identity has no valid SSH fingerprint")
    return value


def planned_management_ip(approved_plan):
    migration_id = str(approved_plan.get("migration_id") or "").strip()
    manifest_path = Path("snapshots") / "migrations" / migration_id / "manifest.json"
    value = ""
    if migration_id and manifest_path.is_file():
        manifest = read_json(manifest_path)
        value = str(
            manifest.get("old_switch", {}).get("connection_address") or ""
        ).strip()
    if not value:
        value = str(
            approved_plan.get("template_variables", {}).get("management_ip") or ""
        ).strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ProvisioningError("approved migration has no valid post-cutover management IP")
    return value


def discovered_management_ip(migration_root, approved_plan=None):
    """Return the old EX4300 connection address that the EX4400 inherits post-cutover.

    Initial discovery records the exact address used to reach the source EX4300 in
    manifest.json.  That address is authoritative for post-cutover management and
    deliberately takes precedence over historical parsed vme/irb addresses in
    older analysis/plan artifacts.  The plan value remains a compatibility
    fallback for migrations created before the manifest carried connection_address.
    """
    manifest_path = migration_root / "manifest.json"
    value = ""
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        value = str(
            manifest.get("old_switch", {}).get("connection_address") or ""
        ).strip()
    if not value and approved_plan is not None:
        value = str(
            approved_plan.get("template_variables", {}).get("management_ip") or ""
        ).strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ProvisioningError(
            "migration has no valid old-switch discovery connection address for post-cutover management"
        )
    return value


def parse_ed25519_fingerprint(output):
    matches = []
    for line in str(output or "").splitlines():
        if "(ED25519)" not in line.upper():
            continue
        for token in line.split():
            if token.startswith("SHA256:"):
                matches.append(token)
    unique = sorted(set(matches))
    _require(len(unique) == 1, "lab probe did not return exactly one ED25519 SSH fingerprint")
    return unique[0]


def lab_probe_command(target, target_port, timeout_seconds):
    target_value = shlex.quote(str(target))
    port_value = int(target_port)
    timeout_value = int(timeout_seconds)
    return (
        "set -e; "
        "nc -z -w %d %s %d >/dev/null 2>&1; "
        "ssh-keyscan -T %d -p %d %s 2>/dev/null | ssh-keygen -lf - -E sha256"
        % (
            timeout_value,
            target_value,
            port_value,
            timeout_value,
            port_value,
            target_value,
        )
    )


def run_lab_probe(profile, management_ip, expected_fingerprint, password):
    validation = profile["inband_validation"]
    probe = validation["probe"]
    try:
        import paramiko
    except ImportError as exc:
        raise ProvisioningError("Paramiko is required for lab-probe validation: %s" % exc)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=str(probe["host"]),
            port=int(probe.get("port", 22)),
            username=str(probe["username"]),
            password=password,
            timeout=int(validation.get("timeout_seconds", 5)),
            banner_timeout=int(validation.get("timeout_seconds", 5)),
            auth_timeout=int(validation.get("timeout_seconds", 5)),
            look_for_keys=False,
            allow_agent=False,
        )
        command = lab_probe_command(
            management_ip,
            int(validation.get("target_port", 830)),
            int(validation.get("timeout_seconds", 5)),
        )
        _stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise ProvisioningError(
                "lab probe could not reach/identify %s:%s: %s"
                % (
                    management_ip,
                    validation.get("target_port", 830),
                    error.strip() or "remote probe command failed",
                )
            )
        observed = parse_ed25519_fingerprint(output)
    except ProvisioningError:
        raise
    except Exception as exc:
        raise ProvisioningError(
            "could not execute in-band validation through lab probe %s: %s"
            % (probe["host"], exc)
        )
    finally:
        try:
            client.close()
        except Exception:
            pass

    return {
        "method": "lab-probe",
        "probe": {
            "host": str(probe["host"]),
            "port": int(probe.get("port", 22)),
            "username": str(probe["username"]),
            "host_key_verification": str(probe["host_key_verification"]),
        },
        "target": {
            "management_ip": management_ip,
            "port": int(validation.get("target_port", 830)),
        },
        "tcp_reachable": True,
        "observed_ed25519_fingerprint": observed,
        "expected_ed25519_fingerprint": expected_fingerprint,
        "fingerprint_match": observed == expected_fingerprint,
        "result": "PASS" if observed == expected_fingerprint else "FAIL",
    }


def build_validation(
    migration_id,
    identity,
    identity_digest,
    qfx_transaction,
    qfx_transaction_digest,
    environment_profile,
    environment_profile_digest,
    approved_plan_digest,
    evidence,
    created_at=None,
):
    _require(evidence.get("result") == "PASS", "in-band management evidence did not pass")
    key = {
        "migration_id": migration_id,
        "identity_id": identity.get("identity_id"),
        "identity_digest": identity_digest,
        "qfx_transaction_id": qfx_transaction.get("transaction_id"),
        "qfx_transaction_digest": qfx_transaction_digest,
        "environment_profile_digest": environment_profile_digest,
        "approved_plan_digest": approved_plan_digest,
        "evidence": evidence,
    }
    validation_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "validation_id": validation_id,
        "migration_id": migration_id,
        "created_at": created_at or utc_now(),
        "inputs": {
            "identity_id": identity.get("identity_id"),
            "identity_digest": identity_digest,
            "qfx_transaction_id": qfx_transaction.get("transaction_id"),
            "qfx_transaction_digest": qfx_transaction_digest,
            "environment": environment_profile.get("environment"),
            "environment_profile_digest": environment_profile_digest,
            "approved_plan_digest": approved_plan_digest,
        },
        "evidence": evidence,
        "result": "PASS",
        "safety": {
            "read_only": True,
            "proves_inband_path_to_pinned_ssh_identity": True,
            "qfx_writes_authorized": False,
            "ex4400_writes_authorized": False,
        },
    }


def write_validation(migration_root, value):
    _require(value.get("result") == "PASS", "in-band management validation did not pass")
    destination = migration_root / "inband-validations" / value["validation_id"]
    path = destination / "validation.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(
            integrity.get("validation.json") == sha256_file(path),
            "in-band validation integrity check failed",
        )
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(value)
        comparable_existing.pop("created_at", None)
        comparable_new.pop("created_at", None)
        _require(
            comparable_existing == comparable_new,
            "existing in-band validation ID has different content",
        )
        return destination, existing, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {
        "validation.json": sha256_file(path),
    })
    return destination, value, "CREATED"
