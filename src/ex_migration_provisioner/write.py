from __future__ import annotations

import base64
import hashlib
import re
import shlex
import socket

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes

from .core import ProvisioningError


class WriteError(ProvisioningError):
    pass


def _require(condition, message):
    if not condition:
        raise WriteError(message)


_EX4400_MODEL = re.compile(r"^EX4400(?:-|$)", re.IGNORECASE)
_VJUNOS_SWITCH_MODEL = re.compile(r"^(?:VJUNOS-SWITCH|EX9214)$", re.IGNORECASE)
_VC_MEMBER = re.compile(
    r"^\s*(\d+)(?:\s+\(FPC\s+\d+\))?\s+"
    r"(Prsnt|NotPrsnt|Unprvsnd)\s+(\S+)\s+(\S+)(?:\s+|$)",
    re.IGNORECASE,
)
_MGMT_DEFAULT = re.compile(
    r"^set routing-instances mgmt_junos routing-options static route "
    r"(?:0\.0\.0\.0/0|default) next-hop (\S+)$"
)


def _allowed_target_model(model, allow_vjunos_switch=False):
    value = str(model or "")
    if _EX4400_MODEL.match(value):
        return True
    return bool(allow_vjunos_switch and _VJUNOS_SWITCH_MODEL.match(value))


def ssh_host_key_fingerprint(host, port=830, timeout=10):
    """Return the SSH server key as an OpenSSH-style SHA256 fingerprint."""
    try:
        import paramiko
    except ImportError as exc:
        raise WriteError(
            "Paramiko is required for SSH host-key fingerprinting: %s" % exc
        )

    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception as exc:
        raise WriteError(
            "could not read SSH host key from %s:%s: %s" % (host, port, exc)
        )
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def parse_virtual_chassis_status(text):
    members = []
    seen = set()
    for line in (text or "").splitlines():
        match = _VC_MEMBER.match(line)
        if not match:
            continue
        member_id = int(match.group(1))
        if member_id in seen:
            raise WriteError(
                "duplicate member %s in virtual-chassis status" % member_id
            )
        seen.add(member_id)
        members.append({
            "member_id": member_id,
            "status": match.group(2),
            "serial_number": match.group(3),
            "model": match.group(4),
        })
    return sorted(members, key=lambda item: item["member_id"])


def parse_mgmt_junos_default_gateway(text):
    """Return the single configured mgmt_junos IPv4 default-route next hop."""
    gateways = []
    for raw in str(text or "").splitlines():
        match = _MGMT_DEFAULT.match(raw.strip())
        if match:
            gateways.append(match.group(1))
    gateways = sorted(set(gateways))
    _require(
        len(gateways) == 1,
        "mgmt_junos must contain exactly one configured IPv4 default next-hop; observed %s"
        % (", ".join(gateways) if gateways else "none"),
    )
    return gateways[0]


def observe_ex4400_identity(
    dev,
    address,
    port,
    host_key_sha256,
    allow_vjunos_switch=False,
):
    facts = getattr(dev, "facts", {}) or {}
    hostname = str(facts.get("hostname") or "")
    model = str(facts.get("model") or "")
    serial = str(facts.get("serialnumber") or "")
    vc_text = dev.cli("show virtual-chassis status", warning=False)
    members = parse_virtual_chassis_status(vc_text)

    # A standalone VC-capable target can have sparse command output on some
    # releases. Top-level PyEZ facts are sufficient only for the single-member
    # fallback; a multi-member bootstrap still fails closed on count mismatch.
    if not members and serial and model:
        members = [{
            "member_id": 0,
            "status": "Prsnt",
            "serial_number": serial,
            "model": model,
        }]

    _require(hostname, "EX4400 bootstrap hostname could not be observed")
    _require(model, "EX4400 model could not be observed")
    _require(
        _allowed_target_model(model, allow_vjunos_switch),
        "bootstrap target model %r is not an EX4400-compatible target" % model,
    )
    _require(
        host_key_sha256 and host_key_sha256.startswith("SHA256:"),
        "SSH host-key fingerprint is invalid",
    )
    _require(
        members,
        "EX4400 virtual-chassis member inventory could not be observed",
    )
    _require(
        all(
            _allowed_target_model(item.get("model"), allow_vjunos_switch)
            for item in members
        ),
        "virtual-chassis member model is not an EX4400-compatible target",
    )

    return {
        "connection": {
            "address": str(address),
            "port": int(port),
            "ssh_host_key_sha256": host_key_sha256,
        },
        "device": {
            "hostname": hostname,
            "model": model,
            "serial_number": serial or members[0]["serial_number"],
            "members": members,
        },
    }


def _member_identity(members):
    return [
        {
            "member_id": int(item["member_id"]),
            "serial_number": str(item["serial_number"]),
            "model": str(item["model"]),
        }
        for item in sorted(
            members,
            key=lambda value: int(value["member_id"]),
        )
    ]


def build_bootstrap_identity(
    migration_id,
    bootstrap,
    bootstrap_profile_digest,
    observed,
    approved_at,
):
    _require(
        bootstrap.get("schema_version") == "1.0",
        "unsupported bootstrap profile schema",
    )
    environment = str(bootstrap.get("environment") or "")
    _require(
        environment in ("lab", "production"),
        "bootstrap profile environment must be lab or production",
    )

    connection = observed.get("connection", {})
    address = str(connection.get("address") or "")
    _require(address, "observed EX4400 OOB connection address is missing")
    allow_vjunos_switch = environment == "lab"

    oob = observed.get("oob_management", {})
    _require(
        str(oob.get("routing_instance") or "") == "mgmt_junos",
        "observed OOB management must use mgmt_junos",
    )
    _require(str(oob.get("address") or ""), "observed OOB management address is missing")
    _require(
        str(oob.get("default_gateway") or ""),
        "observed mgmt_junos default gateway is missing",
    )

    device = observed.get("device", {})
    _require(
        _allowed_target_model(device.get("model"), allow_vjunos_switch),
        "observed target model is not valid for this bootstrap environment",
    )

    vc = bootstrap.get("virtual_chassis", {})
    expected_count = int(vc.get("member_count", 0))
    members = device.get("members", [])
    _require(
        expected_count >= 1,
        "bootstrap profile has invalid virtual-chassis member count",
    )
    _require(
        len(members) == expected_count,
        (
            "observed EX4400 member count %s does not match bootstrap member count %s"
            % (len(members), expected_count)
        ),
    )
    _require(
        all(str(item.get("status", "")).lower() == "prsnt" for item in members),
        "every EX4400 virtual-chassis member must be present before identity binding",
    )
    _require(
        all(
            _allowed_target_model(item.get("model"), allow_vjunos_switch)
            for item in members
        ),
        "every observed virtual-chassis member must match the allowed target platform",
    )

    if any(
        _VJUNOS_SWITCH_MODEL.match(str(item.get("model", "")))
        for item in members
    ):
        _require(
            environment == "lab",
            "vJunos EX9214 identity is permitted only by a lab bootstrap profile",
        )
        _require(
            expected_count == 1,
            "vJunos-switch identity binding supports only a single-member lab target",
        )

    declared = vc.get("members") or []
    if declared:
        _require(
            len(declared) == expected_count,
            "bootstrap profile member inventory is incomplete",
        )
        expected = sorted(
            [
                (int(item["member_id"]), str(item["serial_number"]))
                for item in declared
            ],
            key=lambda value: value[0],
        )
        actual = sorted(
            [
                (int(item["member_id"]), str(item["serial_number"]))
                for item in members
            ],
            key=lambda value: value[0],
        )
        _require(
            actual == expected,
            "observed EX4400 member serials do not match bootstrap profile",
        )

    key = {
        "migration_id": migration_id,
        "bootstrap_profile_digest": bootstrap_profile_digest,
        "observed": observed,
    }
    identity_id = sha256_bytes(canonical_bytes(key))[:16]
    production_eligible = bool(
        environment == "production" and bootstrap.get("production_eligible") is True
    )
    return {
        "schema_version": "1.1",
        "identity_id": identity_id,
        "migration_id": migration_id,
        "approved_at": approved_at,
        "bootstrap": {
            "profile_id": bootstrap["profile_id"],
            "profile_digest": bootstrap_profile_digest,
            "provisioning_mode": bootstrap["provisioning_mode"],
        },
        "observed": observed,
        "approval": {
            "method": "interactive-operator-binding",
            "approved": True,
        },
        "eligibility": {
            "status": "PRODUCTION_ELIGIBLE" if production_eligible else "LAB_ONLY",
            "production_eligible": production_eligible,
            "reason": (
                "bootstrap identity was operator-bound under a production-eligible profile"
                if production_eligible
                else "bootstrap identity was operator-bound under a non-production profile"
            ),
        },
    }


def validate_bound_identity(
    current,
    identity,
    bootstrap_profile_digest,
    expected_hostname=None,
):
    _require(
        identity.get("schema_version") in ("1.0", "1.1"),
        "unsupported bootstrap identity schema",
    )
    _require(
        identity.get("bootstrap", {}).get("profile_digest")
        == bootstrap_profile_digest,
        "bootstrap identity is stale: bootstrap profile digest changed",
    )
    _require(
        identity.get("approval", {}).get("approved") is True,
        "bootstrap identity is not operator approved",
    )

    bound = identity.get("observed", {})
    bound_connection = bound.get("connection", {})
    current_connection = current.get("connection", {})
    _require(
        current_connection.get("address") == bound_connection.get("address"),
        "EX4400 OOB address changed",
    )
    _require(
        int(current_connection.get("port", -1))
        == int(bound_connection.get("port", -2)),
        "EX4400 bootstrap port changed",
    )
    _require(
        current_connection.get("ssh_host_key_sha256")
        == bound_connection.get("ssh_host_key_sha256"),
        "EX4400 SSH host key does not match the approved bootstrap identity",
    )

    bound_device = bound.get("device", {})
    current_device = current.get("device", {})
    wanted_hostname = (
        expected_hostname
        if expected_hostname is not None
        else bound_device.get("hostname")
    )
    _require(
        current_device.get("hostname") == wanted_hostname,
        (
            "EX4400 hostname %r does not match expected %r"
            % (current_device.get("hostname"), wanted_hostname)
        ),
    )
    _require(
        str(current_device.get("model", "")).lower()
        == str(bound_device.get("model", "")).lower(),
        "EX4400 model does not match the approved bootstrap identity",
    )
    _require(
        _member_identity(current_device.get("members", []))
        == _member_identity(bound_device.get("members", [])),
        "EX4400 virtual-chassis serial/model identity changed",
    )
    return True


def render_statements(rendered):
    return [
        line.strip()
        for line in (rendered or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _canonical_statement(line):
    value = line.strip()
    if not value:
        return value
    try:
        return " ".join(shlex.split(value, comments=False, posix=True))
    except ValueError:
        return value


# Post-commit validation deliberately checks the migration-critical semantic
# footprint instead of requiring every rendered boilerplate line to round-trip
# textually through Junos.  Commit check plus operator approval already bind the
# exact candidate diff.  Some platform/release-specific statements (for example
# GRES/NSR/NSB and `set version`) can be accepted at commit time yet be omitted or
# normalized differently by `display set`, especially on vJunos.  Those should not
# force rollback of an otherwise correct pre-stage configuration.
_POST_COMMIT_REQUIRED_PREFIXES = (
    "set system host-name ",
    "set system services netconf ssh",
    "set system management-instance",
    "set system syslog source-address ",
    "set system ntp source-address ",
    "set chassis aggregated-devices ethernet device-count ",
    "set interfaces ",
    "set snmp ",
    "set forwarding-options storm-control-profiles ",
    "set routing-options static route ",
    "set protocols lldp ",
    "set protocols lldp-med ",
    "set protocols igmp-snooping ",
    "set protocols rstp ",
    "set switch-options ",
    "set vlans ",
)


def _post_commit_required_statements(rendered):
    required = set()
    for line in render_statements(rendered):
        canonical = _canonical_statement(line)
        if any(
            canonical == prefix.rstrip() or canonical.startswith(prefix)
            for prefix in _POST_COMMIT_REQUIRED_PREFIXES
        ):
            required.add(canonical)
    return required


def validate_running_config(rendered, running_set):
    wanted = _post_commit_required_statements(rendered)
    actual = {
        _canonical_statement(line)
        for line in (running_set or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = sorted(wanted - actual)
    _require(
        not missing,
        "post-commit configuration is missing migration-critical statements: %s"
        % "; ".join(missing),
    )
    return {
        "result": "PASS",
        "checks": [
            "BOOTSTRAP_IDENTITY_MATCHES",
            "MIGRATION_CRITICAL_CONFIG_PRESENT",
        ],
    }
