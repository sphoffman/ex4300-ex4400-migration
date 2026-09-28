from __future__ import annotations

import re

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from ex_migration_discovery.parsers import parse_mac_table_text

from .core import ProvisioningError


SCHEMA_VERSION = "1.0"
_SOURCE_KINDS = {"LIVE", "SIMULATED"}
_PHYSICAL = re.compile(
    r"^(?P<name>(?:ge|xe|et)-\d+/\d+/\d+)\s+"
    r"(?P<admin>up|down)\s+(?P<oper>up|down)(?:\s|$)"
)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SSH_SHA256 = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _normalize_text(value):
    text = str(value or "")
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def _physical_interfaces(terse_text):
    values = {}
    for raw in str(terse_text or "").splitlines():
        match = _PHYSICAL.match(raw.strip())
        if not match:
            continue
        name = match.group("name")
        current = {
            "interface": name,
            "admin_status": match.group("admin"),
            "oper_status": match.group("oper"),
        }
        previous = values.get(name)
        _require(
            previous is None or previous == current,
            "EX4400 terse output contains conflicting state for %s" % name,
        )
        values[name] = current
    return [values[name] for name in sorted(values)]


def _mac_observations(mac_table_text, observed_at):
    values = []
    for item in parse_mac_table_text(
        mac_table_text or "",
        observed_at,
        "post-cutover-ex4400-observation",
    ):
        values.append({
            "observed_at": str(getattr(item, "observed_at", None) or observed_at or ""),
            "mac": item.mac,
            "routing_instance": item.routing_instance,
            "vlan": {
                "name": item.vlan.name,
                "vlan_id": item.vlan.vlan_id,
            },
            "reported_interface": item.reported_interface,
            "physical_interface": item.physical_interface,
            "unit": item.unit,
            "interface_class": item.interface_class,
            "mac_type": item.mac_type,
        })
    return sorted(
        values,
        key=lambda row: (
            str(row.get("physical_interface") or ""),
            str(row.get("mac") or ""),
            -1 if row.get("vlan", {}).get("vlan_id") is None
            else int(row["vlan"]["vlan_id"]),
            str(row.get("routing_instance") or ""),
        ),
    )


def _device_identity(current_identity):
    device = dict((current_identity or {}).get("device") or {})
    connection = dict((current_identity or {}).get("connection") or {})
    members = []
    for item in device.get("members") or []:
        members.append({
            "member_id": int(item["member_id"]),
            "status": item.get("status"),
            "serial_number": str(item.get("serial_number") or ""),
            "model": str(item.get("model") or ""),
        })
    members.sort(key=lambda item: item["member_id"])
    return {
        "hostname": str(device.get("hostname") or ""),
        "model": str(device.get("model") or ""),
        "serial_number": str(device.get("serial_number") or ""),
        "members": members,
        "ssh_host_key_sha256": str(connection.get("ssh_host_key_sha256") or ""),
    }


def _artifact_digests(value):
    result = {}
    for item in value.get("raw_artifacts") or []:
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "")
        _require(name and name not in result, "post-cutover observation has duplicate raw artifact metadata")
        _require(_HEX_64.fullmatch(digest) is not None, "post-cutover observation has invalid raw artifact digest")
        result[name] = digest
    return result


def validate_postcutover_observation(
    value,
    migration_id=None,
    approved_plan_digest=None,
    identity_digest=None,
    package_digest=None,
):
    _require(isinstance(value, dict), "post-cutover observation must be an object")
    _require(
        value.get("schema_version") == SCHEMA_VERSION,
        "unsupported post-cutover observation schema",
    )
    _require(str(value.get("observation_id") or ""), "post-cutover observation ID is required")
    _require(str(value.get("migration_id") or ""), "post-cutover observation migration ID is required")
    _require(value.get("source", {}).get("kind") in _SOURCE_KINDS, "invalid post-cutover observation source")
    _require(value.get("validation", {}).get("result") == "PASS", "post-cutover observation did not pass validation")

    inputs = value.get("inputs") or {}
    for name in ("approved_plan", "bootstrap_identity", "prestage_package"):
        item = inputs.get(name)
        _require(isinstance(item, dict), "post-cutover observation is missing %s binding" % name)
        _require(str(item.get("id") or ""), "post-cutover observation %s ID is required" % name)
        _require(
            _HEX_64.fullmatch(str(item.get("digest") or "")) is not None,
            "post-cutover observation %s digest is invalid" % name,
        )

    device = value.get("device") or {}
    _require(str(device.get("hostname") or ""), "post-cutover observation hostname is required")
    _require(str(device.get("model") or ""), "post-cutover observation model is required")
    _require(
        _SSH_SHA256.fullmatch(str(device.get("ssh_host_key_sha256") or "")) is not None,
        "post-cutover observation SSH host-key fingerprint is invalid",
    )

    artifacts = _artifact_digests(value)
    _require(
        set(artifacts) == {"mac-table.txt", "interfaces-terse.txt"},
        "post-cutover observation must bind exactly the MAC-table and interface-terse artifacts",
    )

    interfaces = value.get("interfaces")
    macs = value.get("mac_observations")
    _require(isinstance(interfaces, list), "post-cutover observation interfaces must be a list")
    _require(isinstance(macs, list), "post-cutover observation MAC observations must be a list")

    stats = value.get("statistics") or {}
    dynamic_rows = [row for row in macs if row.get("mac_type") == "dynamic"]
    dynamic_macs = {str(row.get("mac") or "") for row in dynamic_rows if row.get("mac")}
    dynamic_ports = {
        str(row.get("physical_interface") or "")
        for row in dynamic_rows
        if row.get("physical_interface")
    }
    _require(
        int(stats.get("physical_interfaces_observed", -1)) == len(interfaces),
        "post-cutover observation physical-interface statistics do not match payload",
    )
    _require(
        int(stats.get("dynamic_mac_observations", -1)) == len(dynamic_rows),
        "post-cutover observation dynamic-MAC statistics do not match payload",
    )
    _require(
        int(stats.get("unique_dynamic_macs", -1)) == len(dynamic_macs),
        "post-cutover observation unique dynamic-MAC statistics do not match payload",
    )
    _require(
        int(stats.get("dynamic_mac_interfaces", -1)) == len(dynamic_ports),
        "post-cutover observation dynamic-MAC interface statistics do not match payload",
    )

    if migration_id is not None:
        _require(value.get("migration_id") == migration_id, "post-cutover observation migration ID mismatch")
    if approved_plan_digest is not None:
        _require(
            inputs["approved_plan"].get("digest") == approved_plan_digest,
            "post-cutover observation is bound to a different approved migration plan",
        )
    if identity_digest is not None:
        _require(
            inputs["bootstrap_identity"].get("digest") == identity_digest,
            "post-cutover observation is bound to a different EX4400 identity",
        )
    if package_digest is not None:
        _require(
            inputs["prestage_package"].get("digest") == package_digest,
            "post-cutover observation is bound to a different pre-stage package",
        )
    return value


def build_postcutover_observation(
    migration_id,
    approved_plan,
    approved_plan_digest,
    identity,
    identity_digest,
    package,
    package_digest,
    access,
    current_identity,
    mac_table_text,
    terse_text,
    source_kind="LIVE",
    started_at=None,
    completed_at=None,
):
    source = str(source_kind or "").upper()
    _require(source in _SOURCE_KINDS, "invalid post-cutover observation source")
    started = started_at or utc_now()
    completed = completed_at or utc_now()
    normalized_mac = _normalize_text(mac_table_text)
    normalized_terse = _normalize_text(terse_text)
    mac_digest = sha256_bytes(normalized_mac.encode("utf-8"))
    terse_digest = sha256_bytes(normalized_terse.encode("utf-8"))
    interfaces = _physical_interfaces(normalized_terse)
    macs = _mac_observations(normalized_mac, completed)
    dynamic_rows = [row for row in macs if row.get("mac_type") == "dynamic"]
    dynamic_macs = {row["mac"] for row in dynamic_rows}
    dynamic_ports = {
        row["physical_interface"]
        for row in dynamic_rows
        if row.get("physical_interface")
    }
    device = _device_identity(current_identity)

    inputs = {
        "approved_plan": {
            "id": str(approved_plan.get("plan_id") or ""),
            "digest": str(approved_plan_digest),
        },
        "bootstrap_identity": {
            "id": str(identity.get("identity_id") or ""),
            "digest": str(identity_digest),
        },
        "prestage_package": {
            "id": str(package.get("package_id") or ""),
            "digest": str(package_digest),
        },
    }
    raw_artifacts = [
        {"name": "interfaces-terse.txt", "sha256": terse_digest},
        {"name": "mac-table.txt", "sha256": mac_digest},
    ]
    key = {
        "migration_id": migration_id,
        "completed_at": completed,
        "source": source,
        "inputs": inputs,
        "device": device,
        "raw_artifacts": raw_artifacts,
    }
    observation_id = sha256_bytes(canonical_bytes(key))[:16]
    value = {
        "schema_version": SCHEMA_VERSION,
        "observation_id": observation_id,
        "migration_id": migration_id,
        "started_at": started,
        "completed_at": completed,
        "source": {"kind": source},
        "inputs": inputs,
        "device": device,
        "access": {
            "environment": access.get("environment"),
            "mode": access.get("mode"),
            "logical_address": access.get("logical_address"),
            "transport_address": access.get("transport_address"),
            "port": int(access.get("port", 830)),
        },
        "interfaces": interfaces,
        "mac_observations": macs,
        "raw_artifacts": raw_artifacts,
        "statistics": {
            "physical_interfaces_observed": len(interfaces),
            "physical_interfaces_up": sum(
                1 for row in interfaces
                if row["admin_status"] == "up" and row["oper_status"] == "up"
            ),
            "dynamic_mac_observations": len(dynamic_rows),
            "unique_dynamic_macs": len(dynamic_macs),
            "dynamic_mac_interfaces": len(dynamic_ports),
        },
        "validation": {
            "result": "PASS",
            "checks": [
                "APPROVED_PLAN_BOUND",
                "EX4400_IDENTITY_BOUND",
                "PRESTAGE_PACKAGE_BOUND",
                "RAW_ARTIFACT_DIGESTS_BOUND",
                "MAC_TABLE_PARSED",
                "INTERFACE_TERSE_PARSED",
            ],
        },
    }
    validate_postcutover_observation(value)
    return value


def collect_live_postcutover_observation(
    dev,
    migration_id,
    approved_plan,
    approved_plan_digest,
    identity,
    identity_digest,
    package,
    package_digest,
    access,
    current_identity,
):
    started = utc_now()
    mac_text = _normalize_text(
        dev.cli("show ethernet-switching table extensive", warning=False) or ""
    )
    terse_text = _normalize_text(
        dev.cli("show interfaces terse", warning=False) or ""
    )
    completed = utc_now()
    value = build_postcutover_observation(
        migration_id,
        approved_plan,
        approved_plan_digest,
        identity,
        identity_digest,
        package,
        package_digest,
        access,
        current_identity,
        mac_text,
        terse_text,
        source_kind="LIVE",
        started_at=started,
        completed_at=completed,
    )
    return value, mac_text, terse_text


def write_postcutover_observation(migration_root, value, mac_table_text, terse_text):
    validate_postcutover_observation(value, migration_id=migration_root.name)
    normalized_mac = _normalize_text(mac_table_text)
    normalized_terse = _normalize_text(terse_text)
    expected = _artifact_digests(value)
    _require(
        sha256_bytes(normalized_mac.encode("utf-8")) == expected["mac-table.txt"],
        "post-cutover observation MAC-table content does not match bound digest",
    )
    _require(
        sha256_bytes(normalized_terse.encode("utf-8")) == expected["interfaces-terse.txt"],
        "post-cutover observation interface-terse content does not match bound digest",
    )

    destination = (
        migration_root
        / "new-switch"
        / "postcutover-observations"
        / value["observation_id"]
    )
    record = destination / "observation.json"
    mac_path = destination / "mac-table.txt"
    terse_path = destination / "interfaces-terse.txt"

    if record.is_file():
        loaded = load_postcutover_observation(
            migration_root,
            value["observation_id"],
            approved_plan_digest=value["inputs"]["approved_plan"]["digest"],
            identity_digest=value["inputs"]["bootstrap_identity"]["digest"],
            package_digest=value["inputs"]["prestage_package"]["digest"],
        )
        comparable_existing = dict(loaded["observation"])
        comparable_new = dict(value)
        comparable_existing.pop("started_at", None)
        comparable_new.pop("started_at", None)
        _require(
            comparable_existing == comparable_new,
            "existing post-cutover observation ID has different content",
        )
        _require(
            loaded["mac_table_text"] == normalized_mac,
            "existing post-cutover observation MAC-table evidence changed",
        )
        _require(
            loaded["terse_text"] == normalized_terse,
            "existing post-cutover observation interface-terse evidence changed",
        )
        return destination, loaded["observation"], "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    mac_path.write_text(normalized_mac, encoding="utf-8")
    terse_path.write_text(normalized_terse, encoding="utf-8")
    atomic_json(record, value)
    atomic_json(destination / "integrity.json", {
        "observation.json": sha256_file(record),
        "mac-table.txt": sha256_file(mac_path),
        "interfaces-terse.txt": sha256_file(terse_path),
    })
    return destination, value, "CREATED"


def load_postcutover_observation(
    migration_root,
    observation_id,
    approved_plan_digest=None,
    identity_digest=None,
    package_digest=None,
):
    destination = (
        migration_root
        / "new-switch"
        / "postcutover-observations"
        / str(observation_id)
    )
    record = destination / "observation.json"
    integrity_path = destination / "integrity.json"
    mac_path = destination / "mac-table.txt"
    terse_path = destination / "interfaces-terse.txt"
    _require(record.is_file(), "post-cutover observation %s was not found" % observation_id)
    _require(integrity_path.is_file(), "post-cutover observation integrity record is missing")
    _require(mac_path.is_file(), "post-cutover observation MAC-table evidence is missing")
    _require(terse_path.is_file(), "post-cutover observation interface-terse evidence is missing")

    integrity = read_json(integrity_path)
    for name, path in (
        ("observation.json", record),
        ("mac-table.txt", mac_path),
        ("interfaces-terse.txt", terse_path),
    ):
        _require(
            integrity.get(name) == sha256_file(path),
            "post-cutover observation integrity failed for %s" % name,
        )

    value = read_json(record)
    validate_postcutover_observation(
        value,
        migration_id=migration_root.name,
        approved_plan_digest=approved_plan_digest,
        identity_digest=identity_digest,
        package_digest=package_digest,
    )
    artifacts = _artifact_digests(value)
    _require(
        artifacts["mac-table.txt"] == sha256_file(mac_path),
        "post-cutover observation bound MAC-table digest does not match persisted evidence",
    )
    _require(
        artifacts["interfaces-terse.txt"] == sha256_file(terse_path),
        "post-cutover observation bound interface-terse digest does not match persisted evidence",
    )
    return {
        "directory": destination,
        "observation": value,
        "observation_path": record,
        "observation_digest": sha256_file(record),
        "mac_table_text": mac_path.read_text(encoding="utf-8"),
        "terse_text": terse_path.read_text(encoding="utf-8"),
    }
