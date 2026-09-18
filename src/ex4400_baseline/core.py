from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from xml.etree import ElementTree as ET


class BaselineError(RuntimeError):
    pass


_PHYSICAL_INTERFACE = re.compile(r"^(?:ge|xe|et)-\d+/\d+/\d+$", re.IGNORECASE)
_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")

INVENTORY_FIELDS = [
    "migration_id",
    "ex4300_ip",
    "ex4400_ip",
    "ex4400_mac",
    "ex4300_interface",
    "management_vlan_id",
    "management_network",
    "ex4400_hostname",
    "ex4400_model",
    "ex4400_serial",
    "ex4400_ssh_host_key_sha256",
    "baseline_template_sha256",
    "status",
    "updated_at",
    "last_error",
]


@dataclass(frozen=True)
class MacEntry:
    mac: str
    vlan_id: int
    interface: str


@dataclass(frozen=True)
class ArpEntry:
    mac: str
    ip: str
    interface: str = ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _localname(tag: str) -> str:
    return str(tag).split("}", 1)[-1]


def _child_text(element, names: Iterable[str]) -> str:
    wanted = set(names)
    for child in element.iter():
        if child is element:
            continue
        if _localname(child.tag) in wanted and child.text:
            return child.text.strip()
    return ""


def normalize_mac(value: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).lower()
    if not _MAC_HEX.fullmatch(raw):
        raise BaselineError("invalid MAC address %r" % value)
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def base_interface(value: str) -> str:
    return str(value or "").strip().split(".", 1)[0]


def parse_ethernet_switching_xml(xml) -> list[MacEntry]:
    entries: list[MacEntry] = []
    for element in xml.iter():
        name = _localname(element.tag)

        if name == "l2ng-l2ald-mac-entry-vlan":
            mac = _child_text(element, ("l2ng-l2-mac-address",))
            vlan = _child_text(element, ("l2ng-l2-vlan-id",))
            interface = _child_text(element, ("l2ng-l2-mac-logical-interface",))
        elif name == "mac-table-entry":
            mac = _child_text(element, ("mac-address",))
            vlan = _child_text(element, ("mac-vlan-tag",))
            interface = _child_text(element, ("mac-interface", "mac-interfaces"))
        else:
            continue

        if not (mac and vlan and interface):
            continue
        try:
            vlan_id = int(vlan)
            normalized = normalize_mac(mac)
        except (ValueError, BaselineError):
            continue
        entries.append(MacEntry(normalized, vlan_id, base_interface(interface)))

    deduped = {(item.mac, item.vlan_id, item.interface): item for item in entries}
    return sorted(
        deduped.values(),
        key=lambda item: (item.vlan_id, item.interface, item.mac),
    )


def select_local_mac(
    entries: Iterable[MacEntry],
    vlan_id: int,
    ignored_interfaces: Iterable[str],
    port_override: Optional[str] = None,
) -> MacEntry:
    ignored = {base_interface(item) for item in ignored_interfaces}
    override = base_interface(port_override) if port_override else None

    candidates = []
    for entry in entries:
        interface = base_interface(entry.interface)
        if entry.vlan_id != int(vlan_id):
            continue
        if interface in ignored:
            continue
        if override and interface != override:
            continue
        if not _PHYSICAL_INTERFACE.fullmatch(interface):
            continue
        candidates.append(MacEntry(entry.mac, entry.vlan_id, interface))

    unique = {(item.mac, item.interface): item for item in candidates}
    candidates = sorted(
        unique.values(),
        key=lambda item: (item.interface, item.mac),
    )

    if not candidates:
        if override:
            raise BaselineError(
                "no MAC was learned in management VLAN %s on source port %s"
                % (vlan_id, override)
            )
        raise BaselineError(
            "no locally learned physical-interface MAC was found in management VLAN %s"
            % vlan_id
        )

    if len(candidates) > 1:
        details = ", ".join(
            "%s on %s" % (item.mac, item.interface)
            for item in candidates
        )
        raise BaselineError(
            "multiple locally learned MACs were found in management VLAN %s: %s. "
            "Re-run with --port <interface>."
            % (vlan_id, details)
        )
    return candidates[0]


def parse_arp_xml(xml) -> list[ArpEntry]:
    entries: list[ArpEntry] = []
    for element in xml.iter():
        if _localname(element.tag) != "arp-table-entry":
            continue
        mac = _child_text(element, ("mac-address",))
        ip = _child_text(element, ("ip-address",))
        interface = _child_text(element, ("interface-name",))
        if not (mac and ip):
            continue
        try:
            normalized = normalize_mac(mac)
            parsed_ip = ipaddress.ip_address(ip)
        except (BaselineError, ValueError):
            continue
        if parsed_ip.version != 4:
            continue
        entries.append(
            ArpEntry(normalized, str(parsed_ip), interface)
        )

    deduped = {
        (item.mac, item.ip, item.interface): item
        for item in entries
    }
    return sorted(
        deduped.values(),
        key=lambda item: (item.mac, item.ip, item.interface),
    )


def find_arp_ip(
    entries: Iterable[ArpEntry],
    wanted_mac: str,
    network: Optional[str] = None,
) -> ArpEntry:
    mac = normalize_mac(wanted_mac)
    subnet = None
    if network:
        try:
            subnet = ipaddress.ip_network(str(network), strict=False)
        except ValueError as exc:
            raise BaselineError(
                "invalid management network %r: %s"
                % (network, exc)
            )
        if subnet.version != 4:
            raise BaselineError("management network must be IPv4")

    matches = []
    for entry in entries:
        if normalize_mac(entry.mac) != mac:
            continue
        addr = ipaddress.ip_address(entry.ip)
        if subnet is not None and addr not in subnet:
            continue
        matches.append(entry)

    unique = {
        (item.ip, item.interface): item
        for item in matches
    }
    matches = sorted(
        unique.values(),
        key=lambda item: (item.ip, item.interface),
    )

    if not matches:
        suffix = " inside %s" % subnet if subnet else ""
        raise BaselineError(
            "MAC %s was not present in the gateway ARP table%s"
            % (mac, suffix)
        )
    if len(matches) > 1:
        details = ", ".join(
            "%s%s"
            % (
                item.ip,
                " via %s" % item.interface
                if item.interface
                else "",
            )
            for item in matches
        )
        raise BaselineError(
            "MAC %s matched multiple ARP entries: %s"
            % (mac, details)
        )
    return matches[0]


def load_config(path: Path) -> dict:
    try:
        config = json.loads(
            path.read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        raise BaselineError(
            "configuration file not found: %s"
            % path
        )
    except json.JSONDecodeError as exc:
        raise BaselineError(
            "invalid JSON in %s: %s"
            % (path, exc)
        )

    if config.get("schema_version") != "1.0":
        raise BaselineError(
            "unsupported baseline configuration schema"
        )

    management = config.get("management")
    if not isinstance(management, dict):
        raise BaselineError(
            "management configuration is required"
        )

    vlan_id = management.get("vlan_id")
    if (
        not isinstance(vlan_id, int)
        or not 1 <= vlan_id <= 4094
    ):
        raise BaselineError(
            "management.vlan_id must be an integer "
            "from 1 through 4094"
        )

    network = management.get("network")
    if network:
        try:
            parsed = ipaddress.ip_network(
                str(network),
                strict=False,
            )
        except ValueError as exc:
            raise BaselineError(
                "management.network is invalid: %s"
                % exc
            )
        if parsed.version != 4:
            raise BaselineError(
                "management.network must be IPv4"
            )

    uplinks = management.get(
        "uplink_interfaces",
        ["ae0"],
    )
    if (
        not isinstance(uplinks, list)
        or not all(
            isinstance(x, str) and x.strip()
            for x in uplinks
        )
    ):
        raise BaselineError(
            "management.uplink_interfaces must be "
            "a non-empty string list"
        )

    gateway = config.get("gateway_router")
    if (
        not isinstance(gateway, dict)
        or not gateway.get("address")
    ):
        raise BaselineError(
            "gateway_router.address is required"
        )
    try:
        ipaddress.ip_address(
            str(gateway["address"])
        )
    except ValueError as exc:
        raise BaselineError(
            "gateway_router.address is invalid: %s"
            % exc
        )

    baseline = config.get("baseline")
    if (
        not isinstance(baseline, dict)
        or not baseline.get("config_file")
    ):
        raise BaselineError(
            "baseline.config_file is required"
        )

    fmt = str(
        baseline.get("format", "set")
    ).lower()
    if fmt not in ("set", "text"):
        raise BaselineError(
            "baseline.format must be 'set' or 'text'"
        )

    load_mode = str(
        baseline.get("load_mode", "merge")
    ).lower()
    if load_mode != "merge":
        raise BaselineError(
            "baseline.load_mode must be 'merge' "
            "for this utility"
        )

    inventory = config.setdefault(
        "inventory",
        {},
    )
    if not inventory.get("csv_file"):
        inventory["csv_file"] = (
            "data/ex4400_inventory.csv"
        )

    connection = config.setdefault(
        "connection",
        {},
    )
    netconf_port = int(
        connection.get("netconf_port", 830)
    )
    auto_probe = int(
        connection.get(
            "auto_probe_seconds",
            10,
        )
    )

    if not 1 <= netconf_port <= 65535:
        raise BaselineError(
            "connection.netconf_port is invalid"
        )
    if auto_probe < 0:
        raise BaselineError(
            "connection.auto_probe_seconds "
            "must be >= 0"
        )

    connection["netconf_port"] = netconf_port
    connection["auto_probe_seconds"] = auto_probe
    management["uplink_interfaces"] = uplinks
    baseline["format"] = fmt
    baseline["load_mode"] = load_mode
    return config


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)
    return digest.hexdigest()


def upsert_inventory(
    path: Path,
    record: dict,
) -> None:
    migration_id = str(
        record.get("migration_id") or ""
    ).strip()
    if not migration_id:
        raise BaselineError(
            "inventory record is missing migration_id"
        )

    rows = []
    if path.is_file():
        with path.open(
            newline="",
            encoding="utf-8",
        ) as handle:
            reader = csv.DictReader(handle)
            if (
                reader.fieldnames
                and "migration_id"
                not in reader.fieldnames
            ):
                raise BaselineError(
                    "existing inventory CSV has "
                    "no migration_id column"
                )
            rows = [
                dict(row)
                for row in reader
            ]

    normalized = {
        field: str(
            record.get(field, "") or ""
        )
        for field in INVENTORY_FIELDS
    }

    found = False
    output = []
    for row in rows:
        if (
            str(
                row.get("migration_id") or ""
            ).strip().lower()
            == migration_id.lower()
        ):
            if not found:
                output.append(normalized)
                found = True
            continue

        output.append(
            {
                field: str(
                    row.get(field, "") or ""
                )
                for field in INVENTORY_FIELDS
            }
        )

    if not found:
        output.append(normalized)

    output.sort(
        key=lambda row:
        row["migration_id"].lower()
    )
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary = tempfile.mkstemp(
        prefix=path.name + ".",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(
            fd,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=INVENTORY_FIELDS,
            )
            writer.writeheader()
            writer.writerows(output)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary,
            path,
        )
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except OSError:
            pass


def lookup_inventory(
    path: Path,
    migration_id: str,
    require_ready: bool = True,
) -> dict:
    if not path.is_file():
        raise BaselineError(
            "EX4400 inventory does not exist: %s"
            % path
        )

    wanted = str(
        migration_id
    ).strip().lower()

    with path.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        rows = list(
            csv.DictReader(handle)
        )

    matches = [
        row
        for row in rows
        if str(
            row.get("migration_id") or ""
        ).strip().lower()
        == wanted
    ]

    if len(matches) != 1:
        raise BaselineError(
            "expected exactly one inventory row "
            "for %s; found %s"
            % (
                migration_id,
                len(matches),
            )
        )

    row = matches[0]

    if (
        require_ready
        and row.get("status") != "READY"
    ):
        raise BaselineError(
            "EX4400 inventory row for %s is "
            "not READY (status=%s)"
            % (
                migration_id,
                row.get("status")
                or "UNKNOWN",
            )
        )

    if (
        require_ready
        and not row.get("ex4400_ip")
    ):
        raise BaselineError(
            "READY inventory row for %s "
            "has no ex4400_ip"
            % migration_id
        )

    return row


def xml_from_string(text: str):
    return ET.fromstring(text)
