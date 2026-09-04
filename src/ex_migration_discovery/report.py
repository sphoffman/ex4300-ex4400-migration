from __future__ import annotations

from collections import defaultdict

from .model import Snapshot


def render_report(snapshot: Snapshot) -> str:
    physical = [m for m in snapshot.mac_observations if m.interface_class == "physical_access"]
    excluded = [m for m in snapshot.mac_observations if m.interface_class != "physical_access"]
    by_port: dict[str, list] = defaultdict(list)
    for observation in physical:
        by_port[observation.physical_interface].append(observation)

    lines = [
        f"# Migration discovery report: {snapshot.device.hostname or snapshot.snapshot_id}",
        "",
        f"- Snapshot: `{snapshot.snapshot_id}`",
        f"- Schema: `{snapshot.schema_version}`",
        f"- Lifecycle: `{snapshot.lifecycle}`",
        f"- Collection: {snapshot.started_at} through {snapshot.completed_at}",
        f"- Model/version: {snapshot.device.model or 'unknown'} / {snapshot.device.junos_version or 'unknown'}",
        f"- Voice VLAN: {voice_summary(snapshot)}",
        f"- MAC observations: {len(snapshot.mac_observations)}",
        f"- Access-port MAC observations: {len(physical)}",
        f"- Non-access observations excluded from correlation: {len(excluded)}",
        "",
        "## Port observation summary",
        "",
        "| Interface | Unique MACs | Data VLANs | Voice VLAN observed | Description | Disposition |",
        "|---|---:|---|---|---|---|",
    ]
    voice_id = snapshot.voice_policy.vlan_id
    interface_map = {i.physical_name: i for i in snapshot.interfaces}
    all_access = sorted(set(by_port) | {name for name, state in interface_map.items() if state.effective_mode == "access"})
    for port in all_access:
        observations = by_port.get(port, [])
        macs = sorted({m.mac for m in observations})
        data_vlans = sorted({m.vlan.vlan_id for m in observations if m.vlan.vlan_id != voice_id})
        voice_seen = any(m.vlan.vlan_id == voice_id for m in observations)
        state = interface_map.get(port)
        description = (state.description if state else None) or ""
        disposition = "OBSERVED" if macs else "CONFIGURED_NO_MAC"
        lines.append(
            f"| `{port}` | {len(macs)} | {', '.join(map(str, data_vlans)) or '-'} | "
            f"{'yes' if voice_seen else 'no'} | {description} | `{disposition}` |"
        )

    lines.extend(["", "## Warnings", ""])
    if snapshot.warnings:
        lines.extend(f"- {warning}" for warning in snapshot.warnings)
    else:
        lines.append("- None")
    if snapshot.errors:
        lines.extend(["", "## Collection errors or unsupported commands", ""])
        lines.extend(f"- `{e.get('command', 'unknown')}`: {e.get('error', 'unknown error')}" for e in snapshot.errors)
    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "MAC OUIs are not used to infer endpoint vendor or device type. Voice association is based on the configured voice VLAN and protocol evidence.",
        "",
    ])
    return "\n".join(lines)


def voice_summary(snapshot: Snapshot) -> str:
    policy = snapshot.voice_policy
    if not policy.configured:
        return "not configured"
    if not policy.valid:
        return f"invalid ({policy.vlan_name or 'unknown'})"
    return f"{policy.vlan_name} ({policy.vlan_id})"

