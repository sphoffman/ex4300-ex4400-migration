from __future__ import annotations
from collections import defaultdict
from .model import Snapshot

def render_report(snapshot:Snapshot)->str:
 physical=[m for m in snapshot.mac_observations if m.interface_class=="physical_access"]; excluded=[m for m in snapshot.mac_observations if m.interface_class!="physical_access"]; by_port=defaultdict(list)
 for observation in physical: by_port[observation.physical_interface].append(observation)
 mgmt=snapshot.management
 lines=[f"# Migration discovery report: {snapshot.device.hostname or snapshot.snapshot_id}","",f"- Snapshot: `{snapshot.snapshot_id}`",f"- Migration ID: `{snapshot.migration_id}`",f"- Proposed hostname: `{snapshot.device.proposed_hostname or 'unresolved'}`",f"- Schema: `{snapshot.schema_version}`",f"- Lifecycle: `{snapshot.lifecycle}`",f"- Collection: {snapshot.started_at} through {snapshot.completed_at}",f"- Model/version: {snapshot.device.model or 'unknown'} / {snapshot.device.junos_version or 'unknown'}",f"- Voice VLAN: {voice_summary(snapshot)}",f"- MAC observations: {len(snapshot.mac_observations)}",f"- Access-port MAC observations: {len(physical)}",f"- Non-access observations excluded from correlation: {len(excluded)}","","## Management profile","",f"- Policy VLAN: `{mgmt.policy_vlan_id}`",f"- Discovered VLAN: `{mgmt.vlan_name or 'unresolved'}` / `{mgmt.vlan_id if mgmt.vlan_id is not None else 'unresolved'}`",f"- Production interface/address: `{mgmt.l3_interface or 'unresolved'}` / `{', '.join(mgmt.addresses) or 'unresolved'}`",f"- Production default gateway: `{mgmt.default_gateway or 'unresolved'}`",f"- Collector connection address: `{mgmt.connection_address or 'unknown'}`",f"- SNMP name: `{mgmt.snmp.name or 'not configured'}`",f"- SNMP name uses hostname: `{mgmt.snmp.name_uses_hostname}`",f"- SNMP location: `{mgmt.snmp.location or 'not configured'}`",f"- SNMP engine ID: `{mgmt.snmp.engine_id or 'not configured'}`",f"- SNMPv3 configured: `{mgmt.snmp.v3_configured if mgmt.snmp.v3_configured is not None else 'unknown'}`",f"- Consistency: **{mgmt.consistency}**",""]
 if mgmt.findings: lines += ["### Management findings",""]+[f"- {x}" for x in mgmt.findings]+[""]
 lines += ["## VLAN inventory","","| VLAN | ID | Description | IRB | Observed MACs | Purpose |","|---|---:|---|---|---:|---|"]
 for vlan in sorted(snapshot.vlans,key=lambda x:(x.vlan_id is None,x.vlan_id or 0,x.name)):
  lines.append(f"| {vlan.name} | {vlan.vlan_id if vlan.vlan_id is not None else ''} | {vlan.description or ''} | {vlan.irb_interface or ''} | {vlan.observed_mac_count} | {vlan.purpose or ''} |")
 lines += ["","## Port observation summary","","| Interface | Unique MACs | Data VLANs | Voice VLAN observed | Description | Disposition |","|---|---:|---|---|---|---|"]
 voice_id=snapshot.voice_policy.vlan_id; interface_map={i.physical_name:i for i in snapshot.interfaces}; all_access=sorted(set(by_port)|{name for name,state in interface_map.items() if state.effective_mode=="access"})
 for port in all_access:
  observations=by_port.get(port,[]); macs=sorted({m.mac for m in observations}); data_vlans=sorted({m.vlan.vlan_id for m in observations if m.vlan.vlan_id!=voice_id}); voice_seen=any(m.vlan.vlan_id==voice_id for m in observations); state=interface_map.get(port); disposition="OBSERVED" if macs else "SILENT"
  lines.append(f"| {port} | {len(macs)} | {', '.join(str(x) for x in data_vlans)} | {'yes' if voice_seen else 'no'} | {(state.description if state else '') or ''} | {disposition} |")
 return "\n".join(lines)+"\n"

def voice_summary(snapshot:Snapshot)->str:
 voice=snapshot.voice_policy
 if not voice.configured:return "not configured"
 if voice.valid:return f"{voice.vlan_name} ({voice.vlan_id})"
 return f"invalid ({'; '.join(voice.errors)})"
