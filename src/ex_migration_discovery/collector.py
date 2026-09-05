from __future__ import annotations
import hashlib,json,os,re,time,uuid
from datetime import datetime,timezone
from pathlib import Path
from .identity import derive_identity
from .model import DeviceIdentity,Snapshot
from .parsers import parse_interfaces_descriptions,parse_interfaces_terse,parse_lldp_neighbors_text,parse_mac_table_text,parse_management_configuration,parse_set_configuration
from .report import render_report

STATIC=[
 "show version","show chassis hardware","show virtual-chassis status",
 "show configuration system host-name | display inheritance | display set",
 "show configuration system management-instance | display inheritance | display set",
 "show configuration system syslog | display inheritance | display set | match source-address",
 "show configuration system ntp | display inheritance | display set | match source-address",
 "show configuration interfaces | display inheritance | display set",
 "show configuration vlans | display inheritance | display set",
 "show configuration snmp name | display set",
 "show configuration snmp location | display inheritance | display set",
 "show configuration snmp engine-id | display inheritance | display set",
 "show configuration snmp trap-options | display inheritance | display set | match source-address",
 "show configuration snmp v3 | display set | count",
 "show configuration routing-options static | display inheritance | display set",
 "show configuration routing-instances mgmt_junos routing-options | display inheritance | display set",
 "show configuration switch-options | display inheritance | display set",
 "show configuration ethernet-switching-options | display inheritance | display set",
 "show configuration protocols rstp | display inheritance | display set",
 "show configuration protocols lldp | display inheritance | display set",
 "show configuration protocols lldp-med | display inheritance | display set",
 "show configuration protocols dot1x | display inheritance | display set",
 "show configuration forwarding-options | display inheritance | display set",
 "show vlans extensive","show interfaces descriptions",
]
SAMPLED=["show ethernet-switching table detail","show interfaces terse","show lldp neighbors detail","show lacp interfaces","show dhcp-security binding","show dot1x interface detail"]
TEXT_ONLY={"show configuration snmp v3 | display set | count"}
def utc(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def safe(s): return re.sub(r"[^A-Za-z0-9_.-]+","_",s).strip("_")
def atomic_json(path,value):
 tmp=path.with_suffix(path.suffix+".tmp"); tmp.write_text(json.dumps(value,indent=2)+"\n"); os.replace(tmp,path)

class Collector:
 def __init__(self,dev,out:Path,duration:int,interval:int,migration_id:str|None=None,device_role:str="old-switch",management_vlan_id:int=163,connection_address:str|None=None,new_fxp_address:str|None=None):
  self.dev,self.out,self.duration,self.interval=dev,out,duration,interval
  self.requested_migration_id=migration_id; self.device_role=device_role; self.management_vlan_id=management_vlan_id
  self.connection_address=connection_address or getattr(dev,"hostname",None); self.new_fxp_address=new_fxp_address
 def run(self):
  facts=getattr(self.dev,"facts",{}) or {}; observed_hostname=str(facts.get("hostname") or "")
  derived=derive_identity(observed_hostname)
  if self.requested_migration_id and self.requested_migration_id!=derived.migration_id:
   raise ValueError(f"supplied migration ID {self.requested_migration_id!r} does not match hostname-derived ID {derived.migration_id!r}")
  migration_id=safe(derived.migration_id)
  if not migration_id or migration_id!=derived.migration_id: raise ValueError("derived migration ID contains unsupported characters")
  started=utc(); run=uuid.uuid4().hex[:8]; migration_root=self.out/"migrations"/migration_id; manifest=migration_root/"manifest.json"
  if manifest.exists():
   existing=json.loads(manifest.read_text()); prior=existing.get("old_switch",{}).get("observed_hostname")
   if prior and prior.lower()!=observed_hostname.lower(): raise ValueError(f"migration {migration_id!r} already belongs to {prior!r}")
  collections=migration_root/self.device_role/"collections"; collections.mkdir(parents=True,exist_ok=True)
  base=collections/(started.replace(":","").replace("-","")[:15]+"Z_pending_"+run); base.mkdir()
  artifacts=[]; errors=[]; texts={}
  def grab(cmd,group,n):
   d=base/"raw"/group; d.mkdir(parents=True,exist_ok=True); stem=f"{n:03d}_{safe(cmd)}"; txt=""; text_path=""
   if cmd not in TEXT_ONLY:
    try:
     xml=self.dev.rpc.cli(command=cmd,format="xml"); xp=d/(stem+".xml")
     xml_bytes=__import__("lxml.etree").etree.tostring(xml,pretty_print=True) if hasattr(xml,"tag") else (repr(xml)+"\n").encode(); xp.write_bytes(xml_bytes)
     artifacts.append({"path":str(xp.relative_to(base)),"sha256":hashlib.sha256(xp.read_bytes()).hexdigest(),"command":cmd,"format":"xml"})
    except Exception as e: errors.append({"command":cmd,"format":"xml","error":f"{type(e).__name__}: {e}"})
   try:
    txt=self.dev.cli(cmd,warning=False); tp=d/(stem+".txt"); tp.write_text(txt); text_path=str(tp.relative_to(base)); usable=not re.search(r"(?m)^protocol:\s*operation-failed\s*$",txt)
    artifacts.append({"path":text_path,"sha256":hashlib.sha256(tp.read_bytes()).hexdigest(),"command":cmd,"format":"text","usable":usable})
    if not usable: errors.append({"command":cmd,"format":"text","error":"device returned operation-failed text"}); txt=""
   except Exception as e: errors.append({"command":cmd,"format":"text","error":f"{type(e).__name__}: {e}"})
   return txt,text_path
  for n,c in enumerate(STATIC): texts[c]=grab(c,"static",n)
  config="\n".join(texts[c][0] for c in STATIC if c.startswith("show configuration"))
  interfaces,vlans,voice,warnings=parse_set_configuration(config)
  v3_command="show configuration snmp v3 | display set | count"
  count_text=texts[v3_command][0]
  count_match=re.search(r"Count:\s*(\d+)\s+lines",count_text)
  v3_text_failed=any(e["command"]==v3_command and e["format"]=="text" for e in errors)
  v3_configured=(int(count_match.group(1))>0) if count_match else (None if v3_text_failed else False)
  configured_hostname,management=parse_management_configuration(config,vlans,self.management_vlan_id,self.connection_address,v3_configured)
  if configured_hostname and configured_hostname.lower()!=observed_hostname.lower(): warnings.append(f"configured hostname {configured_hostname!r} differs from device fact {observed_hostname!r}")
  parse_interfaces_descriptions(texts["show interfaces descriptions"][0],interfaces)
  observations=[]; neighbors=[]; present=set(); sample=0; deadline=time.monotonic()+self.duration
  while True:
   stamp=utc()
   for n,c in enumerate(SAMPLED):
    text,path=grab(c,f"observations/{sample:04d}",n)
    if c.startswith("show ethernet-switching table"): observations+=parse_mac_table_text(text,stamp,path,interfaces)
    elif c=="show interfaces terse": present|=parse_interfaces_terse(text,interfaces)
    elif c=="show lldp neighbors detail": neighbors+=parse_lldp_neighbors_text(text,stamp,path)
   sample+=1
   if time.monotonic()>=deadline: break
   time.sleep(min(self.interval,max(0,deadline-time.monotonic())))
  interfaces={k:v for k,v in interfaces.items() if k in present}
  voice.interface_selectors=[x for x in voice.interface_selectors if x.split('.',1)[0] in present]
  voice.evidence=[x for x in voice.evidence if any(f"interface {sel} " in x for sel in voice.interface_selectors)]
  unique_macs={vlan_id:{o.mac for o in observations if o.vlan.vlan_id==vlan_id} for vlan_id in {o.vlan.vlan_id for o in observations}}
  for vlan in vlans.values(): vlan.observed_mac_count=len(unique_macs.get(vlan.vlan_id,set())); vlan.observed=vlan.observed_mac_count>0
  for vlan in vlans.values():
   if vlan.irb_interface and vlan.vlan_id!=self.management_vlan_id: warnings.append(f"non-management VLAN {vlan.name} has l3-interface {vlan.irb_interface}")
  ident=DeviceIdentity(observed_hostname or None,facts.get("model"),facts.get("version"),"evolved" if "EVO" in str(facts.get("version","")) else "classic",[str(facts[x]) for x in ("serialnumber",) if facts.get(x)],configured_hostname,derived.proposed_hostname,derived.rule)
  formats={c:{a.get("format") for a in artifacts if a["command"]==c and a.get("usable",True)} for c in STATIC+SAMPLED}; capabilities={c:("xml_and_text" if formats[c]=={"xml","text"} else "text_only" if "text" in formats[c] else "xml_only" if "xml" in formats[c] else "unsupported_or_failed") for c in STATIC+SAMPLED}; failed={c for c,v in capabilities.items() if v=="unsupported_or_failed"}
  snap=Snapshot(run,migration_id,self.device_role,started,utc(),"COLLECTED",ident,management,{"duration_seconds":self.duration,"interval_seconds":self.interval,"samples":sample,"management_vlan_id":self.management_vlan_id},capabilities,{"status":"unsupported" if "show virtual-chassis status" in failed else "collected"},list(interfaces.values()),list(vlans.values()),voice,observations,neighbors,artifacts,sorted(set(warnings)),errors)
  name=f"{started.replace(':','').replace('-','')[:15]}Z_{safe(ident.hostname or 'unknown')}_{run}"; final=collections/name
  (base/"snapshot.json").write_text(json.dumps(snap.to_dict(),indent=2)+"\n"); (base/"report.md").write_text(render_report(snap)); (base/"errors.json").write_text(json.dumps(errors,indent=2)+"\n")
  integ={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in base.iterdir() if p.is_file()}; (base/"integrity.json").write_text(json.dumps(integ,indent=2)+"\n"); os.replace(base,final)
  if not manifest.exists(): atomic_json(manifest,{"schema_version":"1.1","migration_id":migration_id,"created_at":started,"old_switch":{"observed_hostname":ident.hostname,"management_address":management.production_ipv4,"connection_address":self.connection_address},"new_switch":{"proposed_hostname":derived.proposed_hostname,"temporary_fxp0_address":self.new_fxp_address}})
  atomic_json(migration_root/"status.json",{"migration_id":migration_id,"state":"COLLECTING_OLD","latest_collection":str(final.relative_to(migration_root)),"updated_at":utc()})
  return final
