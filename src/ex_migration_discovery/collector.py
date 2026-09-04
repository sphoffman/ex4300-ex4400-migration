from __future__ import annotations
import hashlib, json, os, re, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from .model import DeviceIdentity, Snapshot
from .parsers import parse_interfaces_descriptions, parse_mac_table_text, parse_set_configuration
from .report import render_report

STATIC=["show version","show chassis hardware","show virtual-chassis status","show configuration | display inheritance | display set","show vlans extensive","show interfaces descriptions"]
SAMPLED=["show ethernet-switching table detail","show interfaces terse","show lldp neighbors detail","show lacp interfaces","show dhcp-security binding","show dot1x interface detail"]

def utc(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def safe(s): return re.sub(r"[^A-Za-z0-9_.-]+","_",s).strip("_")

class Collector:
 def __init__(self,dev,out:Path,duration:int,interval:int): self.dev,self.out,self.duration,self.interval=dev,out,duration,interval
 def run(self):
  started=utc(); run=uuid.uuid4().hex[:8]; base=self.out/(started.replace(":","").replace("-","")[:15]+"Z_pending_"+run); base.mkdir(parents=True)
  artifacts=[]; errors=[]; texts={}
  def grab(cmd,group,n):
   d=base/"raw"/group; d.mkdir(parents=True,exist_ok=True); stem=f"{n:03d}_{safe(cmd)}"
   try:
    xml=self.dev.rpc.cli(command=cmd,format="xml"); xp=d/(stem+".xml"); xp.write_bytes(__import__("lxml.etree").etree.tostring(xml,pretty_print=True))
    txt=self.dev.cli(cmd,warning=False); tp=d/(stem+".txt"); tp.write_text(txt)
    for p in (xp,tp): artifacts.append({"path":str(p.relative_to(base)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"command":cmd})
    return txt,str(tp.relative_to(base))
   except Exception as e: errors.append({"command":cmd,"error":f"{type(e).__name__}: {e}"}); return "",""
  for n,c in enumerate(STATIC): texts[c]=grab(c,"static",n)
  config=texts[STATIC[3]][0]; interfaces,vlans,voice,warnings=parse_set_configuration(config)
  parse_interfaces_descriptions(texts[STATIC[5]][0],interfaces)
  observations=[]; sample=0; deadline=time.monotonic()+self.duration
  while True:
   stamp=utc()
   for n,c in enumerate(SAMPLED):
    text,path=grab(c,f"observations/{sample:04d}",n)
    if c.startswith("show ethernet-switching table"):
     observations += parse_mac_table_text(text,stamp,path,interfaces)
   sample+=1
   if time.monotonic()>=deadline: break
   time.sleep(min(self.interval,max(0,deadline-time.monotonic())))
  facts=getattr(self.dev,"facts",{}) or {}; ident=DeviceIdentity(facts.get("hostname"),facts.get("model"),facts.get("version"),"evolved" if "EVO" in str(facts.get("version", "")) else "classic",[str(facts[x]) for x in ("serialnumber",) if facts.get(x)])
  snap=Snapshot(run,started,utc(),"COLLECTED",ident,{"duration_seconds":self.duration,"interval_seconds":self.interval,"samples":sample},{}, {},list(interfaces.values()),list(vlans.values()),voice,observations,[],artifacts,warnings,errors)
  name=f"{started.replace(':','').replace('-','')[:15]}Z_{safe(ident.hostname or 'unknown')}_{run}"; final=self.out/name
  (base/"snapshot.json").write_text(json.dumps(snap.to_dict(),indent=2)+"\n"); (base/"report.md").write_text(render_report(snap)); (base/"errors.json").write_text(json.dumps(errors,indent=2)+"\n")
  integ={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in base.iterdir() if p.is_file()}; (base/"integrity.json").write_text(json.dumps(integ,indent=2)+"\n"); os.replace(base,final); return final
