from __future__ import annotations

import argparse,csv,getpass,json,os,sys
from concurrent.futures import ThreadPoolExecutor,as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List,Optional
from .collector import Collector

@dataclass(frozen=True)
class Target:
 host:str
 new_fxp_address:Optional[str]=None

def targets_from_csv(path:Path)->List[Target]:
 with path.open(newline="") as stream:
  reader=csv.DictReader(stream)
  if not reader.fieldnames or "old_address" not in reader.fieldnames: raise ValueError("inventory CSV must contain an old_address column")
  result=[]
  for row_number,row in enumerate(reader,start=2):
   host=(row.get("old_address") or "").strip()
   if not host: raise ValueError(f"inventory row {row_number} has no old_address")
   result.append(Target(host,(row.get("new_fxp_address") or "").strip() or None))
  if not result: raise ValueError("inventory CSV contains no targets")
  return result

def main():
 p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True); c=s.add_parser("collect")
 source=c.add_mutually_exclusive_group(required=False); source.add_argument("--host",action="append",help="Old-switch address; repeat for multiple switches"); source.add_argument("--inventory",type=Path,help="CSV with old_address and optional new_fxp_address")
 c.add_argument("address",nargs="?",help="Old-switch address for the normal single-device workflow")
 c.add_argument("--username"); c.add_argument("--output"); c.add_argument("--migration-id",help="Optional assertion/override; valid only with one host")
 c.add_argument("--management-vlan",type=int); c.add_argument("--password-env"); c.add_argument("--duration",type=int); c.add_argument("--interval",type=int); c.add_argument("--port",type=int,default=830); c.add_argument("--workers",type=int); c.add_argument("--settings",type=Path,default=Path("config/site.json")); c.add_argument("--no-host-key-check",action="store_true",help="LAB ONLY: disable SSH host-key verification")
 a=p.parse_args()
 if a.address and (a.host or a.inventory): p.error("address cannot be combined with --host or --inventory")
 if a.address: targets=[Target(a.address)]
 elif a.host: targets=[Target(x) for x in a.host]
 elif a.inventory: targets=targets_from_csv(a.inventory)
 else:
  address=input("Old-switch address: ").strip()
  if not address: p.error("old-switch address must not be empty")
  targets=[Target(address)]
 if a.migration_id and len(targets)!=1: p.error("--migration-id may be used only with a single host")
 if len({target.host for target in targets})!=len(targets): p.error("duplicate old-switch addresses are not allowed")
 settings=json.loads(a.settings.read_text()) if a.settings.is_file() else {}
 a.output=a.output or settings.get("snapshot_root","snapshots")
 a.management_vlan=a.management_vlan or int(settings.get("default_management_vlan_id",163))
 a.duration=a.duration or int(settings.get("default_collection_duration_seconds",1800))
 a.interval=a.interval or int(settings.get("default_collection_interval_seconds",60))
 workers=a.workers or int(settings.get("collection_workers",4))
 if workers<1: p.error("--workers must be at least 1")
 username=a.username or input("Username: ").strip()
 if not username: p.error("username must not be empty")
 password=os.environ.get(a.password_env) if a.password_env else getpass.getpass("Password: ")
 if a.password_env and password is None: p.error(f"environment variable {a.password_env} is not set")
 from jnpr.junos import Device
 def collect_target(target):
  dev=Device(host=target.host,user=username,passwd=password,port=a.port,gather_facts=True)
  try:
   dev.open(auto_probe=10,hostkey_verify=not a.no_host_key_check)
   result=Collector(dev,Path(a.output),a.duration,a.interval,a.migration_id,management_vlan_id=a.management_vlan,connection_address=target.host,new_fxp_address=target.new_fxp_address).run()
   return target.host,result,None
  except Exception as exc:
   return target.host,None,exc
  finally:
   try: dev.close()
   except Exception: pass
 results=[]
 with ThreadPoolExecutor(max_workers=min(workers,len(targets))) as executor:
  futures=[executor.submit(collect_target,target) for target in targets]
  for future in as_completed(futures): results.append(future.result())
 failures=[item for item in results if item[2] is not None]
 print("\nCollection summary")
 for host,result,error in sorted(results):
  if error: print(f"FAILED   {host}  {type(error).__name__}: {error}",file=sys.stderr)
  else: print(f"SUCCESS  {host}  {result}")
 print(f"\n{len(results)-len(failures)} succeeded, {len(failures)} failed")
 if failures: raise SystemExit(1)

if __name__=="__main__": main()
