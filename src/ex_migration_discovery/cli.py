from __future__ import annotations

import argparse,csv,getpass,os,sys
from dataclasses import dataclass
from pathlib import Path
from .collector import Collector

@dataclass(frozen=True)
class Target:
 host:str
 new_fxp_address:str|None=None

def targets_from_csv(path:Path)->list[Target]:
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
 c.add_argument("--username"); c.add_argument("--output",default="snapshots"); c.add_argument("--migration-id",help="Optional assertion/override; valid only with one host")
 c.add_argument("--management-vlan",type=int,default=163); c.add_argument("--password-env"); c.add_argument("--duration",type=int,default=1800); c.add_argument("--interval",type=int,default=60); c.add_argument("--port",type=int,default=830); c.add_argument("--no-host-key-check",action="store_true",help="LAB ONLY: disable SSH host-key verification")
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
 username=a.username or input("Username: ").strip()
 if not username: p.error("username must not be empty")
 password=os.environ.get(a.password_env) if a.password_env else getpass.getpass("Password: ")
 if a.password_env and password is None: p.error(f"environment variable {a.password_env} is not set")
 from jnpr.junos import Device
 failures=[]
 for target in targets:
  dev=Device(host=target.host,user=username,passwd=password,port=a.port,gather_facts=True)
  try:
   dev.open(auto_probe=10,hostkey_verify=not a.no_host_key_check)
   result=Collector(dev,Path(a.output),a.duration,a.interval,a.migration_id,management_vlan_id=a.management_vlan,connection_address=target.host,new_fxp_address=target.new_fxp_address).run()
   print(f"{target.host}: {result}")
  except Exception as exc:
   failures.append((target.host,exc)); print(f"{target.host}: ERROR: {type(exc).__name__}: {exc}",file=sys.stderr)
  finally:
   try: dev.close()
   except Exception: pass
 if failures: raise SystemExit(1)

if __name__=="__main__": main()
