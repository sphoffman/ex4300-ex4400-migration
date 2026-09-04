import argparse,getpass,os
from pathlib import Path
from .collector import Collector
def main():
 p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True); c=s.add_parser("collect");
 for a in ("host","username","output"): c.add_argument("--"+a,required=True)
 c.add_argument("--password-env"); c.add_argument("--duration",type=int,default=1800); c.add_argument("--interval",type=int,default=60); c.add_argument("--port",type=int,default=830); c.add_argument("--no-host-key-check",action="store_true",help="LAB ONLY: disable SSH host-key verification")
 a=p.parse_args(); password=os.environ.get(a.password_env) if a.password_env else getpass.getpass()
 if a.password_env and password is None: p.error(f"environment variable {a.password_env} is not set")
 from jnpr.junos import Device
 dev=Device(host=a.host,user=a.username,passwd=password,port=a.port,gather_facts=True)
 dev.open(auto_probe=10,hostkey_verify=not a.no_host_key_check)
 try: print(Collector(dev,Path(a.output),a.duration,a.interval).run())
 finally: dev.close()
