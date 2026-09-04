from ex_migration_discovery.normalize import normalize_mac,split_interface
from ex_migration_discovery.parsers import parse_mac_table_text,parse_set_configuration
CFG='''set switch-options voip interface edge_ports vlan voip
set vlans v100 vlan-id 100
set vlans voip vlan-id 1111
set interfaces ge-0/0/2 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members v100
set interfaces ge-0/0/0 gigether-options 802.3ad ae0'''
MAC='''MAC address: 0265.6b7e.3e7b
  Routing instance: default-switch
  VLAN name: v100, VLAN ID: 100
   Learning interface: ge-0/0/2.0
   Layer 2 flags: in_hash,in_ifd
MAC address: 12:36:00:00:00:00
  Routing instance: default-switch
  VLAN name: voip, VLAN ID: 1111
   Learning interface: ae0.0
   Layer 2 flags: in_hash'''
def test_normalization(): assert normalize_mac('0265.6B7E.3E7B')=='02:65:6b:7e:3e:7b'; assert split_interface('ge-3/0/17.0')['physical']=='ge-3/0/17'
def test_voice_and_mac_classification():
 i,v,voice,w=parse_set_configuration(CFG); assert (voice.vlan_name,voice.vlan_id,voice.valid)==('voip',1111,True)
 m=parse_mac_table_text(MAC,'2026-09-04T00:00:00Z','raw.txt',i); assert [x.interface_class for x in m]==['physical_access','ae']; assert m[0].mac=='02:65:6b:7e:3e:7b'
def test_missing_voice_vlan_is_invalid():
 _,_,voice,_=parse_set_configuration('set switch-options voip interface edge_ports vlan absent'); assert not voice.valid and voice.errors

