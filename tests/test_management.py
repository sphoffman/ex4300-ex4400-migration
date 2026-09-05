from ex_migration_discovery.identity import derive_identity
from ex_migration_discovery.parsers import parse_management_configuration,parse_set_configuration

CONFIG='''
set system host-name home1-ex4300-vc-fd-dh4301
set system syslog source-address 10.100.163.10
set system ntp source-address 10.100.163.10
set interfaces fxp0 unit 0 family inet address 10.0.0.15/24
set interfaces irb unit 163 family inet address 10.100.163.10/24
set snmp name hostname
set snmp location <home><1><dh4301>
set snmp engine-id local 10.100.163.10
set snmp trap-options source-address 10.100.163.10
set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 10.0.0.2
set routing-options static route 0.0.0.0/0 next-hop 10.100.163.1
set vlans v100 vlan-id 100
set vlans v163 description management
set vlans v163 vlan-id 163
set vlans v163 l3-interface irb.163
set vlans UNUSED-TEST vlan-id 300
'''

def test_identity_is_derived_and_only_platform_token_changes():
 identity=derive_identity("home1-ex4300-vc-fd-dh4301")
 assert identity.migration_id=="dh4301"
 assert identity.proposed_hostname=="home1-ex4400-vc-fd-dh4301"

def test_identity_rejects_unapproved_name():
 try: derive_identity("home1-access-dh4301")
 except ValueError: pass
 else: raise AssertionError("unapproved hostname was accepted")

def test_management_and_all_configured_vlans_are_normalized():
 _,vlans,_,_=parse_set_configuration(CONFIG)
 hostname,management=parse_management_configuration(CONFIG,vlans,163,"10.0.0.15",True)
 assert hostname=="home1-ex4300-vc-fd-dh4301"
 assert set(vlans)=={"v100","v163","UNUSED-TEST"}
 assert vlans["v163"].description=="management"
 assert vlans["v163"].irb_interface=="irb.163"
 assert management.vlan_name=="v163"
 assert management.addresses==["10.100.163.10/24"]
 assert management.production_ipv4=="10.100.163.10"
 assert management.default_gateway=="10.100.163.1"
 assert management.fxp0_addresses==["10.0.0.15/24"]
 assert management.mgmt_junos_default_gateways==["10.0.0.2"]
 assert management.snmp.location=="<home><1><dh4301>"
 assert management.snmp.name_uses_hostname is True
 assert management.snmp.v3_configured is True
 assert management.consistency=="CONSISTENT"
 assert {x.configuration_path for x in management.source_addresses}=={
  "system syslog source-address","system ntp source-address","snmp trap-options source-address"
 }
 assert all(x.disposition=="COPY_SAFE" for x in management.source_addresses)

def test_mismatched_source_address_requires_review():
 config=CONFIG.replace("set system ntp source-address 10.100.163.10","set system ntp source-address 10.100.163.99")
 _,vlans,_,_=parse_set_configuration(config)
 _,management=parse_management_configuration(config,vlans,163,"10.0.0.15",False)
 assert management.consistency=="REVIEW_REQUIRED"
 assert next(x for x in management.source_addresses if x.configuration_path=="system ntp source-address").disposition=="REVIEW_REQUIRED"
