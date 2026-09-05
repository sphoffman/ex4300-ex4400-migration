from ex_migration_discovery.identity import derive_identity
from ex_migration_discovery.collector import contains_prohibited_credential,needs_dhcp_binding,needs_dot1x_detail
from ex_migration_discovery.parsers import parse_management_configuration,parse_set_configuration

CONFIG='''
set system host-name site1-ex4300-vc-fd-room101
set system syslog source-address 192.0.2.10
set system ntp source-address 192.0.2.10
set interfaces fxp0 unit 0 family inet address 198.51.100.15/24
set interfaces irb unit 163 family inet address 192.0.2.10/24
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members 100
set snmp name hostname
set snmp location <site><1><room101>
set snmp engine-id local 192.0.2.10
set snmp trap-options source-address 192.0.2.10
set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 198.51.100.2
set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1
set vlans v100 vlan-id 100
set vlans v163 description management
set vlans v163 vlan-id 163
set vlans v163 l3-interface irb.163
set vlans UNUSED-TEST vlan-id 300
'''

def test_identity_is_derived_and_only_platform_token_changes():
 identity=derive_identity("site1-ex4300-vc-fd-room101")
 assert identity.migration_id=="room101"
 assert identity.proposed_hostname=="site1-ex4400-vc-fd-room101"

def test_identity_rejects_unapproved_name():
 try: derive_identity("site1-access-room101")
 except ValueError: pass
 else: raise AssertionError("unapproved hostname was accepted")

def test_management_and_all_configured_vlans_are_normalized():
 interfaces,vlans,_,_=parse_set_configuration(CONFIG)
 hostname,management=parse_management_configuration(CONFIG,vlans,163,"198.51.100.15",True)
 assert hostname=="site1-ex4300-vc-fd-room101"
 assert set(vlans)=={"v100","v163","UNUSED-TEST"}
 assert vlans["v163"].description=="management"
 assert vlans["v163"].irb_interface=="irb.163"
 assert interfaces["ge-0/0/2"].untagged_vlan.name=="v100"
 assert interfaces["ge-0/0/2"].untagged_vlan.vlan_id==100
 assert management.vlan_name=="v163"
 assert management.addresses==["192.0.2.10/24"]
 assert management.production_ipv4=="192.0.2.10"
 assert management.default_gateway=="192.0.2.1"
 assert management.fxp0_addresses==["198.51.100.15/24"]
 assert management.mgmt_junos_default_gateways==["198.51.100.2"]
 assert management.snmp.location=="<site><1><room101>"
 assert management.snmp.name_uses_hostname is True
 assert management.snmp.v3_configured is True
 assert management.consistency=="CONSISTENT"
 assert {x.configuration_path for x in management.source_addresses}=={
  "system syslog source-address","system ntp source-address","snmp trap-options source-address"
 }
 assert all(x.disposition=="COPY_SAFE" for x in management.source_addresses)

def test_mismatched_source_address_requires_review():
 config=CONFIG.replace("set system ntp source-address 192.0.2.10","set system ntp source-address 192.0.2.99")
 _,vlans,_,_=parse_set_configuration(config)
 _,management=parse_management_configuration(config,vlans,163,"198.51.100.15",False)
 assert management.consistency=="REVIEW_REQUIRED"
 assert next(x for x in management.source_addresses if x.configuration_path=="system ntp source-address").disposition=="REVIEW_REQUIRED"

def test_hierarchical_snmp_name_preserves_hostname_keyword():
 config=CONFIG.replace("set snmp name hostname","name hostname;")
 _,vlans,_,_=parse_set_configuration(config)
 _,management=parse_management_configuration(config,vlans,163,"198.51.100.15",False)
 assert management.snmp.name=="hostname"
 assert management.snmp.name_uses_hostname is True

def test_optional_operational_collection_is_configuration_driven():
 assert needs_dhcp_binding("set vlans v100 forwarding-options dhcp-security group TRUST interface ae0.0")
 assert needs_dhcp_binding("set ethernet-switching-options secure-access-port interface ge-0/0/2")
 assert not needs_dhcp_binding(CONFIG)
 assert needs_dot1x_detail("set protocols dot1x authenticator interface ge-0/0/2")
 assert not needs_dot1x_detail(CONFIG)

def test_arbitrary_source_address_path_is_normalized():
 config=CONFIG+"set system archival configuration source-address 192.0.2.10\n"
 _,vlans,_,_=parse_set_configuration(config)
 _,management=parse_management_configuration(config,vlans,163,"198.51.100.15",False)
 source=next(x for x in management.source_addresses if x.configuration_path=="system archival configuration source-address")
 assert source.configured_value=="192.0.2.10"
 assert source.disposition=="COPY_SAFE"

def test_credential_material_guard_fails_closed():
 assert contains_prohibited_credential('set system root-authentication encrypted-password "$6$redacted"')
 assert contains_prohibited_credential('<authentication-key>redacted</authentication-key>')
 assert contains_prohibited_credential('set snmp community private authorization read-only')
 assert not contains_prohibited_credential('set system syslog source-address 192.0.2.10')
