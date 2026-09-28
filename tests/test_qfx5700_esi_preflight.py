from ex_migration_qfx_bootstrap.core import validate_config
from ex_migration_qfx_bootstrap.preflight import (
    build_pair_preflight,
    discover_online_fpcs,
    verify_management_vlan,
)


class FakeDevice:
    def __init__(self, fpc_text, configs=None, vlan_text="set vlans v163 vlan-id 163"):
        self.fpc_text = fpc_text
        self.configs = configs or {}
        self.vlan_text = vlan_text

    def cli(self, command, warning=False):
        if command == "show chassis fpc":
            return self.fpc_text
        if command == "show configuration vlans | display set":
            return self.vlan_text
        prefix = "show configuration interfaces "
        if command.startswith(prefix):
            interface = command[len(prefix):].split()[0]
            return self.configs.get(interface, "")
        raise AssertionError("unexpected command: %s" % command)


def config(last_port=1):
    return validate_config({
        "qfx_pair": [
            {"role": "qfx-a", "management_address": "10.255.3.14"},
            {"role": "qfx-b", "management_address": "10.255.3.15"},
        ],
        "management_vlan": {"name": "v163", "vlan_id": 163},
        "interfaces": {
            "type": "et", "pic": 0, "first_port": 0,
            "last_port": last_port, "ports_per_fpc": 16,
        },
        "lacp_system_id": {"prefix": "02:00:00:00"},
    })


FPCS = """
Slot State  Uptime
  0 Online  2 days
  1 Online  2 days
  2 Empty
"""


def test_fpc_discovery_uses_chassis_slots_not_interfaces():
    assert discover_online_fpcs(FakeDevice(FPCS)) == [0, 1]


def test_management_vlan_requires_name_and_id_to_match():
    assert verify_management_vlan(FakeDevice(FPCS), config())["result"] == "PASS"
    bad = FakeDevice(FPCS, vlan_text="set vlans v163 vlan-id 999")
    assert verify_management_vlan(bad, config())["result"] == "FAIL"


def test_empty_matching_ports_are_create_candidates():
    devices = {"qfx-a": FakeDevice(FPCS), "qfx-b": FakeDevice(FPCS)}
    result = build_pair_preflight(devices, config(last_port=1))
    assert result["result"] == "PASS"
    assert result["create_count"] == 4
    assert result["warning_count"] == 0
    assert result["candidates"][2]["physical_interface"] == "et-1/0/0"
    assert result["candidates"][2]["ae_interface"] == "ae16"


def test_configured_pair_is_skipped():
    existing = {"et-0/0/0": "set interfaces et-0/0/0 description reserved"}
    devices = {
        "qfx-a": FakeDevice(FPCS, configs=existing),
        "qfx-b": FakeDevice(FPCS, configs=existing),
    }
    result = build_pair_preflight(devices, config(last_port=0))
    assert result["result"] == "PASS"
    assert result["skip_count"] == 2


def test_asymmetric_configuration_hard_fails_pair_preflight():
    devices = {
        "qfx-a": FakeDevice(FPCS, configs={"et-0/0/0": "set interfaces et-0/0/0 description reserved"}),
        "qfx-b": FakeDevice(FPCS),
    }
    result = build_pair_preflight(devices, config(last_port=0))
    assert result["result"] == "FAIL"
    assert result["warning_count"] == 1
    assert result["candidates"][0]["pair_state"] == "WARN_ASYMMETRIC"


def test_existing_ae_blocks_reuse_even_when_physical_port_is_empty():
    devices = {
        "qfx-a": FakeDevice(FPCS, configs={"ae0": "set interfaces ae0 description existing"}),
        "qfx-b": FakeDevice(FPCS, configs={"ae0": "set interfaces ae0 description existing"}),
    }
    result = build_pair_preflight(devices, config(last_port=0))
    assert result["candidates"][0]["pair_state"] == "SKIP_CONFIGURED"
