import pytest

from ex_migration_qfx_bootstrap.core import (
    BootstrapConfigError,
    ae_number,
    candidate_interfaces,
    lacp_system_id,
    render_esi_lag,
    validate_config,
)


def config():
    return validate_config({
        "qfx_pair": [
            {"role": "qfx-a", "management_address": "10.255.3.14"},
            {"role": "qfx-b", "management_address": "10.255.3.15"},
        ],
        "management_vlan": {"name": "v163", "vlan_id": 163},
        "interfaces": {
            "type": "et",
            "pic": 0,
            "first_port": 0,
            "last_port": 15,
            "ports_per_fpc": 16,
        },
        "lacp_system_id": {"prefix": "02:00:00:00"},
    })


def test_ae_number_is_deterministic_across_fpcs():
    assert ae_number(0, 0) == 0
    assert ae_number(0, 15) == 15
    assert ae_number(1, 0) == 16
    assert ae_number(1, 1) == 17
    assert ae_number(2, 15) == 47


def test_candidate_interfaces_are_generated_without_optic_state():
    values = candidate_interfaces([1, 0], config())
    assert len(values) == 32
    assert values[0]["physical_interface"] == "et-0/0/0"
    assert values[0]["ae_interface"] == "ae0"
    assert values[16]["physical_interface"] == "et-1/0/0"
    assert values[17]["physical_interface"] == "et-1/0/1"
    assert values[17]["ae_interface"] == "ae17"


def test_lacp_system_id_encodes_ae_number():
    assert lacp_system_id(0) == "02:00:00:00:00:00"
    assert lacp_system_id(17) == "02:00:00:00:00:11"
    assert lacp_system_id(511) == "02:00:00:00:01:ff"


def test_render_known_good_shape_for_ae17():
    candidate = candidate_interfaces([1], config())[1]
    assert render_esi_lag(candidate, config()) == [
        "set interfaces ae17 esi auto-derive type-1-lacp",
        "set interfaces ae17 esi all-active",
        "set interfaces ae17 aggregated-ether-options lacp active",
        "set interfaces ae17 aggregated-ether-options lacp system-id 02:00:00:00:00:11",
        "set interfaces ae17 unit 0 family ethernet-switching interface-mode trunk",
        "set interfaces ae17 unit 0 family ethernet-switching vlan members v163",
        "set interfaces et-1/0/1 ether-options 802.3ad ae17",
    ]


def test_last_port_cannot_exceed_ae_namespace():
    value = config()
    value["interfaces"]["last_port"] = 16
    with pytest.raises(BootstrapConfigError):
        validate_config(value)
