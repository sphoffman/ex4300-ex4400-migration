import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def policy():
    """Current generated-policy fixture used by migration/provisioning tests."""
    return json.loads(
        (ROOT / "tests/fixtures/qfx-site-policy.generated.json").read_text()
    )


def digest(char):
    return char * 64


def bootstrap():
    return {
        "environment": "lab",
        "provisioning_mode": "in-place-lab",
        "production_eligible": False,
        "uplink_interfaces": ["ge-0/0/0", "ge-0/0/1"],
        "virtual_chassis": {"member_count": 1, "members": []},
    }


def plan_variables():
    return {
        "migration_id": "sw1203",
        "old_hostname": "home1-ex4300-vc-fd-sw1203",
        "new_hostname": "home1-ex4400-vc-fd-sw1203",
        "management_vlan_id": 163,
        "management_vlan_name": "v163",
        "management_interface": "irb.163",
        "management_ip": "10.100.163.30",
        "management_prefix": "10.100.163.30/24",
        "management_gateway": "10.100.163.1",
        "snmp_location": "<home><1><sw1203>",
        "snmp_engine_id": "10.100.163.30",
        "voice_vlan_name": "voip",
        "voice_vlan_id": 1111,
        "configured_vlans": [
            {"name": "v100", "vlan_id": 100},
            {"name": "v163", "vlan_id": 163},
            {"name": "v200", "vlan_id": 200},
            {"name": "UNUSED-TEST", "vlan_id": 300},
            {"name": "voip", "vlan_id": 1111},
        ],
    }


# The former tests in this module exercised the retired pre-cutover QFX preflight
# and explicit migration->physical-port mapping model. QFX identity/port mapping
# is now site-discovered and baseline-staged before any EX4300 migration begins.
# Current behavior is covered by test_current_site_policy.py, test_attachment.py,
# test_qfx_stage.py, test_prestage.py, and the site-workflow tests.
