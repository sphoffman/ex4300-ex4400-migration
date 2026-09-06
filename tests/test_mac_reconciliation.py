from ex_migration_discovery.model import InterfaceState, VlanState
from ex_migration_discovery.parsers import parse_mac_table_summary_text


def test_summary_parser_preserves_rows_missing_from_detail_view():
    text = """
Ethernet switching table : 2 entries, 2 learned
Routing instance : default-switch
    v100  02:16:d8:cd:c9:00  D  -  ge-0/0/2.0  0  0
    voip  02:30:7f:d5:91:97  D  -  ge-0/0/5.0  0  0
"""
    interfaces = {
        "ge-0/0/2": InterfaceState("ge-0/0/2", "ge-0/0/2", effective_mode="access"),
        "ge-0/0/5": InterfaceState("ge-0/0/5", "ge-0/0/5", effective_mode="access"),
    }
    vlans = {"v100": VlanState("v100", 100), "voip": VlanState("voip", 1111)}
    rows = parse_mac_table_summary_text(text, "2026-09-06T16:15:00Z", "summary.txt", interfaces, vlans)
    assert [(row.mac, row.vlan.vlan_id, row.physical_interface) for row in rows] == [
        ("02:16:d8:cd:c9:00", 100, "ge-0/0/2"),
        ("02:30:7f:d5:91:97", 1111, "ge-0/0/5"),
    ]
