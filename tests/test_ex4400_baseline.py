from pathlib import Path

import pytest

from ex4400_baseline.core import (
    ArpEntry,
    BaselineError,
    MacEntry,
    find_arp_ip,
    lookup_inventory,
    normalize_mac,
    parse_arp_xml,
    parse_ethernet_switching_xml,
    select_local_mac,
    upsert_inventory,
    xml_from_string,
)


def test_normalize_mac_common_formats():
    assert normalize_mac(
        "AA:BB:CC:DD:EE:FF"
    ) == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac(
        "aabb.ccdd.eeff"
    ) == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac(
        "aa-bb-cc-dd-ee-ff"
    ) == "aa:bb:cc:dd:ee:ff"


def test_parse_els_and_select_ignores_ae0():
    xml = xml_from_string(
        """
        <rpc-reply>
          <l2ng-l2ald-mac-entry-vlan>
            <l2ng-l2-mac-address>00:11:22:33:44:55</l2ng-l2-mac-address>
            <l2ng-l2-vlan-id>163</l2ng-l2-vlan-id>
            <l2ng-l2-mac-logical-interface>ae0.0</l2ng-l2-mac-logical-interface>
          </l2ng-l2ald-mac-entry-vlan>
          <l2ng-l2ald-mac-entry-vlan>
            <l2ng-l2-mac-address>aa:bb:cc:dd:ee:ff</l2ng-l2-mac-address>
            <l2ng-l2-vlan-id>163</l2ng-l2-vlan-id>
            <l2ng-l2-mac-logical-interface>ge-4/0/47.0</l2ng-l2-mac-logical-interface>
          </l2ng-l2ald-mac-entry-vlan>
        </rpc-reply>
        """
    )
    result = select_local_mac(
        parse_ethernet_switching_xml(xml),
        163,
        ["ae0"],
    )
    assert result == MacEntry(
        "aa:bb:cc:dd:ee:ff",
        163,
        "ge-4/0/47",
    )


def test_parse_non_els():
    xml = xml_from_string(
        """
        <rpc-reply>
          <mac-table-entry>
            <mac-vlan>mgmt</mac-vlan>
            <mac-vlan-tag>163</mac-vlan-tag>
            <mac-address>aa:bb:cc:dd:ee:ff</mac-address>
            <mac-interface>ge-0/0/47.0</mac-interface>
          </mac-table-entry>
        </rpc-reply>
        """
    )
    assert parse_ethernet_switching_xml(
        xml
    ) == [
        MacEntry(
            "aa:bb:cc:dd:ee:ff",
            163,
            "ge-0/0/47",
        )
    ]


def test_multiple_local_macs_requires_port_override():
    entries = [
        MacEntry(
            "00:11:22:33:44:55",
            163,
            "ge-0/0/46",
        ),
        MacEntry(
            "aa:bb:cc:dd:ee:ff",
            163,
            "ge-0/0/47",
        ),
    ]
    with pytest.raises(
        BaselineError,
        match="multiple locally learned MACs",
    ):
        select_local_mac(
            entries,
            163,
            ["ae0"],
        )

    assert (
        select_local_mac(
            entries,
            163,
            ["ae0"],
            "ge-0/0/47",
        ).mac
        == "aa:bb:cc:dd:ee:ff"
    )


def test_arp_lookup_filters_management_network():
    entries = [
        ArpEntry(
            "aa:bb:cc:dd:ee:ff",
            "10.1.1.10",
            "irb.163",
        ),
        ArpEntry(
            "aa:bb:cc:dd:ee:ff",
            "192.0.2.10",
            "irb.999",
        ),
    ]
    result = find_arp_ip(
        entries,
        "aabb.ccdd.eeff",
        "10.1.1.0/24",
    )
    assert result.ip == "10.1.1.10"


def test_parse_arp_xml():
    xml = xml_from_string(
        """
        <rpc-reply>
          <arp-table-entry>
            <mac-address>AA:BB:CC:DD:EE:FF</mac-address>
            <ip-address>10.1.1.10</ip-address>
            <interface-name>irb.163</interface-name>
          </arp-table-entry>
        </rpc-reply>
        """
    )
    assert parse_arp_xml(
        xml
    ) == [
        ArpEntry(
            "aa:bb:cc:dd:ee:ff",
            "10.1.1.10",
            "irb.163",
        )
    ]


def test_inventory_upsert_and_ready_lookup(
    tmp_path: Path,
):
    path = (
        tmp_path
        / "inventory.csv"
    )
    first = {
        "migration_id": "sw1203",
        "ex4300_ip": "10.0.0.1",
        "ex4400_ip": "10.1.1.10",
        "status": "IN_PROGRESS",
    }
    upsert_inventory(
        path,
        first,
    )

    with pytest.raises(
        BaselineError,
        match="not READY",
    ):
        lookup_inventory(
            path,
            "sw1203",
        )

    second = dict(
        first,
        status="READY",
    )
    upsert_inventory(
        path,
        second,
    )
    row = lookup_inventory(
        path,
        "SW1203",
    )
    assert (
        row["ex4400_ip"]
        == "10.1.1.10"
    )
    assert row["status"] == "READY"


def test_cli_module_imports():
    from ex4400_baseline import cli

    assert callable(cli.main)


def test_lab_model_policy():
    from ex4400_baseline.cli import _allowed_target_model

    assert _allowed_target_model("EX4400-48F", "production")
    assert _allowed_target_model("EX9214", "lab")
    assert _allowed_target_model("VJUNOS-SWITCH", "lab")
    assert not _allowed_target_model("EX9214", "production")
    assert not _allowed_target_model("QFX5700", "lab")


def test_cli_has_separate_ex4400_credentials():
    from ex4400_baseline.cli import _parser

    args = _parser().parse_args([
        "172.16.163.10",
        "--username", "radius-user",
        "--ex4400-username", "local-admin",
        "--dry-run",
    ])
    assert args.username == "radius-user"
    assert args.ex4400_username == "local-admin"
    assert args.dry_run is True
