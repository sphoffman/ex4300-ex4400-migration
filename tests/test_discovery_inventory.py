from pathlib import Path

import pytest

from ex_migration_discovery.cli import Target, _resolve, targets_from_csv


def test_inventory_parses_per_host_collection_options(tmp_path):
    path = tmp_path / "switches.csv"
    path.write_text(
        "old_address,new_fxp_address,duration,interval,port,management_vlan,no_host_key_check\n"
        "10.0.0.1,192.0.2.10/24,300,30,830,163,true\n"
        "10.0.0.2,,600,60,1830,200,false\n",
        encoding="utf-8",
    )

    rows = targets_from_csv(path)
    assert rows == [
        Target("10.0.0.1", "192.0.2.10/24", 300, 30, 830, 163, True),
        Target("10.0.0.2", None, 600, 60, 1830, 200, False),
    ]


def test_inventory_accepts_management_vlan_id_alias(tmp_path):
    path = tmp_path / "switches.csv"
    path.write_text(
        "old_address,management_vlan_id\n10.0.0.1,163\n",
        encoding="utf-8",
    )
    assert targets_from_csv(path)[0].management_vlan == 163


def test_cli_value_overrides_inventory_then_site_default():
    assert _resolve(60, 300, 1800) == 60
    assert _resolve(None, 300, 1800) == 300
    assert _resolve(None, None, 1800) == 1800


def test_inventory_rejects_invalid_boolean(tmp_path):
    path = tmp_path / "switches.csv"
    path.write_text(
        "old_address,no_host_key_check\n10.0.0.1,maybe\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid boolean"):
        targets_from_csv(path)
