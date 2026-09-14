import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ex_migration_provisioner.attachment import (
    build_attachment_artifact,
    discover_qfx_attachment,
)
from test_provisioner import policy


ROOT = Path(__file__).resolve().parents[1]
TARGET = "home1-ex4400-vc-fd-sw1203"


class FakeQFX:
    def __init__(
        self,
        hostname,
        physical="et-0/0/5",
        ae="ae2",
        system_id="00:01:02:03:04:02",
        target=TARGET,
        force_up=False,
        lacp_up=True,
        explicit_lacp_active=True,
        baseline=(163,),
        vlan_scope="top-level",
        conflicting_vlan_name=False,
        lldp_parent=None,
    ):
        self.facts = {"hostname": hostname, "model": "PTX10001-36MR"}
        self.physical = physical
        self.ae = ae
        self.system_id = system_id
        self.target = target
        self.force_up = force_up
        self.lacp_up = lacp_up
        self.explicit_lacp_active = explicit_lacp_active
        self.baseline = baseline
        self.vlan_scope = vlan_scope
        self.conflicting_vlan_name = conflicting_vlan_name
        self.lldp_parent = lldp_parent or ae
        self.commands = []

    def cli(self, command, warning=False):
        self.commands.append(command)
        if command == "show lldp neighbors":
            return "\n".join([
                "Local Interface    Parent Interface    Chassis Id                               Port info          System Name",
                "%s           %s                 2c:6b:f5:94:59:c0                        ge-0/0/0            %s"
                % (self.physical, self.lldp_parent, self.target),
                "et-0/0/1           -                   f2:6a:08:5e:23:92                        eth1                host4",
                "",
            ])
        if command == "show configuration interfaces %s | display set" % self.physical:
            return "set interfaces %s ether-options 802.3ad %s\n" % (
                self.physical,
                self.ae,
            )
        if command == "show configuration interfaces %s | display set" % self.ae:
            lines = [
                "set interfaces %s aggregated-ether-options lacp system-id %s"
                % (self.ae, self.system_id),
                "set interfaces %s esi auto-derive type-1-lacp" % self.ae,
                "set interfaces %s esi all-active" % self.ae,
            ]
            if self.explicit_lacp_active:
                lines.insert(
                    0,
                    "set interfaces %s aggregated-ether-options lacp active" % self.ae,
                )
            if self.force_up:
                lines.append(
                    "set interfaces %s aggregated-ether-options lacp force-up"
                    % self.ae
                )
            names = {163: "v163", 3999: "TEMP-RECOVERY", 999: "EXTRA"}
            for vlan_id in self.baseline:
                lines.append(
                    "set interfaces %s unit 0 family ethernet-switching vlan members %s"
                    % (self.ae, names.get(vlan_id, str(vlan_id)))
                )
            return "\n".join(lines) + "\n"
        if command == "show configuration vlans | display set":
            if self.vlan_scope == "top-level":
                lines = [
                    "set vlans v163 vlan-id 163",
                    "set vlans TEMP-RECOVERY vlan-id 3999",
                    "set vlans EXTRA vlan-id 999",
                ]
                if self.conflicting_vlan_name:
                    lines.append("set vlans v163 vlan-id 999")
                return "\n".join(lines) + "\n"
            return ""
        if command == 'show configuration routing-instances | display set | match " vlan-id "':
            if self.vlan_scope == "routing-instance":
                lines = [
                    "set routing-instances MAC-VRF-1 vlans v163 vlan-id 163",
                    "set routing-instances MAC-VRF-1 vlans TEMP-RECOVERY vlan-id 3999",
                    "set routing-instances MAC-VRF-1 vlans EXTRA vlan-id 999",
                ]
                if self.conflicting_vlan_name:
                    lines.append(
                        "set routing-instances MAC-VRF-2 vlans v163 vlan-id 999"
                    )
                return "\n".join(lines) + "\n"
            return ""
        if command == "show lacp interfaces %s extensive" % self.ae:
            state = "Collecting Distributing" if self.lacp_up else "Detached"
            return "Aggregated interface: %s\n  %s %s\n" % (
                self.ae,
                self.physical,
                state,
            )
        raise AssertionError("unexpected command: %s" % command)


def devices(a=None, b=None):
    return {
        "qfx-a": a or FakeQFX("BD-1"),
        "qfx-b": b or FakeQFX("BD-2"),
    }


def host_keys():
    return {
        "qfx-a": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "qfx-b": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    }


def test_attachment_discovery_learns_matching_existing_ae_from_lldp_ports():
    pair = devices()
    result = discover_qfx_attachment(
        policy(), TARGET, pair, host_keys(), observed_at="2026-09-08T18:00:00Z"
    )
    assert result["result"] == "PASS"
    assert all(result["pair_checks"].values())
    assert [item["physical_interface"] for item in result["devices"]] == [
        "et-0/0/5",
        "et-0/0/5",
    ]
    assert [item["ae_interface"] for item in result["devices"]] == ["ae2", "ae2"]
    assert [item["baseline_vlan_ids"] for item in result["devices"]] == [
        [163],
        [163],
    ]
    for device in pair.values():
        assert "show lldp neighbors" in device.commands
        assert "show lldp neighbors detail" not in device.commands


def test_attachment_discovery_tolerates_legacy_3999_without_managing_it():
    result = discover_qfx_attachment(
        policy(), TARGET,
        devices(a=FakeQFX("BD-1", baseline=(163, 3999)), b=FakeQFX("BD-2", baseline=(163, 3999))),
        host_keys(), observed_at="2026-09-08T18:00:00Z"
    )
    assert result["result"] == "PASS"
    assert all(item["baseline_vlan_ids"] == [163, 3999] for item in result["devices"])


def test_attachment_discovery_rejects_unrelated_extra_baseline_vlan():
    result = discover_qfx_attachment(
        policy(), TARGET,
        devices(a=FakeQFX("BD-1", baseline=(163, 999))),
        host_keys(), observed_at="2026-09-08T18:00:00Z"
    )
    assert result["result"] == "FAIL"
    assert result["devices"][0]["checks"]["baseline_vlans_exact"] is False


def test_attachment_discovery_requires_lldp_parent_to_match_configured_ae():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(a=FakeQFX("BD-1", lldp_parent="ae1")),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert result["devices"][0]["checks"]["lldp_parent_matches_configured_ae"] is False


def test_attachment_discovery_accepts_operational_lacp_without_explicit_active():
    pair = devices(
        a=FakeQFX(
            "BD-1",
            explicit_lacp_active=False,
            vlan_scope="routing-instance",
        ),
        b=FakeQFX(
            "BD-2",
            explicit_lacp_active=False,
            vlan_scope="routing-instance",
        ),
    )
    result = discover_qfx_attachment(
        policy(), TARGET, pair, host_keys(), observed_at="2026-09-08T18:00:00Z"
    )
    assert result["result"] == "PASS"
    for item in result["devices"]:
        assert item["checks"]["lacp_configured"] is True
        assert item["checks"]["lacp_collecting_distributing"] is True
        assert item["baseline_vlan_ids"] == [163]
        assert item["unresolved_vlan_members"] == []


def test_attachment_discovery_fails_when_physical_ports_are_not_symmetric():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(b=FakeQFX("BD-2", physical="et-0/0/4", ae="ae2")),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert result["pair_checks"]["physical_interface_symmetry"] is False


def test_attachment_discovery_fails_when_existing_ae_numbers_differ():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(b=FakeQFX("BD-2", physical="et-0/0/5", ae="ae1", system_id="00:01:02:03:04:01")),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert result["pair_checks"]["ae_symmetry"] is False
    assert result["pair_checks"]["lacp_system_id_symmetry"] is False


def test_attachment_discovery_fails_if_force_up_is_present():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(a=FakeQFX("BD-1", force_up=True)),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert result["devices"][0]["checks"]["lacp_force_up_absent"] is False


def test_attachment_discovery_requires_permanent_management_baseline():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(a=FakeQFX("BD-1", baseline=())),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert result["devices"][0]["checks"]["baseline_vlans_exact"] is False


def test_attachment_discovery_fails_closed_on_conflicting_vlan_name_ids():
    result = discover_qfx_attachment(
        policy(),
        TARGET,
        devices(
            a=FakeQFX(
                "BD-1",
                explicit_lacp_active=False,
                vlan_scope="routing-instance",
                conflicting_vlan_name=True,
            )
        ),
        host_keys(),
        observed_at="2026-09-08T18:00:00Z",
    )
    assert result["result"] == "FAIL"
    assert (
        result["devices"][0]["checks"]["baseline_vlan_names_unambiguous"]
        is False
    )
    assert result["devices"][0]["checks"]["baseline_vlans_exact"] is False
    assert result["devices"][0]["unresolved_vlan_members"] == [
        "v163(ambiguous:163,999)"
    ]


def test_attachment_artifact_is_schema_valid_and_authorizes_no_writes():
    discovery = discover_qfx_attachment(
        policy(), TARGET, devices(), host_keys(), observed_at="2026-09-08T18:00:00Z"
    )
    artifact = build_attachment_artifact(
        "sw1203",
        "0123456789abcdef",
        "a" * 64,
        "lab-site-inventory-test",
        "b" * 64,
        discovery,
        "2026-09-08T18:01:00Z",
    )
    assert artifact["result"] == "PASS"
    assert artifact["safety"]["qfx_writes_authorized"] is False
    assert artifact["safety"]["ex4400_writes_authorized"] is False
    assert artifact["safety"]["force_up_allowed"] is False

    schema = json.loads((ROOT / "schemas/qfx-attachment-1.0.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(artifact)
