from __future__ import annotations

from copy import deepcopy

from .core import ProvisioningError


_DEFERRED_DEVICE_CHECKS = (
    "physical_interface_up",
    "lacp_collecting_distributing",
    "lldp_neighbor_present",
)

_REQUIRED_PAIR_CHECKS = (
    "interface_symmetry",
    "ae_symmetry",
    "lacp_system_id_symmetry",
)

_REVALIDATION_REQUIRED = [
    "device.physical_interface_up",
    "device.lacp_collecting_distributing",
    "device.lldp_neighbor_present",
    "pair.lldp_neighbor_symmetry",
]


def scope_pre_stage_qfx_preflight(raw):
    """Convert full live-peer observations into EX4400 pre-stage readiness.

    prepare must prove the QFX policy/static attachment before it can create a
    renderable package. Link/LACP/LLDP operational state is deliberately deferred
    because the new EX may not advertise or aggregate until after pre-stage is
    applied. Positive contradictory LLDP evidence is still fail-closed.
    """
    if raw.get("schema_version") != "1.0":
        raise ProvisioningError("unsupported raw QFX preflight schema")

    value = deepcopy(raw)
    value["schema_version"] = "1.1"
    value["readiness_scope"] = "EX4400_PRE_STAGE"
    deferred = []

    required_device_checks = set()
    for item in value.get("devices", []):
        checks = item.get("checks", {})
        required = [
            name
            for name in checks
            if name not in _DEFERRED_DEVICE_CHECKS
        ]
        required_device_checks.update(required)
        failed_required = [name for name in required if checks.get(name) is not True]
        item_deferred = [
            name for name in _DEFERRED_DEVICE_CHECKS
            if checks.get(name) is not True
        ]
        item["deferred_checks"] = item_deferred
        item["result"] = "PASS" if not failed_required else "FAIL"
        deferred.extend(
            "%s.%s" % (item.get("role", "device"), name)
            for name in item_deferred
        )

    pair_checks = value.get("pair_checks", {})
    failed_pair_required = [
        name for name in _REQUIRED_PAIR_CHECKS
        if pair_checks.get(name) is not True
    ]

    # LLDP is expected to be absent before the new EX pre-stage enables it. If
    # neither QFX sees a neighbor, defer symmetry. If either side sees a neighbor,
    # asymmetric evidence is contradictory and remains a hard failure.
    neighbors = [
        str(item.get("lldp_neighbor_system_name") or "").strip()
        for item in value.get("devices", [])
    ]
    if pair_checks.get("lldp_neighbor_symmetry") is not True:
        if not any(neighbors):
            deferred.append("pair.lldp_neighbor_symmetry")
        else:
            failed_pair_required.append("lldp_neighbor_symmetry")

    value["required_device_checks"] = sorted(required_device_checks)
    value["required_pair_checks"] = list(_REQUIRED_PAIR_CHECKS)
    value["deferred_checks"] = sorted(set(deferred))
    value["revalidation_required"] = list(_REVALIDATION_REQUIRED)

    devices_pass = all(
        item.get("result") == "PASS" for item in value.get("devices", [])
    )
    value["result"] = (
        "PASS" if devices_pass and not failed_pair_required else "FAIL"
    )
    return value


def print_pre_stage_qfx_preflight(preflight):
    print("\nQFX read-only pre-stage preflight")
    for item in sorted(preflight["devices"], key=lambda value: value["role"]):
        print("  %s %s (%s) %s -> %s: %s" % (
            item["expected_hostname"],
            item["management_address"],
            item["observed_model"] or "unknown-model",
            item["physical_interface"],
            item["ae_interface"],
            item["result"],
        ))
        if item["result"] != "PASS":
            for name, passed in item["checks"].items():
                if not passed and name not in item.get("deferred_checks", []):
                    print("    FAIL: %s" % name)
        for name in item.get("deferred_checks", []):
            print("    DEFERRED: %s" % name)

    deferred = set(preflight.get("deferred_checks", []))
    for name, passed in preflight["pair_checks"].items():
        if passed:
            continue
        qualified = "pair.%s" % name
        if qualified in deferred:
            print("  Pair DEFERRED: %s" % name)
        else:
            print("  Pair FAIL: %s" % name)

    print("  Result: %s" % preflight["result"])
    if preflight.get("deferred_checks"):
        print(
            "  Live link/LACP/LLDP checks are deferred until after EX pre-stage; "
            "they remain mandatory before QFX writes or cutover."
        )
