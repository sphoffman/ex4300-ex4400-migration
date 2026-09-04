from __future__ import annotations

import re


_MAC_HEX = re.compile(r"[^0-9a-fA-F]")
_IFACE = re.compile(
    r"^(?P<media>[a-z]+)-(?P<member>\d+)/(?P<pic>\d+)/(?P<port>\d+)"
    r"(?:\.(?P<unit>\d+))?$"
)
_AE = re.compile(r"^ae(?P<number>\d+)(?:\.(?P<unit>\d+))?$")


def normalize_mac(value: str) -> str:
    compact = _MAC_HEX.sub("", value).lower()
    if len(compact) != 12:
        raise ValueError(f"invalid MAC address: {value!r}")
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def split_interface(value: str) -> dict[str, object]:
    name = value.strip()
    match = _IFACE.match(name)
    if match:
        fields = match.groupdict()
        physical = name.split(".", 1)[0]
        return {
            "reported": name,
            "physical": physical,
            "unit": int(fields["unit"]) if fields["unit"] else None,
            "media": fields["media"],
            "member": int(fields["member"]),
            "pic": int(fields["pic"]),
            "port": int(fields["port"]),
            "class": "physical",
        }
    match = _AE.match(name)
    if match:
        return {
            "reported": name,
            "physical": name.split(".", 1)[0],
            "unit": int(match.group("unit")) if match.group("unit") else None,
            "media": "ae",
            "member": None,
            "pic": None,
            "port": None,
            "class": "ae",
        }
    return {
        "reported": name,
        "physical": name.split(".", 1)[0],
        "unit": int(name.rsplit(".", 1)[1]) if "." in name and name.rsplit(".", 1)[1].isdigit() else None,
        "media": None,
        "member": None,
        "pic": None,
        "port": None,
        "class": "other",
    }


def classify_learning_interface(value: str, configured: dict[str, InterfaceStateLike] | None = None) -> str:
    parsed = split_interface(value)
    if parsed["class"] == "ae":
        return "ae"
    if parsed["class"] != "physical":
        return "other"
    state = (configured or {}).get(str(parsed["physical"]))
    if state and getattr(state, "ae_parent", None):
        return "ae_member"
    if state and getattr(state, "effective_mode", None) == "trunk":
        return "physical_trunk"
    return "physical_access"


class InterfaceStateLike:
    ae_parent: str | None
    effective_mode: str | None

