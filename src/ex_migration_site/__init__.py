"""Site initialization, QFX discovery, and baseline staging for EX migrations."""

from __future__ import annotations

import re

__version__ = "0.1.1"

# The QFX pair needs the same per-AE LACP system ID on both devices for the
# auto-derived type-1 LACP ESI. This is a site convention, not something that
# can be safely guessed from an unconfigured AE. Keep the convention in the
# operator-created site profile and register it whenever that profile is used.
from . import core as _core

_ORIGINAL_BUILD_PROFILE = _core.build_profile
_ORIGINAL_LOAD_PROFILE = _core.load_profile
_SYSTEM_ID_BASES = {}


def _normalize_system_id_base(value):
    text = str(value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", text):
        raise _core.SiteError(
            "LACP system-ID base must be six hexadecimal octets, for example 02:00:00:00:00:00"
        )
    octets = [int(item, 16) for item in text.split(":")]
    if octets[0] & 0x01:
        raise _core.SiteError("LACP system-ID base must be a unicast MAC address")
    return text


def _register_profile(profile):
    base = _normalize_system_id_base(profile.get("lacp_system_id_base"))
    _SYSTEM_ID_BASES[str(profile["site_id"])] = base
    return profile


def build_profile(
    site_id,
    environment,
    qfx_a,
    qfx_b,
    management_vlan,
    recovery_vlan,
    prestage_vlan,
    excluded_interfaces,
    ae_min,
    ae_max,
    lacp_system_id_base="02:00:00:00:00:00",
):
    value = _ORIGINAL_BUILD_PROFILE(
        site_id,
        environment,
        qfx_a,
        qfx_b,
        management_vlan,
        recovery_vlan,
        prestage_vlan,
        excluded_interfaces,
        ae_min,
        ae_max,
    )
    value["lacp_system_id_base"] = _normalize_system_id_base(
        lacp_system_id_base
    )
    return _register_profile(value)


def load_profile(settings):
    value, path = _ORIGINAL_LOAD_PROFILE(settings)
    return _register_profile(value), path


def _explicit_site_lacp_system_id(site_id, ae):
    base = _SYSTEM_ID_BASES.get(str(site_id))
    if not base:
        raise _core.SiteError(
            "site profile has no registered LACP system-ID base; rerun site-init"
        )
    number = int(str(ae)[2:])
    if not 0 <= number <= 255:
        raise _core.SiteError(
            "AE number %s cannot be encoded by the configured LACP system-ID convention"
            % number
        )
    octets = base.split(":")
    octets[-1] = "%02x" % number
    return ":".join(octets)


_core.build_profile = build_profile
_core.load_profile = load_profile
_core._site_lacp_system_id = _explicit_site_lacp_system_id
