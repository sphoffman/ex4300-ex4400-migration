from __future__ import annotations

"""Current site CLI compatibility layer.

The historical site implementation still carries a dormant Temp-Management
field for old artifact/schema compatibility.  Current operator workflows must
not give VLAN 3999 any live semantics on QFX migration AEs.  Install an inert
legacy VLAN ID before delegating so pre-stage discovery allows only an empty or
management-only AE, and post-stage validation requires management-only state.
"""

from . import cli as legacy


_EXTERNAL_TEMP_SENTINEL = -1


def install_current_site_policy():
    legacy._legacy_temp_vlan_id = lambda _profile: _EXTERNAL_TEMP_SENTINEL


def main(argv=None):
    install_current_site_policy()
    return legacy.main(argv)
