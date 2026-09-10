"""Digest-bound EX migration preparation, guarded writes, QFX staging, silent-port pre-cutover probing, old-switch recovery, endpoint activation, port-state comparison, facilities reporting, and final recovery/access cleanup."""

__version__ = "0.26.0"
RENDERER_VERSION = "0.9.2"

# Current-only development model: site identity/attachment inventory is generated
# by site discovery/staging, while voice VLAN intent is derived from each
# migration's approved EX4300 evidence. Patch the shared helpers before the CLI
# modules import them by name.
from . import core as _core
from . import current_policy as _current_policy

_core.validate_site_policy = _current_policy.validate_site_policy
_core._render_variables = _current_policy.render_variables

from . import prestage as _prestage

_prestage.validate_pre_cutover_site_policy = _current_policy.validate_site_policy

from . import attachment as _attachment

_attachment.validate_pre_cutover_site_policy = _current_policy.validate_site_policy

from . import qfx_stage as _qfx_stage

_qfx_stage.derive_required_qfx_vlans = _current_policy.derive_required_qfx_vlans
