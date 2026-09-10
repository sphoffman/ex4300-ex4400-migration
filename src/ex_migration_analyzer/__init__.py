"""Offline analysis for EX4300-to-EX4400 migrations."""

__version__ = "0.9.0"

# Current analysis contract: promote the voice VLAN that discovery already
# resolved from the EX4300 configuration into template_variables so the planner
# and provisioner can bind it per migration. No site-wide voice VLAN exists.
from . import core as _core

_original_analyze = _core.analyze


def _analyze_with_voice(snapshot, envelope, policy, policy_digest, approval_digest, analyzer_version, history=None):
    result = _original_analyze(
        snapshot,
        envelope,
        policy,
        policy_digest,
        approval_digest,
        analyzer_version,
        history=history,
    )
    voice = snapshot.get("voice_policy", {}) or {}
    variables = result.setdefault("template_variables", {})
    variables["voice_vlan_name"] = voice.get("vlan_name") if voice.get("valid") else None
    variables["voice_vlan_id"] = voice.get("vlan_id") if voice.get("valid") else None
    return result


_core.analyze = _analyze_with_voice
