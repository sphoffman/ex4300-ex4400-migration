# Old-switch recovery policy

`site-init` records whether retired EX4300 switches are expected to remain powered and reachable after cutover.

The setting is stored in `config/site.json` as `old_switch_recovery_required` so changing this operator workflow policy does not invalidate the approved QFX site-profile or discovery digest.

- `old_switch_recovery_required: true` preserves the original behavior: prestage moves the approved replacement OOB address to `vme.0` in `mgmt_junos` on the old EX4300 so it can remain reachable after the cable move.
- `old_switch_recovery_required: false` treats that step as not required. Prestage skips the old-switch role handoff and performs no old-EX recovery write because the retired switch is expected to be powered down or removed.

Settings created before this policy field existed default to `true` for backward compatibility.
