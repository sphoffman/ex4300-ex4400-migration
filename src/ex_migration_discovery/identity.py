from __future__ import annotations

import re
from dataclasses import dataclass


HOSTNAME_RULE = re.compile(
    r"^(?P<prefix>.+)-ex4300-vc-fd-(?P<migration_id>[^-]+)$", re.IGNORECASE
)


@dataclass(frozen=True)
class DerivedIdentity:
    migration_id: str
    proposed_hostname: str
    rule: str = "campus-ex4300-vc-fd"


def derive_identity(hostname: str) -> DerivedIdentity:
    match = HOSTNAME_RULE.fullmatch(hostname.strip())
    if not match:
        raise ValueError(
            f"hostname {hostname!r} does not match '*-ex4300-vc-fd-<migration-id>'"
        )
    start, end = match.span(0)
    del start, end
    token = re.search(r"-ex4300-", hostname, re.IGNORECASE)
    assert token is not None
    proposed = hostname[: token.start()] + "-ex4400-" + hostname[token.end() :]
    return DerivedIdentity(match.group("migration_id"), proposed)
