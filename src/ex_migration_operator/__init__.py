"""Operator-facing workflow orchestration for EX4300-to-EX4400 migrations."""

# Importing the current provisioner dispatcher installs the compatibility readers
# used for immutable historical package schemas and the current schema-1.1 package
# layout. The operator status layer must see the same artifact semantics as the
# underlying provisioner commands.
from ex_migration_provisioner import cli as _provisioner_compat  # noqa: F401

__version__ = "0.25.0"
