import pytest

from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.endpoint_stage_cli import _bind_lab_identity_transport


def _identity(transport="10.255.3.16", logical="10.0.0.15"):
    return {
        "observed": {
            "connection": {
                "address": logical,
                "transport_address": transport,
                "port": 830,
                "ssh_host_key_sha256": "SHA256:test",
            }
        }
    }


def test_lab_transport_is_taken_from_selected_identity():
    profile = {
        "schema_version": "1.0",
        "environment": "lab",
        "postcutover_ex_access": {
            "mode": "transport-override",
            "port": 830,
        },
    }
    value = _bind_lab_identity_transport(profile, _identity("10.255.3.16"))
    assert value["postcutover_ex_access"]["transport_address"] == "10.255.3.16"


def test_lab_transport_rejects_identity_without_distinct_override():
    profile = {
        "schema_version": "1.0",
        "environment": "lab",
        "postcutover_ex_access": {
            "mode": "transport-override",
            "port": 830,
        },
    }
    with pytest.raises(ProvisioningError):
        _bind_lab_identity_transport(profile, _identity("10.0.0.15", "10.0.0.15"))


def test_production_profile_is_not_modified():
    profile = {
        "schema_version": "1.0",
        "environment": "production",
        "postcutover_ex_access": {
            "mode": "direct-management",
            "port": 830,
        },
    }
    assert _bind_lab_identity_transport(profile, _identity()) == profile
