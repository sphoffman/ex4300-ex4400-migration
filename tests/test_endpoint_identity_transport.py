from ex_migration_provisioner.endpoint_stage_cli import _bind_lab_identity_transport


def _identity(address="10.255.3.16", transport=None):
    connection = {
        "address": address,
        "port": 830,
        "ssh_host_key_sha256": "SHA256:test",
    }
    if transport is not None:
        connection["transport_address"] = transport
    return {"observed": {"connection": connection}}


def test_lab_access_is_taken_from_authoritative_oob_identity():
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


def test_legacy_identity_transport_remains_supported():
    profile = {
        "schema_version": "1.0",
        "environment": "lab",
        "postcutover_ex_access": {
            "mode": "transport-override",
            "port": 830,
        },
    }
    value = _bind_lab_identity_transport(
        profile,
        _identity("10.0.0.15", transport="10.255.3.16"),
    )
    assert value["postcutover_ex_access"]["transport_address"] == "10.255.3.16"


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
