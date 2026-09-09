from ex_migration_provisioner.old_recovery import build_recovery_transaction, recovery_statement


def test_recovery_statement_uses_vme_for_ex4300_vc():
    assert recovery_statement("vme", "192.0.2.30/24") == (
        "set interfaces vme unit 0 family inet address 192.0.2.30/24"
    )


def test_recovery_transaction_preserves_inband_and_requires_secondary_proof():
    plan = {"plan_id": "plan123"}
    tx = build_recovery_transaction(
        "sw1203",
        plan,
        "1" * 64,
        "2" * 64,
        "production",
        "10.100.163.30",
        "10.100.163.30",
        "vme",
        "192.0.2.30/24",
        "192.0.2.30",
        "SHA256:old",
        "[edit interfaces vme]\n+ unit 0 family inet address 192.0.2.30/24;\n",
        "2026-09-09T12:00:00Z",
        10,
        "DIRECT_RECOVERY_ADDRESS",
    )
    assert tx["recovery"]["interface"] == "vme"
    assert tx["recovery"]["address"] == "192.0.2.30/24"
    assert tx["source_access"]["logical_address"] == "10.100.163.30"
    assert tx["safety"]["existing_inband_management_preserved"] is True
    assert tx["safety"]["secondary_recovery_connection_required"] is True
    assert tx["commit"]["status"] == "APPROVED_PENDING_COMMIT"
