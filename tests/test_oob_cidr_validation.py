import pytest

from ex_migration_operator import current_cli
from ex_migration_operator.core import OperatorError


def test_replacement_oob_requires_explicit_prefix():
    with pytest.raises(OperatorError, match="explicit CIDR prefix"):
        current_cli._validated_oob_address("10.255.3.16")


def test_replacement_oob_accepts_valid_ipv4_cidr():
    assert current_cli._validated_oob_address("10.255.3.16/24") == "10.255.3.16/24"


def test_replacement_oob_allows_intentional_host_prefix():
    assert current_cli._validated_oob_address("10.255.3.16/32") == "10.255.3.16/32"


def test_replacement_oob_rejects_invalid_cidr():
    with pytest.raises(OperatorError, match="not valid IPv4 CIDR"):
        current_cli._validated_oob_address("10.255.3.999/24")
