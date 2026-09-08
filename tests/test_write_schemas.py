import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_live_write_artifact_schemas_are_valid():
    for path in (
        "schemas/bootstrap-identity-1.0.json",
        "schemas/prestage-transaction-1.0.json",
    ):
        schema = load(path)
        Draft202012Validator.check_schema(schema)
