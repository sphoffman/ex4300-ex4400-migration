from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import cli_base as base
from .cabling_report import (
    build_facilities_report,
    choose_endpoint_transactions,
    write_facilities_report,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner cabling-report",
        description=(
            "Offline-generate a cumulative facilities cable relabel report from every "
            "integrity-valid committed-and-confirmed endpoint activation transaction "
            "bound to the current approved migration plan. Only endpoints whose "
            "physical interface changed are listed."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument(
        "--endpoint-transaction-id",
        help=(
            "diagnostic override: limit the report to one committed endpoint transaction; "
            "the transaction must still be bound to the current approved migration plan"
        ),
    )
    return parser


def run(argv):
    args = _parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected_plan = base.choose_approved_plan(migration_root)
    selected = choose_endpoint_transactions(
        migration_root,
        selected_plan["plan_digest"],
        args.endpoint_transaction_id,
    )
    report = build_facilities_report(selected, selected_plan["plan_digest"])
    destination, action = write_facilities_report(migration_root, report)
    stats = report["statistics"]

    print("Facilities cable relabel report")
    print("  Migration: %s" % report["migration_id"])
    print("  Endpoint transactions aggregated: %d" % stats["contributing_endpoint_transactions"])
    for source in report["source_endpoint_transactions"]:
        print("    %s" % source["transaction_id"])
    print("  Activated endpoint intents: %d" % stats["activated_endpoint_intents"])
    print("  Same-position/no relabel: %d" % stats["same_position_no_relabel"])
    print("  Relabel required: %d" % stats["relabel_required"])
    print("  Unresolved operator holds: %d" % stats["operator_holds"])
    print("  Report: %s (%s)" % (report["report_id"], action))
    print("  Markdown: %s" % (destination / "report.md"))
    print("  CSV: %s" % (destination / "report.csv"))
    print("  Device writes performed: no")
    return 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        return run(values)
    except (
        base.AnalysisError,
        base.ProvisioningError,
        base.WriteError,
        OSError,
        ValueError,
    ) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
