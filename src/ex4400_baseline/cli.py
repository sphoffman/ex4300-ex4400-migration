from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from pathlib import Path

from .core import (
    BaselineError,
    find_arp_ip,
    load_config,
    parse_arp_xml,
    parse_ethernet_switching_xml,
    select_local_mac,
    sha256_file,
    upsert_inventory,
    utc_now,
)


_EX4400_MODEL = re.compile(r"^EX4400(?:-|$)", re.IGNORECASE)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ex4400-baseline",
        description=(
            "Discover a replacement EX4400 through the source EX4300 management VLAN, "
            "resolve its vme address from the gateway ARP table, install a static "
            "baseline, and publish migration inventory."
        ),
    )
    parser.add_argument(
        "ex4300",
        help="source EX4300 management address",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/ex4400-baseline.json"),
        help=(
            "baseline discovery configuration "
            "(default: config/ex4400-baseline.json)"
        ),
    )
    parser.add_argument(
        "--port",
        help=(
            "optional EX4300 physical interface override, "
            "for example ge-4/0/47"
        ),
    )
    parser.add_argument(
        "--username",
        help="operator username; prompted when omitted",
    )
    parser.add_argument(
        "--password-env",
        help=(
            "read the shared device password from this "
            "environment variable instead of prompting"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "perform discovery and commit-check, then "
            "roll back instead of committing"
        ),
    )
    return parser


def _credentials(args):
    username = str(
        args.username
        or input("Username: ")
    ).strip()
    if not username:
        raise BaselineError(
            "username cannot be empty"
        )

    if args.password_env:
        if args.password_env not in os.environ:
            raise BaselineError(
                "password environment variable %s is not set"
                % args.password_env
            )
        password = os.environ[
            args.password_env
        ]
    else:
        password = getpass.getpass(
            "Password: "
        )

    if not password:
        raise BaselineError(
            "password cannot be empty"
        )

    return username, password


def _open_device(
    host,
    username,
    password,
    connection,
):
    from jnpr.junos import Device

    dev = Device(
        host=str(host),
        user=username,
        passwd=password,
        port=int(
            connection["netconf_port"]
        ),
        gather_facts=True,
    )
    dev.open(
        auto_probe=int(
            connection[
                "auto_probe_seconds"
            ]
        ),
        hostkey_verify=False,
    )
    return dev


def _close(dev):
    if dev is None:
        return
    try:
        dev.close()
    except Exception:
        pass


def _write_status(
    inventory_path,
    record,
    status,
    error="",
):
    updated = dict(record)
    updated["status"] = status
    updated["updated_at"] = utc_now()
    updated["last_error"] = str(
        error or ""
    )
    upsert_inventory(
        inventory_path,
        updated,
    )
    return updated


def _print_summary(
    record,
    config,
    template,
    dry_run,
):
    print(
        "\nEX4400 Baseline Provisioning"
    )
    print(
        "============================"
    )

    print("\nEX4300")
    print(
        "  Hostname:         %s"
        % record["migration_id"]
    )
    print(
        "  Address:          %s"
        % record["ex4300_ip"]
    )
    print(
        "  Mgmt VLAN:        %s"
        % record["management_vlan_id"]
    )
    if record.get(
        "management_network"
    ):
        print(
            "  Mgmt network:     %s"
            % record["management_network"]
        )

    print("\nEX4400 Discovery")
    print(
        "  Local interface:  %s"
        % record["ex4300_interface"]
    )
    print(
        "  MAC address:      %s"
        % record["ex4400_mac"]
    )

    print("\nGateway Lookup")
    print(
        "  Router:           %s"
        % config[
            "gateway_router"
        ]["address"]
    )
    print(
        "  EX4400 address:   %s"
        % record["ex4400_ip"]
    )

    print("\nEX4400")
    print(
        "  Hostname:         %s"
        % record["ex4400_hostname"]
    )
    print(
        "  Model:            %s"
        % record["ex4400_model"]
    )
    print(
        "  Serial:           %s"
        % record["ex4400_serial"]
    )
    if record.get(
        "ex4400_ssh_host_key_sha256"
    ):
        print(
            "  SSH host key:     %s"
            % record[
                "ex4400_ssh_host_key_sha256"
            ]
        )

    print("\nBaseline")
    print(
        "  Config:           %s"
        % template
    )
    print(
        "  Config check:     PASS"
    )
    print(
        "  Commit:           %s"
        % (
            "SKIPPED (dry-run)"
            if dry_run
            else "SUCCESS"
        )
    )

    print("\nMigration inventory")
    print(
        "  File:             %s"
        % config["inventory"][
            "csv_file"
        ]
    )
    print(
        "  Status:           %s"
        % record["status"]
    )

    if not dry_run:
        print(
            "\nREADY FOR MIGRATION"
        )
        print(
            "  Migration ID:     %s"
            % record["migration_id"]
        )
        print(
            "  EX4400 IP:        %s"
            % record["ex4400_ip"]
        )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)

    record = {
        "migration_id": "",
        "ex4300_ip": str(
            args.ex4300
        ),
        "ex4400_ip": "",
        "ex4400_mac": "",
        "ex4300_interface": "",
        "management_vlan_id": "",
        "management_network": "",
        "ex4400_hostname": "",
        "ex4400_model": "",
        "ex4400_serial": "",
        "ex4400_ssh_host_key_sha256": "",
        "baseline_template_sha256": "",
        "status": "",
        "updated_at": "",
        "last_error": "",
    }

    inventory_path = None
    source = None
    router = None
    target = None

    try:
        config = load_config(
            args.config
        )
        inventory_path = Path(
            config["inventory"][
                "csv_file"
            ]
        )
        management = config[
            "management"
        ]
        connection = config[
            "connection"
        ]
        template = Path(
            config["baseline"][
                "config_file"
            ]
        )

        if not template.is_file():
            raise BaselineError(
                "baseline configuration file "
                "not found: %s"
                % template
            )
        if not template.read_text(
            encoding="utf-8"
        ).strip():
            raise BaselineError(
                "baseline configuration file "
                "is empty: %s"
                % template
            )

        username, password = (
            _credentials(args)
        )

        print(
            "Connecting to EX4300 %s..."
            % args.ex4300
        )
        source = _open_device(
            args.ex4300,
            username,
            password,
            connection,
        )

        migration_id = str(
            (source.facts or {}).get(
                "hostname"
            )
            or ""
        ).strip().lower()

        if not migration_id:
            raise BaselineError(
                "source EX4300 hostname "
                "could not be determined"
            )

        record[
            "migration_id"
        ] = migration_id
        record[
            "management_vlan_id"
        ] = str(
            management["vlan_id"]
        )
        record[
            "management_network"
        ] = str(
            management.get(
                "network"
            )
            or ""
        )

        _write_status(
            inventory_path,
            record,
            "IN_PROGRESS",
        )

        switching_xml = (
            source.rpc
            .get_ethernet_switching_table_information(
                detail=True
            )
        )
        entries = (
            parse_ethernet_switching_xml(
                switching_xml
            )
        )
        candidate = (
            select_local_mac(
                entries,
                management[
                    "vlan_id"
                ],
                management[
                    "uplink_interfaces"
                ],
                args.port,
            )
        )

        record[
            "ex4400_mac"
        ] = candidate.mac
        record[
            "ex4300_interface"
        ] = candidate.interface

        print(
            "  Found %s on %s "
            "in VLAN %s."
            % (
                candidate.mac,
                candidate.interface,
                management[
                    "vlan_id"
                ],
            )
        )

        _close(source)
        source = None

        gateway = config[
            "gateway_router"
        ]
        print(
            "Connecting to gateway "
            "router %s..."
            % gateway["address"]
        )

        router = _open_device(
            gateway["address"],
            username,
            password,
            connection,
        )

        kwargs = {
            "no_resolve": True,
        }
        if gateway.get(
            "routing_instance"
        ):
            kwargs[
                "routing_instance"
            ] = str(
                gateway[
                    "routing_instance"
                ]
            )

        arp_xml = (
            router.rpc
            .get_arp_table_information(
                **kwargs
            )
        )

        arp = find_arp_ip(
            parse_arp_xml(
                arp_xml
            ),
            candidate.mac,
            management.get(
                "network"
            ),
        )

        record[
            "ex4400_ip"
        ] = arp.ip

        print(
            "  ARP resolved %s -> %s."
            % (
                candidate.mac,
                arp.ip,
            )
        )

        _close(router)
        router = None

        try:
            from ex_migration_provisioner.write import ssh_host_key_fingerprint

            record[
                "ex4400_ssh_host_key_sha256"
            ] = (
                ssh_host_key_fingerprint(
                    arp.ip,
                    int(
                        connection[
                            "netconf_port"
                        ]
                    ),
                )
            )
        except Exception as exc:
            raise BaselineError(
                "could not fingerprint "
                "EX4400 SSH endpoint: %s"
                % exc
            )

        print(
            "Connecting to discovered "
            "EX4400 %s..."
            % arp.ip
        )

        target = _open_device(
            arp.ip,
            username,
            password,
            connection,
        )

        facts = target.facts or {}
        model = str(
            facts.get("model") or ""
        ).strip()
        hostname = str(
            facts.get("hostname") or ""
        ).strip()
        serial = str(
            facts.get(
                "serialnumber"
            )
            or ""
        ).strip()

        if not _EX4400_MODEL.match(
            model
        ):
            raise BaselineError(
                "discovered device %s "
                "reports model %r, "
                "not an EX4400"
                % (
                    arp.ip,
                    model,
                )
            )

        if not serial:
            raise BaselineError(
                "EX4400 serial number "
                "could not be determined"
            )

        record[
            "ex4400_model"
        ] = model
        record[
            "ex4400_hostname"
        ] = hostname
        record[
            "ex4400_serial"
        ] = serial
        record[
            "baseline_template_sha256"
        ] = sha256_file(
            template
        )

        _write_status(
            inventory_path,
            record,
            "DISCOVERED",
        )

        from jnpr.junos.utils.config import Config
        from jnpr.junos.exception import (
            CommitError,
            ConfigLoadError,
            LockError,
            UnlockError,
        )

        cu = Config(target)
        locked = False

        try:
            cu.lock()
            locked = True

            cu.load(
                path=str(template),
                format=config[
                    "baseline"
                ]["format"],
                merge=True,
            )

            if (
                cu.commit_check()
                is not True
            ):
                raise BaselineError(
                    "EX4400 commit check "
                    "did not return PASS"
                )

            if args.dry_run:
                cu.rollback()
                record = (
                    _write_status(
                        inventory_path,
                        record,
                        "DRY_RUN",
                    )
                )
            else:
                cu.commit(
                    comment=(
                        "Install EX4400 "
                        "baseline before "
                        "migration"
                    )
                )
                record = (
                    _write_status(
                        inventory_path,
                        record,
                        "READY",
                    )
                )

        except (
            ConfigLoadError,
            CommitError,
            LockError,
            UnlockError,
        ) as exc:
            raise BaselineError(
                "EX4400 baseline transaction "
                "failed: %s"
                % exc
            )
        finally:
            if locked:
                try:
                    cu.unlock()
                except Exception:
                    pass

        _print_summary(
            record,
            config,
            template,
            args.dry_run,
        )
        return 0

    except KeyboardInterrupt:
        error = (
            "operator interrupted "
            "baseline provisioning"
        )
        if (
            inventory_path is not None
            and record.get(
                "migration_id"
            )
        ):
            try:
                _write_status(
                    inventory_path,
                    record,
                    "FAILED",
                    error,
                )
            except Exception:
                pass

        print(
            "\nERROR: %s"
            % error,
            file=sys.stderr,
        )
        return 130

    except Exception as exc:
        error = str(exc)

        if (
            inventory_path is not None
            and record.get(
                "migration_id"
            )
        ):
            try:
                _write_status(
                    inventory_path,
                    record,
                    "FAILED",
                    error,
                )
            except Exception:
                pass

        print(
            "ERROR: %s"
            % error,
            file=sys.stderr,
        )
        return 2

    finally:
        _close(source)
        _close(router)
        _close(target)


if __name__ == "__main__":
    raise SystemExit(main())
