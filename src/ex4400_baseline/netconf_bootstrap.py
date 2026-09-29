from __future__ import annotations

import re
import socket
import time

from .core import BaselineError


_EX4300_MODEL = re.compile(r"\bEX4300(?:-[A-Z0-9]+)?\b", re.IGNORECASE)


def tcp_open(host, port, timeout=3.0):
    try:
        with socket.create_connection((str(host), int(port)), timeout=float(timeout)):
            return True
    except OSError:
        return False


def _read_until(channel, markers, timeout=20.0):
    deadline = time.time() + float(timeout)
    chunks = []
    while time.time() < deadline:
        if channel.recv_ready():
            data = channel.recv(65535).decode("utf-8", errors="replace")
            chunks.append(data)
            text = "".join(chunks)
            if any(marker in text for marker in markers):
                return text
        else:
            time.sleep(0.1)
    raise BaselineError("timed out waiting for EX4300 SSH CLI response")


def _command(channel, command, timeout=30.0):
    channel.send(command.rstrip() + "\n")
    return _read_until(channel, ("> ", "# ", ">", "#"), timeout=timeout)


def ensure_netconf(host, username, password, netconf_port=830, ssh_port=22, wait_seconds=30):
    """Ensure NETCONF/SSH is enabled on a source EX4300 using ordinary SSH/22.

    Returns ALREADY_ENABLED or ENABLED.  The only configuration statement this
    helper is permitted to add is `set system services netconf ssh`.
    """
    if tcp_open(host, netconf_port):
        return "ALREADY_ENABLED"

    try:
        import paramiko
    except ImportError as exc:
        raise BaselineError("Paramiko is required to bootstrap NETCONF: %s" % exc)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=str(host),
            port=int(ssh_port),
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=15,
            banner_timeout=15,
        )
        channel = client.invoke_shell(width=200, height=1000)
        _read_until(channel, ("> ", "# ", ">", "#"), timeout=20)

        hardware = _command(channel, "show chassis hardware | no-more", timeout=30)
        if not _EX4300_MODEL.search(hardware):
            raise BaselineError(
                "NETCONF bootstrap refused: %s did not identify as an EX4300" % host
            )

        services = _command(
            channel,
            "show configuration system services | display set | match netconf",
            timeout=20,
        )
        if "set system services netconf ssh" not in services:
            _command(channel, "configure", timeout=20)
            _command(channel, "set system services netconf ssh", timeout=20)
            commit = _command(channel, 'commit comment "Enable NETCONF for EX4400 migration automation"', timeout=120)
            if "commit complete" not in commit.lower():
                try:
                    _command(channel, "rollback 0", timeout=20)
                    _command(channel, "exit", timeout=20)
                except Exception:
                    pass
                raise BaselineError("EX4300 NETCONF bootstrap commit did not report commit complete")
            _command(channel, "exit", timeout=20)

    except BaselineError:
        raise
    except Exception as exc:
        raise BaselineError("could not bootstrap NETCONF on EX4300 %s over SSH/22: %s" % (host, exc))
    finally:
        try:
            client.close()
        except Exception:
            pass

    deadline = time.time() + int(wait_seconds)
    while time.time() < deadline:
        if tcp_open(host, netconf_port):
            return "ENABLED"
        time.sleep(1)

    raise BaselineError(
        "NETCONF was configured on EX4300 %s but TCP/%s did not become reachable within %s seconds"
        % (host, netconf_port, wait_seconds)
    )
