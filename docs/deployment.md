# Deployment and Server Setup

This document describes how to deploy and run the EX4300-to-EX4400 migration automation on a Linux server.

For day-to-day command examples, including the difference between running from the Linux host and from inside the `PyEZ1` container, see [`lab-pyez-usage.md`](lab-pyez-usage.md).

## Architecture

The migration repository normally runs Python inside the `juniper/pyez` Docker container. The host server does not need a dedicated Python virtual environment or PyEZ installation.

The repository includes two host-side launchers:

- `./migrate` — guided operator workflow. It launches the PyEZ container and routes to the correct migration module.
- `./py` — generic Python launcher for standalone modules and utility commands.

The `./py` launcher:

- Runs the `juniper/pyez` container.
- Mounts the repository at `/scripts`.
- Sets `/scripts` as the working directory.
- Sets `PYTHONPATH=/scripts/src`.
- Runs the container using the invoking host user's UID/GID so bind-mounted artifacts do not become root-owned.
- Invokes Python inside the container with the arguments supplied after `./py`.

An existing shell function named `py` can still be used if desired, but the repository-managed `./py` wrapper is the preferred portable form because it moves with the repository and reflects the current project launch behavior.

When already logged into an existing PyEZ container, do not launch another Docker container. Use `python migrate.py ...` for the guided workflow or `PYTHONPATH=src python -m ...` for standalone modules. See the lab command guide for examples.

## New Server Requirements

Install:

- Git
- Docker

Verify:

```bash
git --version
docker --version
```

Clone or copy the repository, then from the repository root verify the generic PyEZ launcher:

```bash
./py --version
```

Verify the guided migration launcher:

```bash
./migrate --help
```

Run the test suite:

```bash
./scripts/test.sh
```

## Normal operator commands

From the Linux host:

```bash
./migrate site-prep
./migrate discover
./migrate <migration-id>
```

Standalone utilities use `./py`, for example:

```bash
./py -m ex4400_baseline --help
```

From inside the lab PyEZ container:

```bash
cd ~/scripts
python migrate.py site-prep
python migrate.py discover
python migrate.py <migration-id>
```

Standalone modules inside the container use:

```bash
PYTHONPATH=src python -m ex4400_baseline --help
```
