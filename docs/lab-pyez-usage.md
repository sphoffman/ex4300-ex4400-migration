# Lab PyEZ command usage

This guide explains which command form to use when running the EX4300-to-EX4400 migration tools in the lab.

The repository supports two normal execution locations:

1. **On the Linux host/server**, where Docker is available and the repository is checked out.
2. **Inside an already-running PyEZ container**, such as the `PyEZ1:~/scripts$` shell used in the lab.

The important distinction is that the host-side wrappers launch Docker for you. Inside a PyEZ container, Python is already running in the required environment, so you invoke Python directly instead.

## Quick decision table

| Task | From the Linux host | From inside `PyEZ1` |
| --- | --- | --- |
| Guided migration workflow | `./migrate <migration-id>` | `python migrate.py <migration-id>` |
| Initial EX4300 discovery | `./migrate discover` | `python migrate.py discover` |
| Site preparation | `./migrate site-prep` | `python migrate.py site-prep` |
| EX4400 baseline utility | `./py -m ex4400_baseline <EX4300-IP>` | `PYTHONPATH=src python -m ex4400_baseline <EX4300-IP>` |
| Any standalone Python module | `./py -m <module> ...` | `PYTHONPATH=src python -m <module> ...` |
| Full test suite | `./scripts/test.sh` | Prefer running tests from the host; see the testing section below |

## 1. Running from the Linux host

Use this mode when your prompt is on the server that has Docker installed and the repository checked out, for example:

```text
shoffman@lab:/storage/ex4300-ex4400-migration$
```

### Guided migration workflow

Use the repository's `migrate` launcher:

```bash
./migrate site-prep
./migrate discover
./migrate sw1203
```

The `./migrate` launcher starts the `juniper/pyez` Docker image, mounts the repository at `/scripts`, sets the required Python path, and launches the correct migration module.

You do **not** need to prefix these commands with `py` or set `PYTHONPATH` yourself.

### Standalone Python utilities

Use the repository's portable `./py` launcher:

```bash
./py -m ex4400_baseline 172.16.163.10 --dry-run
```

Other examples:

```bash
./py -m ex4400_baseline --help
./py -m ex_migration_discovery.cli --help
./py -m ex_migration_provisioner.cli --help
```

`./py` launches the `juniper/pyez` Docker image with:

```text
repository -> /scripts
working directory -> /scripts
PYTHONPATH -> /scripts/src
```

It also runs the container using the host user's UID/GID so files created in the bind-mounted repository are not left owned by `root`.

### What about the old `py` shell function?

A shell function named `py` can still be used if it launches the same `juniper/pyez` container correctly. For example:

```bash
py -m ex4400_baseline --help
```

However, the repository-managed `./py` script is now the preferred form because it travels with the repository and includes the current mount, working-directory, `PYTHONPATH`, and file-ownership behavior.

There is no project command named `pyez`; older documentation that showed commands such as `pyez -m ...` should be treated as obsolete.

## 2. Running inside the PyEZ container

Use this mode when the shell prompt is already inside the lab PyEZ container, for example:

```text
PyEZ1:~/scripts$
```

At this point **do not use `./py` or the shell `./migrate` wrapper**. Those are host-side Docker launchers. You are already inside the Docker/PyEZ environment.

Start from the repository root:

```bash
cd ~/scripts
```

### Guided migration workflow inside PyEZ1

Use the Python-native migration launcher:

```bash
python migrate.py site-prep
python migrate.py discover
python migrate.py sw1203
```

Explicit phases work the same way:

```bash
python migrate.py sw1203 status
python migrate.py sw1203 analyze
python migrate.py sw1203 build
python migrate.py sw1203 prestage
python migrate.py sw1203 cutover-ready
python migrate.py sw1203 cutover
python migrate.py sw1203 activate
python migrate.py sw1203 validate
python migrate.py sw1203 finalize
```

`migrate.py` adds the repository `src` directory to Python's import path itself, so you do not need to write `PYTHONPATH=src` in front of normal migration commands.

### Standalone utilities inside PyEZ1

Standalone modules do not go through `migrate.py`, so give Python the repository source directory explicitly:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10 --dry-run
```

Other examples:

```bash
PYTHONPATH=src python -m ex4400_baseline --help
PYTHONPATH=src python -m ex_migration_discovery.cli --help
PYTHONPATH=src python -m ex_migration_provisioner.cli --help
```

If you are doing several standalone commands in the same shell, export it once:

```bash
export PYTHONPATH="$PWD/src"
```

Then the commands become:

```bash
python -m ex4400_baseline --help
python -m ex4400_baseline 172.16.163.10 --dry-run
```

The export lasts only for that shell session unless you add it to the container's shell profile.

## 3. When to use `migrate` versus a Python module

Use **`migrate` / `migrate.py`** for the normal EX4300-to-EX4400 migration workflow. It is the operator-facing orchestrator and selects the next safe phase, preserves workflow state, and calls the lower-level modules for you.

Examples:

```bash
./migrate sw1203
```

or inside PyEZ1:

```bash
python migrate.py sw1203
```

Use **`./py -m ...`** or **`PYTHONPATH=src python -m ...`** for standalone utilities that are not a normal guided migration phase.

The EX4400 baseline utility is the main example:

```bash
./py -m ex4400_baseline 172.16.163.10
```

or inside PyEZ1:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10
```

## 4. EX4400 baseline examples

### Host-side Docker wrapper

Dry run:

```bash
./py -m ex4400_baseline 172.16.163.10 --dry-run
```

Normal run:

```bash
./py -m ex4400_baseline 172.16.163.10
```

Optional EX4300 port override:

```bash
./py -m ex4400_baseline 172.16.163.10 --port ge-0/0/1
```

### Inside PyEZ1

Dry run:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10 --dry-run
```

Normal run:

```bash
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10
```

The utility prompts separately for the existing EX4300/router credentials and the replacement EX4400 credentials.

## 5. Testing

From the Linux host, use the project test launcher:

```bash
./scripts/test.sh
```

That script uses `./py`, installs or reuses the bundled test dependencies under `.test-deps`, and runs the entire pytest suite.

Inside PyEZ1, the normal recommendation is to leave the container and run `./scripts/test.sh` from the host. If `.test-deps` is already populated and you specifically need to run tests from inside PyEZ1, the equivalent command is:

```bash
PYTHONPATH=src python -c '
import sys
sys.path.insert(0, ".test-deps")
import pytest
raise SystemExit(pytest.main(["-q"]))
'
```

## 6. Why `pip install -e .` is normally unnecessary

The lab workflow executes directly from the repository source tree. The host-side wrappers set `PYTHONPATH=/scripts/src`, while `migrate.py` adds `src` itself when running inside PyEZ1.

Therefore this is not required for normal lab operation:

```bash
python -m pip install -e .
```

This is especially useful with older PyEZ images whose bundled `pip` does not support modern editable installs from `pyproject.toml`.

## 7. Command cheat sheet

From the **host**:

```bash
# Guided migration
./migrate sw1203

# Standalone EX4400 baseline
./py -m ex4400_baseline 172.16.163.10 --dry-run

# Tests
./scripts/test.sh
```

From **inside PyEZ1**:

```bash
# Guided migration
python migrate.py sw1203

# Standalone EX4400 baseline
PYTHONPATH=src python -m ex4400_baseline 172.16.163.10 --dry-run
```

If you remember only one rule, use this one:

> **Host shell:** `./migrate` for migrations, `./py` for standalone Python modules.  
> **Inside PyEZ1:** `python migrate.py` for migrations, `PYTHONPATH=src python -m ...` for standalone modules.
