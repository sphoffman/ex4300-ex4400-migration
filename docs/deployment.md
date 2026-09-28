# Deployment and Server Setup

This document describes how to deploy and run the EX4300-to-EX4400
migration automation on a new Linux server.

## Architecture

The migration repository runs Python inside the `juniper/pyez` Docker
container. The host server does not need a dedicated Python virtual
environment or PyEZ installation.

The repository includes a portable `./py` launcher that:

- Runs the `juniper/pyez` container
- Mounts the repository at `/scripts`
- Sets `/scripts` as the working directory
- Sets `PYTHONPATH=/scripts/src`
- Invokes Python inside the container

This replaces any server-specific shell `py()` function.

## New Server Requirements

Install:

- Git
- Docker

Verify:

```bash
git --version
docker --version
