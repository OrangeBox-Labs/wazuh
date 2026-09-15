# Wazuh Agent RPM for `/opt/ossec`

This directory contains the reproducible build wrapper for an OrangeBox-oriented Wazuh Agent RPM.

The package is built from the upstream Wazuh source using Wazuh's own package generator and installs the agent under `/opt/ossec` instead of `/var/ossec`.

## Target platforms

- AlmaLinux 8, 9 and 10
- Rocky Linux 8, 9 and 10
- RHEL-compatible distributions using the upstream RPM package model

The upstream Wazuh package generator already carries SCA content for AlmaLinux/Rocky 8/9/10. The build itself is performed by the upstream packaging container.

## Build locally

Requirements:

- Git
- Docker

```bash
./build.sh
```

Optional variables:

```bash
WAZUH_VERSION=4.14.7 JOBS=4 ./build.sh
```

The generated RPM is written to `output/`.

## Why `/opt/ossec`?

The default Wazuh RPM installs under `/var/ossec`. OrangeBox uses `/opt/ossec` for this package so the Wazuh agent filesystem is separated from software such as Imunify that may interact with `/var/ossec`.

This is a native package build; it does **not** create a `/var/ossec -> /opt/ossec` symlink.

## Important

The package is generated from upstream Wazuh packaging rather than reimplementing the Wazuh agent RPM spec. This keeps the service scripts, SELinux build flags, dependencies and package layout aligned with the selected Wazuh release.
