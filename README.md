# KahLuna WARP Gateway

A network appliance that functions as a router, firewall, VPN gateway, DHCP server, DNS forwarder, and diagnostic platform. Managed via a Cisco/Juniper-style CLI shell, a web UI, and optionally through KahLuna Platform Core for central management.

Deployable as a software package on any Linux server, a VM image (Proxmox/VMware), or a custom WARP OS appliance image for bare metal hardware.

## Architecture

```
Management Plane
  CLI Shell (SSH / Console)  |  Web UI (Flask)  |  REST API

Service Layer
  interface | network | endpoint | firewall | dhcp | dns
  shaping | health | diagnostics | client

System Layer
  commander | wireguard | firewall | traffic | routing
  dhcp | dns | interfaces | checker

Linux / WARP OS
  WireGuard | iptables | tc | dnsmasq | iproute2 | systemd
```

The CLI, web UI, and API are peers -- they all call the same service layer. No business logic is duplicated.

## Features

- Cisco/Juniper-style CLI with tab completion, "?" help, and command abbreviation
- Hierarchical CLI modes: exec, privileged, configure, and sub-modes (interface, firewall, VPN, DHCP, DNS)
- Running-config / startup-config serialization (Cisco-style)
- First-boot setup wizard with interface detection and DHCP probing
- WireGuard VPN with three network types: Secure Internet, Remote Resource Gateway, L3VPN Gateway
- iptables firewall with custom rules and port forwarding
- DHCP server (dnsmasq) with static reservations
- DNS forwarding with local overrides
- Traffic shaping (tc) with per-endpoint rate limiting
- Connected client visibility (ARP + DHCP + WireGuard peers)
- Network diagnostics: ping, traceroute, MTR, DNS lookup, packet capture, iperf3
- System health monitoring (CPU, memory, disk, uptime, dependency status)
- KahLuna Nexus integration for central management (standalone, managed, pre-provisioned modes)
- WARP OS appliance image builder (debootstrap, raw/OVA/ISO export)
- Plymouth boot splash and GRUB theme
- Serial console support for headless appliances

## Quick Start

### On an Existing Linux Server

```bash
git clone https://github.com/kahluna-systems/warp-gateway.git /opt/warp-gateway
cd /opt/warp-gateway
sudo bash setup.sh
source venv/bin/activate
python3 cli_entry.py
```

The first-boot wizard will guide you through interface assignment, network configuration, and admin credentials.

### As a VM

See the [Deployment Guide](DEPLOYMENT_GUIDE.md) for Proxmox, VMware, and ISO installer instructions.

## CLI Usage

After setup, the CLI is available via SSH or console:

```
kahluna-gw> enable
Password:
kahluna-gw# show interfaces
Interface  Role  IP Address      Netmask        Link  Speed      MAC
---------  ----  --------------  -------------  ----  ---------  -----------------
ens33      WAN   192.168.1.1     255.255.255.0  UP    1000 Mbps  00:0c:29:f8:e1:51
ens38      LAN   10.246.247.1    255.255.255.0  UP    1000 Mbps  00:0c:29:f8:e1:5b

kahluna-gw# show system health
Hostname  : kahluna-gw
Uptime    : 2d 4h 15m
CPU Usage : 3.2%
Memory    : 512 / 2048 MB (25.0%)
Disk      : 4.2 / 16.0 GB (26.3%)

kahluna-gw# configure terminal
kahluna-gw(config)# interface ens38
kahluna-gw(config-if)# ip address 10.246.247.1 255.255.255.0
kahluna-gw(config-if)# exit
kahluna-gw(config)# end
kahluna-gw# copy running-config startup-config
```

See the [CLI Command Reference](CLI_REFERENCE.md) for the full command list.

## Web UI

The web UI is available at `http://<gateway-ip>:5000` and provides the same functionality as the CLI through a browser interface. Login with the admin credentials set during the first-boot wizard.

## Project Structure

```
warp-gateway/
  gateway.py              Main Flask app and startup sequence
  cli_entry.py            CLI entry point (login shell)
  database.py             SQLAlchemy db instance
  nexus_client.py         KahLuna Platform Core integration
  cli/                    CLI shell package
    shell.py              WarpShell (cmd.Cmd)
    command_tree.py        Declarative command definitions
    parser.py              Tokenizer and abbreviation resolver
    modes.py               Mode stack (exec/privileged/configure)
    completer.py           Tab completion
    help_system.py         Context-aware "?" help
    formatter.py           Table/key-value output (plain ASCII)
    session.py             Session management and audit
    config_serializer.py   Running-config / startup-config
    first_boot.py          First-boot setup wizard
    handlers/              Command handler modules
  services/               Business logic (interface, network, firewall, etc.)
  system/                 OS command wrappers (wireguard, iptables, dnsmasq, etc.)
  models_new/             SQLAlchemy models
  routes/                 Flask web UI routes
  templates/              Jinja2 templates
  image/                  WARP OS image builder
    build.sh              Main build script
    installer/            Disk installer for ISO
    scripts/              Customize, harden, finalize
    config/               Systemd units, sshd, sysctl, iptables
    plymouth/             Boot splash theme
    grub/                 GRUB bootloader theme
    export/               Raw, OVA, ISO export scripts
  tests/                  Test suite
    cli/                  Unit, property, and integration tests
    functional_test.sh    On-device functional test script
```

## Documentation

- [Deployment Guide](DEPLOYMENT_GUIDE.md) -- ISO, raw image, OVA, and pre-provisioned deployment
- [CLI Command Reference](CLI_REFERENCE.md) -- Complete command list with examples
- [Administration Guide](ADMINISTRATION_GUIDE.md) -- Day-to-day operations and management

## Testing

```bash
# Unit, property, and integration tests (run anywhere with Python)
source venv/bin/activate
pytest tests/cli/ -v

# Functional tests (run on the deployed gateway)
bash tests/functional_test.sh
```

## License

Proprietary -- KahLuna Systems. All rights reserved.
