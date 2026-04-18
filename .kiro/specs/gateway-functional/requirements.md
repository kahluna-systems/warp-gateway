# WARP Gateway — Network Appliance Requirements

## Vision

The WARP Gateway is a managed network appliance that functions as a router, firewall, VPN gateway, DHCP server, and diagnostic tool. When deployed on hardware with multiple NICs, it replaces the customer's existing router/firewall. It registers with KahLuna Platform Core for centralized management.

## Personas

- **MSP Engineer**: Deploys and configures the gateway for a customer site via Mission Control or local UI
- **End User**: Connects to the LAN behind the gateway, gets an IP, browses the internet, connects via VPN when remote
- **Platform Admin**: Monitors all gateways across tenants via Mission Control

## Core Functional Requirements

### FR-1: Interface Management
- Detect all physical network interfaces on the system
- Assign roles to interfaces: WAN, LAN, OPT (optional/DMZ)
- Configure WAN interface: static IP, DHCP client, or PPPoE
- Configure LAN interface: static IP (gateway address for the LAN subnet)
- Support multiple LAN interfaces
- Show interface status: link up/down, speed, duplex, MAC, IP
- Initial setup wizard to assign WAN/LAN on first boot

### FR-2: DHCP Server
- Run DHCP server on LAN interfaces (dnsmasq)
- Configurable: subnet, range, lease time, gateway, DNS servers
- Static DHCP reservations (MAC → IP mapping)
- View active DHCP leases (who's connected)
- Option to disable DHCP (for networks with existing DHCP)

### FR-3: DNS Forwarding
- Forward DNS queries from LAN clients to upstream DNS (dnsmasq)
- Configurable upstream DNS servers (default: 1.1.1.1, 8.8.8.8)
- Local DNS overrides (hostname → IP mapping)
- DNS query logging (optional)
- Future: DNS-based content filtering

### FR-4: Routing and NAT
- Enable IP forwarding between interfaces
- NAT masquerade: LAN → WAN (internet access for LAN clients)
- Static routes
- Default gateway configuration
- Future: policy-based routing, dynamic routing (BGP/OSPF via FRRouting)

### FR-5: Firewall
- Default policy: block inbound on WAN, allow outbound from LAN
- Allow established/related connections
- Custom firewall rules: source, destination, port, protocol, action (allow/deny/reject)
- Rule ordering with priorities
- Per-interface rules (WAN inbound, LAN inbound, inter-VLAN)
- Port forwarding / destination NAT (expose internal services)
- Logging for blocked/allowed traffic
- Future: IDS/IPS integration (Suricata)

### FR-6: WireGuard VPN
- Remote access VPN: clients connect from internet to LAN resources
- Site-to-site VPN: connect two gateways
- Peer management: add/remove/suspend peers
- QR code and config file generation for mobile/desktop clients
- Split tunnel or full tunnel configuration
- Multiple WireGuard interfaces (separate networks)
- Real-time peer status: handshake time, transfer stats

### FR-7: Traffic Shaping
- Per-client bandwidth limits (upload/download)
- Per-network bandwidth limits
- Burst factor support
- QoS profiles (residential basic, business, custom)
- Enforcement via tc htb with per-IP filters
- Real-time bandwidth monitoring per client

### FR-8: Client Visibility
- ARP table: see all devices on the LAN
- DHCP lease table: hostname, MAC, IP, lease expiry
- Active connections: which clients are passing traffic
- WireGuard peer status: connected/disconnected, last handshake
- Combined view: all connected clients (LAN + VPN) in one place

### FR-9: Network Diagnostics
- Ping from the gateway
- Traceroute from the gateway
- DNS lookup from the gateway
- Packet capture (tcpdump) on any interface
- Speed test (iperf3 client/server)
- MTR (live path analysis)
- All results viewable in the UI and reportable to Mission Control

### FR-10: System Management
- Startup dependency validation
- System health dashboard: CPU, memory, disk, uptime, interface stats
- Configuration backup and restore
- Firmware/software update mechanism
- Reboot/shutdown from UI
- Syslog / log viewer
- NTP time sync

### FR-11: Platform Integration (Nexus)
- Register with Platform Core via provisioning token
- Heartbeat reporting (online/offline/degraded)
- Config sync from Platform Core (future: push config from Mission Control)
- Audit logging to Platform Core
- API for Mission Control to query gateway status and manage remotely

## Non-Functional Requirements

### NFR-1: Security
- All system commands via safe subprocess wrapper
- Sudo with specific command allowlists
- Web UI requires authentication
- CSRF protection on all forms
- Future: SSO via Platform Core JWT

### NFR-2: Reliability
- Failed system commands don't crash the gateway
- Graceful degradation: if tc fails, VPN still works
- Startup sync: restore all active configs on reboot
- Persistent iptables rules across reboots
- Persistent DHCP/DNS config across reboots

### NFR-3: Performance
- Handle 100+ concurrent LAN clients
- Handle 50+ concurrent VPN peers
- Traffic shaping with minimal overhead
- Responsive web UI even under load

### NFR-4: Hardware Compatibility
- Run on standard Ubuntu 22.04/24.04
- Support multi-NIC systems (2-6 ports)
- Detect and configure Intel i226 NICs
- Support USB LTE modems for WAN failover (future)
- Support WiFi interfaces as LAN AP (future)
