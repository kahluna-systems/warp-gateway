# WARP Gateway — Network Appliance Architecture

## Architecture Layers

```
┌──────────────────────────────────────────────────────┐
│              Management Plane                         │
│  Flask Web UI + REST API + Nexus Client               │
│  (Admin interface, Mission Control integration)       │
├──────────────────────────────────────────────────────┤
│              Service Layer                            │
│  Network Svc | Endpoint Svc | Firewall Svc |         │
│  DHCP Svc | DNS Svc | Shaping Svc |                  │
│  Health Svc | Diagnostics Svc | Interface Svc        │
│  (Business logic — orchestrates system changes)       │
├──────────────────────────────────────────────────────┤
│              System Layer                             │
│  commander | wireguard | firewall | traffic |         │
│  routing | dhcp | dns | interfaces | checker          │
│  (Safe wrappers around OS commands)                   │
├──────────────────────────────────────────────────────┤
│              Linux System                             │
│  WireGuard | iptables/nftables | tc/htb |            │
│  dnsmasq (DHCP+DNS) | ip/iproute2 | sysctl |        │
│  tcpdump | iperf3 | mtr | traceroute                 │
└──────────────────────────────────────────────────────┘
```

## Project Structure

```
warp-gateway/
├── app.py                          # Flask app entry + startup sequence
├── config.py                       # App configuration
├── database.py                     # SQLAlchemy setup
├── models/                         # Database models
│   ├── __init__.py
│   ├── user.py                     # Auth users
│   ├── interface.py                # Network interface assignments
│   ├── network.py                  # VPN networks
│   ├── endpoint.py                 # VPN peers
│   ├── firewall_rule.py            # Firewall rules
│   ├── dhcp.py                     # DHCP config + reservations
│   ├── dns.py                      # DNS overrides
│   └── audit.py                    # Local audit log
│
├── system/                         # System layer
│   ├── __init__.py
│   ├── commander.py                # Safe subprocess wrapper
│   ├── checker.py                  # Dependency validation
│   ├── interfaces.py               # NIC detection, link status, IP config
│   ├── wireguard.py                # WireGuard interface lifecycle
│   ├── firewall.py                 # iptables rule management
│   ├── traffic.py                  # tc traffic shaping
│   ├── routing.py                  # IP forwarding, NAT, static routes
│   ├── dhcp.py                     # dnsmasq DHCP management
│   ├── dns.py                      # dnsmasq DNS management
│   └── diagnostics.py              # ping, traceroute, tcpdump, iperf3, mtr
│
├── services/                       # Service layer
│   ├── __init__.py
│   ├── interface_service.py        # Interface role assignment + IP config
│   ├── network_service.py          # VPN network CRUD + system orchestration
│   ├── endpoint_service.py         # VPN peer CRUD + WireGuard peer mgmt
│   ├── firewall_service.py         # Firewall rule CRUD + iptables sync
│   ├── dhcp_service.py             # DHCP config + dnsmasq management
│   ├── dns_service.py              # DNS config + dnsmasq management
│   ├── shaping_service.py          # Rate limiting orchestration
│   ├── health_service.py           # System health aggregation
│   ├── diagnostics_service.py      # Network diagnostic tools
│   └── client_service.py           # Connected client visibility (ARP + DHCP + WG)
│
├── routes/                         # Flask routes
│   ├── __init__.py
│   ├── auth.py                     # Login/logout/user management
│   ├── dashboard.py                # Main dashboard
│   ├── interfaces.py               # Interface management
│   ├── networks.py                 # VPN networks
│   ├── endpoints.py                # VPN peers
│   ├── firewall.py                 # Firewall rules
│   ├── dhcp.py                     # DHCP settings
│   ├── dns.py                      # DNS settings
│   ├── clients.py                  # Connected clients view
│   ├── diagnostics.py              # Diagnostic tools
│   ├── system.py                   # System settings, backup, update
│   └── api.py                      # REST API for Mission Control
│
├── nexus_client.py                 # Platform Core integration
├── templates/                      # Jinja2 templates
├── static/                         # CSS, JS, images
├── setup.sh                        # System setup script
└── requirements.txt
```

## System Layer Modules

### commander.py
```python
class CommandResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str
    duration_ms: float

def run(cmd: list, sudo: bool = False, timeout: int = 30) -> CommandResult
def run_pipe(cmd1: list, cmd2: list, sudo: bool = False) -> CommandResult
```

### interfaces.py
```python
def detect_all() -> list[InterfaceInfo]        # name, mac, speed, link, driver
def get_status(name) -> InterfaceInfo
def set_ip(name, ip, netmask) -> CommandResult
def set_dhcp_client(name) -> CommandResult     # WAN mode
def bring_up(name) -> CommandResult
def bring_down(name) -> CommandResult
def get_arp_table() -> list[ArpEntry]          # ip, mac, interface
```

### dhcp.py
```python
def configure(interface, subnet, range_start, range_end, gateway, dns, lease_time)
def add_reservation(mac, ip, hostname)
def remove_reservation(mac)
def get_leases() -> list[DhcpLease]            # ip, mac, hostname, expiry
def restart() -> CommandResult
def stop() -> CommandResult
```

### dns.py
```python
def configure(upstream_servers, local_overrides)
def add_override(hostname, ip)
def remove_override(hostname)
def get_query_log(limit) -> list               # if logging enabled
def restart() -> CommandResult
```

### firewall.py
```python
def set_default_policy()                       # drop inbound WAN, allow outbound LAN
def add_rule(chain, rule) -> CommandResult
def remove_rule(chain, rule_num) -> CommandResult
def add_port_forward(wan_port, lan_ip, lan_port, protocol) -> CommandResult
def remove_port_forward(wan_port) -> CommandResult
def add_nat_masquerade(source_subnet, out_interface) -> CommandResult
def remove_nat_masquerade(source_subnet, out_interface) -> CommandResult
def block_peer_to_peer(interface) -> CommandResult
def list_rules(table, chain) -> list
def save_rules() -> CommandResult
def restore_rules() -> CommandResult
```

### wireguard.py
```python
def create_interface(name, private_key, address, port, peers) -> CommandResult
def destroy_interface(name) -> CommandResult
def add_peer(interface, public_key, allowed_ips, endpoint, psk) -> CommandResult
def remove_peer(interface, public_key) -> CommandResult
def get_status(interface) -> WgStatus          # parsed wg show
def get_all_interfaces() -> list[str]
def generate_keypair() -> (private_key, public_key)
def generate_preshared_key() -> str
```

### traffic.py
```python
def apply_limit(interface, peer_ip, down_kbps, up_kbps, burst_kbps) -> CommandResult
def remove_limit(interface, peer_ip) -> CommandResult
def clear_all(interface) -> CommandResult
def get_stats(interface) -> dict
```

### routing.py
```python
def enable_ip_forwarding() -> CommandResult
def get_forwarding_status() -> bool
def detect_default_interface() -> str
def add_static_route(dest, gateway, interface) -> CommandResult
def remove_static_route(dest) -> CommandResult
def get_routing_table() -> list
```

### diagnostics.py
```python
def ping(target, count=4) -> PingResult
def traceroute(target, max_hops=30) -> TracerouteResult
def dns_lookup(query, record_type='A', server=None) -> DnsResult
def packet_capture(interface, filter, count=100, duration=None) -> CaptureResult
def mtr(target, count=10) -> MtrResult
def iperf_client(server, duration=10) -> IperfResult
def iperf_server(port=5201, one_off=True) -> IperfResult
```

## Startup Sequence

```
1. Run dependency checker
   → Log results, set system_ready flag
   → Missing critical deps = warning banner in UI

2. Detect and configure interfaces
   → If first boot: prompt for WAN/LAN assignment
   → If configured: apply saved interface config

3. Start DHCP server on LAN interfaces
   → Apply saved DHCP config from database

4. Start DNS forwarder
   → Apply saved DNS config from database

5. Apply firewall rules
   → Default policy + saved custom rules
   → NAT masquerade for LAN → WAN

6. Enable IP forwarding

7. Bring up WireGuard interfaces
   → For each active VPN network, wg-quick up
   → Apply rate limits for configured endpoints

8. Start Nexus heartbeat (if registered)

9. Start Flask web server
```

## Dashboard Redesign

The dashboard should show the appliance as a network device, not just a VPN manager:

```
┌─────────────────────────────────────────────────┐
│  WARP Gateway — [hostname] — [WAN IP]           │
├─────────────┬───────────────┬───────────────────┤
│ WAN         │ LAN           │ VPN               │
│ ens3        │ ens4          │ wg0               │
│ 34.75.x.x  │ 192.168.1.1   │ 10.100.0.1        │
│ ▲ 45 Mbps  │ 12 clients    │ 3 peers online    │
│ ▼ 12 Mbps  │ DHCP active   │ 2 peers offline   │
├─────────────┴───────────────┴───────────────────┤
│ Connected Clients (15)                           │
│ ┌──────────┬──────────┬────────┬───────────────┐│
│ │ Name     │ IP       │ Type   │ Status        ││
│ │ iPhone   │ .1.100   │ DHCP   │ Active        ││
│ │ Laptop   │ .1.101   │ Static │ Active        ││
│ │ Remote-1 │ 10.100.2 │ VPN    │ Connected     ││
│ └──────────┴──────────┴────────┴───────────────┘│
├─────────────────────────────────────────────────┤
│ Recent Events                                    │
│ • Client iPhone connected via DHCP               │
│ • VPN peer Remote-1 handshake completed          │
│ • Firewall blocked inbound on WAN:443            │
└─────────────────────────────────────────────────┘
```

## System Dependencies

Required packages (installed by setup.sh):
- wireguard, wireguard-tools
- dnsmasq
- iptables (or nftables)
- iproute2 (ip, tc, ss)
- tcpdump
- iperf3
- mtr-tiny
- traceroute
- dnsutils (dig)
- nmap (optional, for network scanning)
