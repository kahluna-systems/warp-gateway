# WARP Gateway — Network Appliance Implementation Tasks

## Phase 1: System Layer Foundation

### Task 1: Commander and dependency checker
- [ ] Create `system/` package with `__init__.py`
- [ ] Implement `system/commander.py` — CommandResult class, run(), run_pipe() with sudo, timeout, logging
- [ ] Implement `system/checker.py` — check for wireguard, dnsmasq, iptables, tc, ip, tcpdump, iperf3, mtr, traceroute
- [ ] Return structured health report with installed/missing/version for each tool
- [ ] Add `/api/system/deps` endpoint
- [ ] Add startup check in app.py

### Task 2: Interface detection and management
- [ ] Implement `system/interfaces.py`:
  - detect_all() — list all NICs with name, MAC, speed, link state, driver
  - get_status(name) — detailed status for one interface
  - set_ip(name, ip, netmask) — configure static IP
  - set_dhcp_client(name) — configure interface as DHCP client (WAN)
  - bring_up(name) / bring_down(name)
  - get_arp_table() — parse `ip neigh` output
- [ ] Create `models/interface.py` — InterfaceConfig model (name, role, ip, netmask, gateway, mode)
- [ ] Implement `services/interface_service.py`:
  - assign_role(interface_name, role) — WAN/LAN/OPT
  - configure_wan(interface_name, mode, ip, netmask, gateway)
  - configure_lan(interface_name, ip, netmask)
  - get_all_configured() — return all interfaces with roles and status
- [ ] Create `routes/interfaces.py` — UI for interface management

### Task 3: DHCP server
- [ ] Implement `system/dhcp.py`:
  - configure() — write dnsmasq DHCP config
  - add_reservation(mac, ip, hostname)
  - remove_reservation(mac)
  - get_leases() — parse dnsmasq lease file
  - restart() / stop()
- [ ] Create `models/dhcp.py` — DhcpConfig, DhcpReservation models
- [ ] Implement `services/dhcp_service.py`:
  - setup_dhcp(interface, subnet, range, gateway, dns, lease_time)
  - add_static_lease(mac, ip, hostname)
  - get_connected_clients() — leases + ARP table merged
- [ ] Create `routes/dhcp.py` — DHCP settings UI + lease viewer

### Task 4: DNS forwarding
- [ ] Implement `system/dns.py`:
  - configure(upstream_servers, local_overrides)
  - add_override(hostname, ip)
  - remove_override(hostname)
  - restart()
- [ ] Create `models/dns.py` — DnsConfig, DnsOverride models
- [ ] Implement `services/dns_service.py`
- [ ] Create `routes/dns.py` — DNS settings UI

## Phase 2: Firewall and Routing

### Task 5: Firewall rules engine
- [ ] Implement `system/firewall.py`:
  - set_default_policy() — drop WAN inbound, allow LAN outbound, allow established
  - add_rule(chain, source, dest, port, protocol, action, priority)
  - remove_rule(chain, rule_id)
  - add_port_forward(wan_port, lan_ip, lan_port, protocol)
  - remove_port_forward(wan_port)
  - add_nat_masquerade(subnet, out_interface)
  - remove_nat_masquerade(subnet, out_interface)
  - block_peer_to_peer(interface) — network isolation
  - list_rules(table, chain)
  - save_rules() / restore_rules()
- [ ] Create `models/firewall_rule.py` — FirewallRule, PortForward models
- [ ] Implement `services/firewall_service.py`:
  - apply_default_policy()
  - add_custom_rule() — DB + iptables
  - remove_custom_rule() — DB + iptables
  - add_port_forward() — DB + iptables
  - sync_all_rules() — apply all DB rules to iptables (startup)
- [ ] Create `routes/firewall.py` — firewall rules UI + port forwarding

### Task 6: Routing and NAT
- [ ] Implement `system/routing.py`:
  - enable_ip_forwarding() + persist
  - detect_default_interface()
  - get_forwarding_status()
  - add_static_route() / remove_static_route()
  - get_routing_table()
- [ ] Integrate NAT masquerade into interface_service:
  - When LAN is configured, auto-add NAT from LAN subnet → WAN interface
- [ ] Apply IP forwarding on startup

## Phase 3: VPN (WireGuard)

### Task 7: WireGuard interface manager
- [ ] Implement `system/wireguard.py`:
  - create_interface(name, private_key, address, port, peers)
  - destroy_interface(name)
  - add_peer(interface, public_key, allowed_ips, endpoint, psk)
  - remove_peer(interface, public_key)
  - get_status(interface) — parse wg show
  - get_all_interfaces()
  - generate_keypair() / generate_preshared_key()
- [ ] Implement `services/network_service.py`:
  - create_network() — DB + write config + wg-quick up + NAT if secure_internet
  - delete_network() — wg-quick down + remove config + remove NAT + DB
  - suspend_network() / resume_network()
  - get_network_status() — real data from wg show
- [ ] Implement `services/endpoint_service.py`:
  - add_endpoint() — DB + wg set add peer + rate limit
  - remove_endpoint() — wg set remove peer + remove rate limit + DB
  - get_endpoint_status() — real handshake/transfer data
- [ ] Refactor existing network/endpoint routes to use services

### Task 8: Traffic shaping
- [ ] Implement `system/traffic.py`:
  - apply_limit(interface, peer_ip, down_kbps, up_kbps, burst)
  - remove_limit(interface, peer_ip)
  - clear_all(interface)
  - get_stats(interface)
- [ ] Implement `services/shaping_service.py`
- [ ] Hook into endpoint create/update/delete
- [ ] Apply saved rate limits on startup

## Phase 4: Visibility and Diagnostics

### Task 9: Client visibility
- [ ] Implement `services/client_service.py`:
  - get_all_clients() — merge ARP table + DHCP leases + WireGuard peers
  - Return unified list: name, IP, MAC, type (LAN/VPN), status, bandwidth
- [ ] Create `routes/clients.py` — connected clients page
- [ ] Add client count to dashboard

### Task 10: Diagnostics
- [ ] Implement `system/diagnostics.py`:
  - ping, traceroute, dns_lookup, packet_capture, mtr, iperf
- [ ] Implement `services/diagnostics_service.py`
- [ ] Create `routes/diagnostics.py` — diagnostic tools UI
- [ ] Port relevant code from the Network Diagnostic Platform

### Task 11: Health and dashboard
- [ ] Implement `services/health_service.py`:
  - get_system_health() — CPU, memory, disk, uptime
  - get_interface_stats() — per-interface traffic counters
  - get_vpn_stats() — per-peer handshake and transfer
  - get_firewall_stats() — blocked/allowed counts
  - get_dhcp_stats() — lease count, pool utilization
- [ ] Redesign dashboard template:
  - Interface status cards (WAN/LAN/VPN)
  - Connected clients table (LAN + VPN combined)
  - Recent events (audit log)
  - System health indicators

## Phase 5: Startup and Deployment

### Task 12: Startup sequence
- [ ] Implement startup_sync():
  1. Dependency check
  2. Apply interface configs
  3. Start DHCP on LAN interfaces
  4. Start DNS forwarder
  5. Apply firewall rules + default policy
  6. Enable IP forwarding + NAT
  7. Bring up WireGuard interfaces
  8. Apply rate limits
  9. Start Nexus heartbeat
- [ ] Call on app startup
- [ ] Log all actions

### Task 13: Deploy script and setup
- [ ] Update deploy script to install all system deps:
  wireguard, wireguard-tools, dnsmasq, iptables, iproute2,
  tcpdump, iperf3, mtr-tiny, traceroute, dnsutils
- [ ] Disable system dnsmasq service (gateway manages it)
- [ ] Enable IP forwarding persistently
- [ ] Create initial admin user with generated password
- [ ] Display credentials on completion
- [ ] Create setup.sh for manual installation
