# KahLuna WARP Gateway -- CLI Command Reference

## Navigation

The CLI uses a hierarchical mode system similar to Cisco IOS.

| Mode | Prompt | Access |
|------|--------|--------|
| Exec | `hostname>` | Login (read-only commands) |
| Privileged | `hostname#` | `enable` from exec mode |
| Configure | `hostname(config)#` | `configure terminal` from privileged |
| Interface | `hostname(config-if)#` | `interface <name>` from configure |
| Firewall | `hostname(config-fw)#` | `firewall` from configure |
| VPN | `hostname(config-vpn)#` | `vpn network <name>` from configure |
| DHCP | `hostname(config-dhcp)#` | `dhcp` from configure |
| DNS | `hostname(config-dns)#` | `dns` from configure |

Commands can be abbreviated as long as the abbreviation is unambiguous. For example, `sh int` resolves to `show interfaces`.

Type `?` at any point to see available commands or arguments. Help appears instantly without pressing Enter.

## Output Modifiers (Pipe Filters)

Any show command can be piped through output modifiers using `|`:

```
kahluna-gw# show running-config | include interface
kahluna-gw# show interfaces | display json
kahluna-gw# show firewall rules | exclude DROP
kahluna-gw# show clients | count
kahluna-gw# show log | last 5
kahluna-gw# show tech-support | no-more
```

| Filter | Description |
|--------|-------------|
| `\| include <pattern>` | Show only lines matching a pattern (regex) |
| `\| exclude <pattern>` | Hide lines matching a pattern |
| `\| begin <pattern>` | Start output from the first matching line |
| `\| count` | Count the number of output lines |
| `\| last <n>` | Show the last N lines |
| `\| display json` | Format output as JSON |
| `\| display xml` | Format output as XML |
| `\| no-more` | Disable pagination for this command |

Filters can be chained: `show interfaces | include WAN | display json`

---

## Exec Mode

Available after login. Read-only commands.

### show interfaces [name]

Display all network interfaces or detailed info for a specific interface.

```
kahluna-gw> show interfaces
Interface  Role  IP Address      Netmask        Link  Speed      MAC
---------  ----  --------------  -------------  ----  ---------  -----------------
ens33      WAN   192.168.1.1     255.255.255.0  UP    1000 Mbps  00:0c:29:f8:e1:51
ens38      LAN   10.246.247.1    255.255.255.0  UP    1000 Mbps  00:0c:29:f8:e1:5b

kahluna-gw> show interfaces ens33
Interface      : ens33
Role           : WAN
Link           : UP
MAC            : 00:0c:29:f8:e1:51
IP Address     : 192.168.1.1
...
```

### show ip route

Display the routing table.

```
kahluna-gw> show ip route
Routing Table:
  default via 192.168.1.254 dev ens33
  10.246.247.0/24 dev ens38 proto kernel scope link src 10.246.247.1
  192.168.1.0/24 dev ens33 proto kernel scope link src 192.168.1.1
```

### show firewall rules

Display custom firewall rules, port forwards, and live iptables state.

### show vpn networks

Display all VPN networks with status, subnet, port, and peer count.

### show vpn peers

Display all VPN peers with connection status, last handshake, and transfer stats.

### show vpn peer-config [name]

Display the WireGuard client configuration for a specific peer.

### show dhcp leases

Display active DHCP leases with IP, MAC, hostname, and expiry.

### show dhcp config

Display DHCP server configuration and static reservations.

### show dns overrides

Display DNS overrides and upstream server configuration.

### show clients

Display all connected clients (LAN via ARP/DHCP, VPN via WireGuard).

### show system health

Display CPU, memory, disk, uptime, and dependency status.

```
kahluna-gw> show system health
Hostname  : kahluna-gw
Platform  : Linux-6.8.0-88-generic-x86_64-with-glibc2.39
Uptime    : 2d 4h 15m
CPU Usage : 3.2%
CPU Cores : 4
Memory    : 512 / 2048 MB (25.0%)
Disk      : 4.2 / 16.0 GB (26.3%)

Dependencies:
  Status: All OK
```

### show running-config

Display the complete active configuration in CLI-command format.

### show startup-config

Display the saved startup configuration.

### show version

Display software version, hostname, platform, and uptime.

### show nexus status

Display KahLuna Nexus registration status and heartbeat state.

### show log [count]

Display recent audit and system log entries. Default: 20 entries.

```
kahluna-gw# show log
Time                 Action            Details                                              User
-------------------  ----------------  ---------------------------------------------------  --------
2026-04-19 20:30:00  cli_session_start CLI session started via ssh from 192.168.10.251      admin
2026-04-19 20:28:23  interface_assign  ens38 assigned as LAN                                System
2026-04-19 20:28:23  interface_assign  ens33 assigned as WAN                                System

kahluna-gw# show log 5
```

### show uptime

Display system uptime (quick shortcut).

```
kahluna-gw> show uptime
Uptime: 2d 4h 15m
```

### show arp

Display the full ARP table across all interfaces (including WAN).

```
kahluna-gw> show arp
IP Address       MAC Address        Interface  State
---------------  -----------------  ---------  ---------
192.168.10.254   c0:06:c3:f0:7b:bd  ens33      REACHABLE
192.168.10.251   6c:02:e0:60:dc:66  ens33      STALE
```

### show history

Display commands entered in the current CLI session.

```
kahluna-gw# show history
     1  show interfaces
     2  show ip route
     3  show system health
     4  configure terminal
```

### show tech-support

Dump the full system state into a single output for support tickets. Includes version, interfaces, routes, firewall, VPN, DHCP, DNS, clients, health, nexus status, running-config, and recent logs.

```
kahluna-gw# show tech-support | no-more
```

### ping [target]

Send ICMP echo requests to a hostname or IP.

```
kahluna-gw> ping 8.8.8.8
Pinging 8.8.8.8 with 4 packets...
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms
...
```

### traceroute [target]

Trace the route to a host.

### mtr [target]

Combined traceroute and ping (My Traceroute).

### nslookup [hostname]

Perform a DNS lookup.

### dig [hostname] [record-type]

Perform a detailed DNS lookup.

### enable

Enter privileged mode. Prompts for the enable password.

### ssh [host] [user]

SSH to another host from the gateway. Useful for hopping to other devices.

```
kahluna-gw> ssh 10.246.247.100
kahluna-gw> ssh 10.246.247.100 admin
```

### exit

Disconnect from the CLI.

---

## Privileged Mode

Entered via `enable`. Includes all exec commands plus operational commands.

### configure terminal

Enter configuration mode.

### setup

Re-run the first-boot setup wizard. Prompts for confirmation.

### write memory

Alias for `copy running-config startup-config`. Network engineers type this reflexively.

```
kahluna-gw# write memory
Running configuration saved to startup-config
```

### terminal length [lines]

Set the pagination page size. Use `0` to disable pagination entirely.

```
kahluna-gw# terminal length 0
Pagination disabled

kahluna-gw# terminal length 40
Terminal length set to 40 lines
```

### copy running-config startup-config

Save the active configuration to persistent storage.

### reload

Restart the gateway. Prompts for confirmation.

### clear counters

Reset interface traffic counters.

### clear arp

Flush the ARP table.

### capture [interface] [filter] [count]

Start a packet capture on an interface.

```
kahluna-gw# capture ens33 tcp port 80 20
Capturing 20 packets on ens33...
Filter: tcp port 80
...
```

### iperf [server]

Run an iperf3 bandwidth test to a server.

### disable

Return to exec mode.

---

## Configure Mode

Entered via `configure terminal`. Write access to all gateway settings.

### hostname [name]

Set the gateway hostname. Updates both the database and the OS hostname.

```
kahluna-gw(config)# hostname my-gateway
Hostname set to "my-gateway"
my-gateway(config)#
```

### interface [name]

Enter interface sub-configuration mode.

```
kahluna-gw(config)# interface ens38
kahluna-gw(config-if)#
```

### firewall

Enter firewall sub-configuration mode.

### vpn network [name]

Enter VPN network sub-configuration mode.

### dhcp

Enter DHCP sub-configuration mode.

### dns

Enter DNS sub-configuration mode.

### nexus register [token] [platform-url]

Register the gateway with KahLuna Platform Core.

```
kahluna-gw(config)# nexus register ABC123TOKEN https://api.kahluna.com
Registering with KahLuna Nexus at https://api.kahluna.com...
Registration successful
  Service ID: 51cc6caa-6098-473f-8cdb-3e72cc26eea2
  Tenant ID:  746f0f5c-18db-42e1-a424-55af558ca550
  Heartbeat:  started
```

### nexus deregister

Deregister from Platform Core. Prompts for confirmation.

### webui enable

Enable the web UI.

### webui disable

Disable the web UI.

### webui listen [interface|all|localhost]

Set which interface the web UI listens on.

```
kahluna-gw(config)# webui listen all
Web UI will listen on all interfaces (0.0.0.0:5000)
```

### exit

Return to privileged mode.

### end

Return to privileged mode (from any config or sub-config mode).

---

## Interface Sub-Mode

Entered via `interface [name]` from configure mode.

### role [WAN|LAN|OPT|DISABLED]

Assign a role to the interface.

```
kahluna-gw(config-if)# role LAN
Interface ens38 assigned as LAN
```

### ip address [address] [netmask]

Set a static IP address.

```
kahluna-gw(config-if)# ip address 10.246.247.1 255.255.255.0
Interface ens38 configured with 10.246.247.1 255.255.255.0
```

### ip address dhcp

Configure the interface to obtain its address via DHCP.

### gateway [address]

Set the default gateway for this interface.

### shutdown

Disable the interface.

### no shutdown

Enable the interface.

---

## Firewall Sub-Mode

Entered via `firewall` from configure mode.

### rule [chain] [action] [protocol] [source] [destination] [port]

Add a firewall rule.

```
kahluna-gw(config-fw)# rule INPUT ACCEPT tcp any any 443
Firewall rule added: INPUT ACCEPT tcp any any port 443
```

### no rule [rule-id]

Remove a firewall rule by ID.

### port-forward [wan-port] [lan-ip] [lan-port] [protocol]

Add a port forwarding rule.

```
kahluna-gw(config-fw)# port-forward 8080 10.246.247.100 80 tcp
Port forward added: WAN:8080 -> 10.246.247.100:80/tcp
```

### no port-forward [id]

Remove a port forwarding rule by ID.

---

## VPN Sub-Mode

Entered via `vpn network [name]` from configure mode.

### type [secure_internet|remote_resource_gw|l3vpn_gateway]

Set the VPN network type.

### subnet [cidr]

Set the VPN subnet.

### port [number]

Set the WireGuard listen port.

### peer [name]

Add a VPN peer. Displays the generated client configuration.

```
kahluna-gw(config-vpn)# peer laptop-1
Peer "laptop-1" added to "corporate" (10.100.0.2)

Client configuration:
[Interface]
PrivateKey = ...
Address = 10.100.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0
Endpoint = 192.168.1.1:51820
PersistentKeepalive = 25
```

### no peer [name]

Remove a VPN peer.

### rate-limit [download-mbps] [upload-mbps]

Set bandwidth limits for the network.

---

## DHCP Sub-Mode

Entered via `dhcp` from configure mode.

### pool [interface] range [start-ip] [end-ip]

Configure the DHCP address pool.

```
kahluna-gw(config-dhcp)# pool ens38 range 10.246.247.10 10.246.247.199
DHCP pool configured on ens38: 10.246.247.10 - 10.246.247.199
```

### reservation [mac] [ip] [hostname]

Add a static DHCP reservation.

```
kahluna-gw(config-dhcp)# reservation aa:bb:cc:dd:ee:ff 10.246.247.50 printer
DHCP reservation added: aa:bb:cc:dd:ee:ff -> 10.246.247.50
```

### no reservation [mac]

Remove a DHCP reservation by MAC address.

---

## DNS Sub-Mode

Entered via `dns` from configure mode.

### override [hostname] [ip]

Add a local DNS override.

```
kahluna-gw(config-dns)# override intranet.company.com 10.246.247.10
DNS override added: intranet.company.com -> 10.246.247.10
```

### no override [hostname]

Remove a DNS override.

### upstream [ip1] [ip2]

Set upstream DNS servers. Also updates the gateway's own `/etc/resolv.conf`.

```
kahluna-gw(config-dns)# upstream 1.1.1.1 8.8.8.8
Upstream DNS servers set to: 1.1.1.1, 8.8.8.8
```
