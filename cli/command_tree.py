"""
Declarative command tree data structure.
Defines all CLI commands, their parameters, help text, and handler references.
Handlers are initially None and wired in by build_command_tree() or later tasks.
"""
from dataclasses import dataclass, field
from typing import Optional, Callable

from cli.modes import (
    EXEC, PRIVILEGED, CONFIGURE,
    CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
    CONFIG_VLAN, CONFIG_ZONE,
)


@dataclass
class ParamDef:
    """Parameter definition for a command."""
    name: str
    help_text: str
    required: bool = True
    choices: Optional[list] = None
    validator: Optional[Callable] = None


@dataclass
class CommandNode:
    """A node in the command tree."""
    name: str
    help_text: str
    handler: Optional[Callable] = None
    children: dict = field(default_factory=dict)
    params: list = field(default_factory=list)
    modes: list = field(default_factory=lambda: [EXEC])
    min_role: str = 'viewer'

    def add_child(self, node: 'CommandNode') -> 'CommandNode':
        """Add a child command node and return it for chaining."""
        self.children[node.name] = node
        return node


def build_exec_tree() -> dict:
    """Build the command tree for exec mode."""
    from cli.handlers import show as show_h
    from cli.handlers import diagnostics as diag_h
    from cli.handlers import commit as commit_h

    tree = {}

    # ── show ─────────────────────────────────────────────────────────────
    show = CommandNode('show', 'Display system information')
    tree['show'] = show

    show.add_child(CommandNode(
        'interfaces', 'Display interface status and configuration',
        handler=show_h.show_interfaces,
        params=[ParamDef('name', 'Interface name (optional)', required=False)],
    ))
    show.children['interfaces'].add_child(CommandNode(
        'trunk', 'Display trunk port status', handler=show_h.show_interfaces_trunk,
    ))
    show.add_child(CommandNode('ip', 'Display IP information'))
    show.children['ip'].add_child(CommandNode('route', 'Display the routing table', handler=show_h.show_ip_route))

    show.add_child(CommandNode('firewall', 'Display firewall information'))
    show.children['firewall'].add_child(CommandNode('rules', 'Display active firewall rules', handler=show_h.show_firewall_rules))

    show.add_child(CommandNode('vpn', 'Display VPN information'))
    show.children['vpn'].add_child(CommandNode('networks', 'Display VPN networks', handler=show_h.show_vpn_networks))
    show.children['vpn'].add_child(CommandNode('peers', 'Display VPN peers', handler=show_h.show_vpn_peers))
    show.children['vpn'].add_child(CommandNode(
        'peer-config', 'Display WireGuard config for a peer',
        handler=show_h.show_vpn_peer_config,
        params=[ParamDef('name', 'Peer name')],
    ))

    show.add_child(CommandNode('dhcp', 'Display DHCP information'))
    show.children['dhcp'].add_child(CommandNode('leases', 'Display active DHCP leases', handler=show_h.show_dhcp_leases))
    show.children['dhcp'].add_child(CommandNode('config', 'Display DHCP server configuration', handler=show_h.show_dhcp_config))

    show.add_child(CommandNode('dns', 'Display DNS information'))
    show.children['dns'].add_child(CommandNode('overrides', 'Display DNS overrides', handler=show_h.show_dns_overrides))

    show.add_child(CommandNode('clients', 'Display connected LAN and VPN clients', handler=show_h.show_clients))

    show.add_child(CommandNode('arp', 'Display the full ARP table (all interfaces)', handler=show_h.show_arp))

    show.add_child(CommandNode('system', 'Display system information'))
    show.children['system'].add_child(CommandNode('health', 'Display system health', handler=show_h.show_system_health))
    show.children['system'].add_child(CommandNode('rollback', 'Display available rollback versions', handler=commit_h.show_system_rollback))

    show.add_child(CommandNode('running-config', 'Display the active configuration', handler=show_h.show_running_config))
    show.add_child(CommandNode('startup-config', 'Display the saved startup configuration', handler=show_h.show_startup_config))
    show.add_child(CommandNode('version', 'Display software version and system info', handler=show_h.show_version))
    show.add_child(CommandNode('nexus', 'Display KahLuna Nexus information'))
    show.children['nexus'].add_child(CommandNode('status', 'Display Nexus registration status', handler=show_h.show_nexus_status))

    show.add_child(CommandNode('log', 'Display recent log entries', handler=show_h.show_log,
        params=[ParamDef('count', 'Number of entries (default: 20)', required=False)],
    ))
    show.add_child(CommandNode('uptime', 'Display system uptime', handler=show_h.show_uptime))
    show.add_child(CommandNode('history', 'Display command history', handler=show_h.show_history))
    show.add_child(CommandNode('tech-support', 'Dump full system state for support', handler=show_h.show_tech_support))

    show.add_child(CommandNode('vlan', 'Display VLAN table', handler=show_h.show_vlan))
    show.add_child(CommandNode('zone', 'Display security zone assignments', handler=show_h.show_zone))
    show.add_child(CommandNode('zone-policy', 'Display zone firewall policies', handler=show_h.show_zone_policy))

    # ── diagnostics ──────────────────────────────────────────────────────
    tree['ping'] = CommandNode(
        'ping', 'Send ICMP echo requests',
        handler=diag_h.do_ping,
        params=[ParamDef('target', 'Hostname or IP address')],
    )
    tree['traceroute'] = CommandNode(
        'traceroute', 'Trace the route to a host',
        handler=diag_h.do_traceroute,
        params=[ParamDef('target', 'Hostname or IP address')],
    )
    tree['mtr'] = CommandNode(
        'mtr', 'Combined traceroute and ping',
        handler=diag_h.do_mtr,
        params=[ParamDef('target', 'Hostname or IP address')],
    )
    tree['nslookup'] = CommandNode(
        'nslookup', 'DNS lookup',
        handler=diag_h.do_nslookup,
        params=[ParamDef('hostname', 'Hostname to resolve')],
    )
    tree['dig'] = CommandNode(
        'dig', 'DNS lookup (detailed)',
        handler=diag_h.do_dig,
        params=[ParamDef('hostname', 'Hostname to resolve')],
    )

    # ── session ──────────────────────────────────────────────────────────
    tree['enable'] = CommandNode('enable', 'Enter privileged mode')
    tree['exit'] = CommandNode('exit', 'Exit the current mode or disconnect')
    tree['help'] = CommandNode('help', 'Display available commands')
    tree['ssh'] = CommandNode(
        'ssh', 'SSH to another host',
        handler=diag_h.do_ssh,
        params=[ParamDef('host', 'Hostname or IP address')],
    )

    return tree


def build_privileged_tree() -> dict:
    """Build additional commands for privileged mode."""
    from cli.handlers import system as sys_h
    from cli.handlers import diagnostics as diag_h
    from cli.handlers import commit as commit_h

    tree = {}

    tree['configure'] = CommandNode(
        'configure', 'Enter configuration mode',
        params=[ParamDef('mode', '"terminal", "private", or "exclusive"',
                         required=False, choices=['terminal', 'private', 'exclusive'])],
    )
    tree['disable'] = CommandNode('disable', 'Return to exec mode')
    tree['reload'] = CommandNode('reload', 'Restart the gateway', handler=sys_h.do_reload)
    tree['copy'] = CommandNode('copy', 'Copy configuration')
    tree['copy'].add_child(CommandNode('running-config', 'Source: running configuration'))
    tree['copy'].children['running-config'].add_child(
        CommandNode('startup-config', 'Destination: startup configuration', handler=sys_h.copy_running_startup)
    )
    tree['clear'] = CommandNode('clear', 'Clear system data')
    tree['clear'].add_child(CommandNode('counters', 'Reset interface traffic counters', handler=sys_h.clear_counters))
    tree['clear'].add_child(CommandNode('arp', 'Flush the ARP table', handler=sys_h.clear_arp))

    tree['capture'] = CommandNode(
        'capture', 'Start a packet capture',
        handler=diag_h.do_capture,
        params=[
            ParamDef('interface', 'Interface to capture on'),
            ParamDef('filter', 'BPF filter expression', required=False),
            ParamDef('count', 'Number of packets', required=False),
        ],
        min_role='operator',
    )
    tree['iperf'] = CommandNode(
        'iperf', 'Run an iperf3 bandwidth test',
        handler=diag_h.do_iperf,
        params=[ParamDef('server', 'iperf3 server address')],
        min_role='operator',
    )
    tree['setup'] = CommandNode(
        'setup', 'Run the first-boot setup wizard',
        handler=sys_h.do_setup,
        min_role='admin',
    )
    tree['write'] = CommandNode('write', 'Write configuration')
    tree['write'].add_child(CommandNode('memory', 'Save running-config to startup-config', handler=sys_h.write_memory))

    tree['terminal'] = CommandNode('terminal', 'Set terminal parameters')
    tree['terminal'].add_child(CommandNode(
        'length', 'Set pagination length (0 to disable)',
        handler=sys_h.terminal_length,
        params=[ParamDef('lines', 'Number of lines (0 = no pagination)')],
    ))

    tree['commit'] = CommandNode(
        'commit', 'Commit the running configuration',
        handler=commit_h.do_commit,
        params=[
            ParamDef('confirmed', '"confirmed" keyword', required=False, choices=['confirmed']),
            ParamDef('minutes', 'Auto-rollback timer in minutes (1-60)', required=False),
        ],
        min_role='operator',
    )
    tree['rollback'] = CommandNode(
        'rollback', 'Load a previous configuration version',
        handler=commit_h.do_rollback,
        params=[ParamDef('version', 'Rollback version number (0-49)')],
        min_role='operator',
    )

    return tree


def build_configure_tree() -> dict:
    """Build commands for configure mode."""
    from cli.handlers import system as sys_h
    from cli.handlers import commit as commit_h

    tree = {}

    tree['interface'] = CommandNode(
        'interface', 'Configure a network interface',
        params=[ParamDef('name', 'Interface name (e.g., ens4)')],
    )
    tree['firewall'] = CommandNode('firewall', 'Enter firewall configuration mode')
    tree['vpn'] = CommandNode('vpn', 'Configure VPN')
    tree['vpn'].add_child(CommandNode(
        'network', 'Configure a VPN network',
        params=[ParamDef('name', 'Network name')],
    ))
    tree['dhcp'] = CommandNode('dhcp', 'Enter DHCP configuration mode')
    tree['dns'] = CommandNode('dns', 'Enter DNS configuration mode')
    tree['vlan'] = CommandNode(
        'vlan', 'Configure a VLAN',
        params=[ParamDef('id', 'VLAN ID (1-4094)')],
    )
    tree['zone'] = CommandNode(
        'zone', 'Configure a security zone',
        params=[ParamDef('name', 'Zone name')],
    )
    tree['hostname'] = CommandNode(
        'hostname', 'Set the gateway hostname',
        handler=sys_h.set_hostname,
        params=[ParamDef('name', 'New hostname')],
    )
    tree['nexus'] = CommandNode('nexus', 'KahLuna Nexus management')
    tree['nexus'].add_child(CommandNode(
        'register', 'Register with KahLuna Platform Core',
        handler=sys_h.nexus_register,
        params=[
            ParamDef('token', 'Provisioning token'),
            ParamDef('platform-url', 'Platform Core URL'),
        ],
    ))
    tree['nexus'].add_child(CommandNode('deregister', 'Deregister from KahLuna Platform Core', handler=sys_h.nexus_deregister))

    tree['webui'] = CommandNode('webui', 'Configure the web UI')
    tree['webui'].add_child(CommandNode(
        'enable', 'Enable the web UI',
        handler=sys_h.webui_enable,
    ))
    tree['webui'].add_child(CommandNode(
        'disable', 'Disable the web UI',
        handler=sys_h.webui_disable,
    ))
    tree['webui'].add_child(CommandNode(
        'listen', 'Set which interface the web UI listens on',
        handler=sys_h.webui_listen,
        params=[ParamDef('interface', 'Interface name, "all", or "localhost"')],
    ))

    tree['exit'] = CommandNode('exit', 'Return to privileged mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')
    tree['help'] = CommandNode('help', 'Display available commands')
    tree['show'] = CommandNode('show', 'Display system information (available in all modes)')
    tree['commit'] = CommandNode(
        'commit', 'Commit the running configuration',
        handler=commit_h.do_commit,
        params=[
            ParamDef('confirmed', '"confirmed" keyword', required=False, choices=['confirmed']),
            ParamDef('minutes', 'Auto-rollback timer in minutes (1-60)', required=False),
        ],
        min_role='operator',
    )
    tree['rollback'] = CommandNode(
        'rollback', 'Load a previous configuration version',
        handler=commit_h.do_rollback,
        params=[ParamDef('version', 'Rollback version number (0-49)')],
        min_role='operator',
    )

    return tree


def build_interface_submode_tree() -> dict:
    """Build commands for interface sub-configuration mode."""
    from cli.handlers import interface as if_h

    tree = {}

    tree['role'] = CommandNode(
        'role', 'Assign interface role',
        handler=if_h.set_role,
        params=[ParamDef('role', 'WAN, LAN, OPT, or DISABLED', choices=['WAN', 'LAN', 'OPT', 'DISABLED'])],
    )
    tree['ip'] = CommandNode('ip', 'Configure IP settings')
    tree['ip'].add_child(CommandNode(
        'address', 'Set IP address',
        handler=if_h.set_ip_address,
        params=[
            ParamDef('address', 'IP address or "dhcp"'),
            ParamDef('netmask', 'Subnet mask (e.g., 255.255.255.0)', required=False),
        ],
    ))
    tree['gateway'] = CommandNode(
        'gateway', 'Set the default gateway',
        handler=if_h.set_gateway,
        params=[ParamDef('address', 'Gateway IP address')],
    )
    tree['shutdown'] = CommandNode('shutdown', 'Disable the interface', handler=if_h.shutdown)
    tree['no'] = CommandNode('no', 'Negate a command')
    tree['no'].add_child(CommandNode('shutdown', 'Enable the interface', handler=if_h.no_shutdown))

    # Switchport commands
    tree['switchport'] = CommandNode('switchport', 'Configure Layer 2 switching')
    tree['switchport'].add_child(CommandNode(
        'mode', 'Set switchport mode',
        handler=if_h.set_switchport_mode,
        params=[ParamDef('mode', 'trunk, access, or routed', choices=['trunk', 'access', 'routed'])],
    ))
    tree['switchport'].add_child(CommandNode('trunk', 'Configure trunk settings'))
    tree['switchport'].children['trunk'].add_child(CommandNode(
        'allowed', 'Configure allowed VLANs'))
    tree['switchport'].children['trunk'].children['allowed'].add_child(CommandNode(
        'vlan', 'Set allowed VLAN list',
        handler=if_h.set_switchport_trunk_allowed,
        params=[ParamDef('list', 'VLAN IDs (comma-separated) or add/remove <list>')],
    ))
    tree['switchport'].children['trunk'].add_child(CommandNode(
        'native', 'Configure native VLAN'))
    tree['switchport'].children['trunk'].children['native'].add_child(CommandNode(
        'vlan', 'Set native VLAN ID',
        handler=if_h.set_switchport_trunk_native,
        params=[ParamDef('id', 'VLAN ID')],
    ))
    tree['switchport'].add_child(CommandNode('access', 'Configure access settings'))
    tree['switchport'].children['access'].add_child(CommandNode(
        'vlan', 'Set access VLAN',
        handler=if_h.set_switchport_access_vlan,
        params=[ParamDef('id', 'VLAN ID')],
    ))

    # Zone assignment
    tree['zone'] = CommandNode(
        'zone', 'Assign interface to a security zone',
        handler=if_h.set_interface_zone,
        params=[ParamDef('name', 'Zone name')],
    )

    # Description
    tree['description'] = CommandNode(
        'description', 'Set interface description',
        handler=if_h.set_description,
        params=[ParamDef('text', 'Description text')],
    )

    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')

    return tree


def build_firewall_submode_tree() -> dict:
    """Build commands for firewall sub-configuration mode."""
    from cli.handlers import firewall as fw_h

    tree = {}

    tree['rule'] = CommandNode(
        'rule', 'Add a firewall rule',
        handler=fw_h.add_rule,
        params=[
            ParamDef('chain', 'Chain: INPUT, FORWARD, OUTPUT', choices=['INPUT', 'FORWARD', 'OUTPUT']),
            ParamDef('action', 'ACCEPT, DROP, or REJECT', choices=['ACCEPT', 'DROP', 'REJECT']),
            ParamDef('protocol', 'Protocol: tcp, udp, icmp, any', choices=['tcp', 'udp', 'icmp', 'any']),
            ParamDef('source', 'Source IP/CIDR or "any"'),
            ParamDef('destination', 'Destination IP/CIDR or "any"'),
            ParamDef('port', 'Port number', required=False),
        ],
    )
    tree['port-forward'] = CommandNode(
        'port-forward', 'Add a port forwarding rule',
        handler=fw_h.add_port_forward,
        params=[
            ParamDef('wan-port', 'WAN port number'),
            ParamDef('lan-ip', 'LAN destination IP'),
            ParamDef('lan-port', 'LAN destination port'),
            ParamDef('protocol', 'Protocol: tcp or udp', required=False, choices=['tcp', 'udp']),
        ],
    )
    tree['no'] = CommandNode('no', 'Remove a rule')
    tree['no'].add_child(CommandNode(
        'rule', 'Remove a firewall rule',
        handler=fw_h.remove_rule,
        params=[ParamDef('rule-id', 'Rule ID to remove')],
    ))
    tree['no'].add_child(CommandNode(
        'port-forward', 'Remove a port forwarding rule',
        handler=fw_h.remove_port_forward,
        params=[ParamDef('id', 'Port forward ID to remove')],
    ))

    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')

    return tree


def build_vpn_submode_tree() -> dict:
    """Build commands for VPN network sub-configuration mode."""
    from cli.handlers import vpn as vpn_h

    tree = {}

    tree['type'] = CommandNode(
        'type', 'Set the VPN network type',
        handler=vpn_h.set_type,
        params=[ParamDef('type', 'Network type', choices=['secure_internet', 'remote_resource_gw', 'l3vpn_gateway'])],
    )
    tree['subnet'] = CommandNode(
        'subnet', 'Set the VPN subnet',
        handler=vpn_h.set_subnet,
        params=[ParamDef('cidr', 'Subnet in CIDR notation (e.g., 10.100.0.0/24)')],
    )
    tree['port'] = CommandNode(
        'port', 'Set the WireGuard listen port',
        handler=vpn_h.set_port,
        params=[ParamDef('number', 'Port number (51820-51829)')],
    )
    tree['peer'] = CommandNode(
        'peer', 'Add a VPN peer',
        handler=vpn_h.add_peer,
        params=[ParamDef('name', 'Peer name')],
    )
    tree['no'] = CommandNode('no', 'Remove a peer')
    tree['no'].add_child(CommandNode(
        'peer', 'Remove a VPN peer',
        handler=vpn_h.remove_peer,
        params=[ParamDef('name', 'Peer name to remove')],
    ))
    tree['rate-limit'] = CommandNode(
        'rate-limit', 'Set bandwidth limits',
        handler=vpn_h.set_rate_limit,
        params=[
            ParamDef('download', 'Download limit in Mbps'),
            ParamDef('upload', 'Upload limit in Mbps'),
        ],
    )

    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')

    return tree


def build_dhcp_submode_tree() -> dict:
    """Build commands for DHCP sub-configuration mode."""
    from cli.handlers import dhcp as dhcp_h

    tree = {}

    tree['pool'] = CommandNode(
        'pool', 'Configure DHCP address pool',
        handler=dhcp_h.set_pool,
        params=[
            ParamDef('interface', 'Interface name'),
            ParamDef('range', '"range" keyword', choices=['range']),
            ParamDef('start-ip', 'Start of IP range'),
            ParamDef('end-ip', 'End of IP range'),
        ],
    )
    tree['reservation'] = CommandNode(
        'reservation', 'Add a static DHCP reservation',
        handler=dhcp_h.add_reservation,
        params=[
            ParamDef('mac', 'MAC address (aa:bb:cc:dd:ee:ff)'),
            ParamDef('ip', 'IP address'),
            ParamDef('hostname', 'Hostname', required=False),
        ],
    )
    tree['no'] = CommandNode('no', 'Remove a reservation')
    tree['no'].add_child(CommandNode(
        'reservation', 'Remove a DHCP reservation',
        handler=dhcp_h.remove_reservation,
        params=[ParamDef('mac', 'MAC address to remove')],
    ))

    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')

    return tree


def build_dns_submode_tree() -> dict:
    """Build commands for DNS sub-configuration mode."""
    from cli.handlers import dns as dns_h

    tree = {}
    tree['override'] = CommandNode(
        'override', 'Add a DNS override',
        handler=dns_h.add_override,
        params=[
            ParamDef('hostname', 'Hostname'),
            ParamDef('ip', 'IP address'),
        ],
    )
    tree['no'] = CommandNode('no', 'Remove an override')
    tree['no'].add_child(CommandNode(
        'override', 'Remove a DNS override',
        handler=dns_h.remove_override,
        params=[ParamDef('hostname', 'Hostname to remove')],
    ))
    tree['upstream'] = CommandNode(
        'upstream', 'Set upstream DNS servers',
        handler=dns_h.set_upstream,
        params=[
            ParamDef('ip1', 'Primary DNS server'),
            ParamDef('ip2', 'Secondary DNS server', required=False),
        ],
    )

    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')

    return tree


# ── Mode-to-tree mapping ────────────────────────────────────────────────────

_TREES = None


def get_command_trees() -> dict:
    """
    Return the complete command trees keyed by mode.
    Exec and privileged trees are merged (privileged includes exec commands).
    """
    global _TREES
    if _TREES is not None:
        return _TREES

    exec_tree = build_exec_tree()
    priv_tree = build_privileged_tree()

    # Privileged mode includes all exec commands plus its own
    merged_priv = {}
    merged_priv.update(exec_tree)
    merged_priv.update(priv_tree)

    # Configure mode gets its own tree plus show from exec
    config_tree = build_configure_tree()
    # Wire the full show subtree into configure mode
    config_tree['show'] = exec_tree['show']

    _TREES = {
        EXEC: exec_tree,
        PRIVILEGED: merged_priv,
        CONFIGURE: config_tree,
        CONFIG_IF: build_interface_submode_tree(),
        CONFIG_FW: build_firewall_submode_tree(),
        CONFIG_VPN: build_vpn_submode_tree(),
        CONFIG_DHCP: build_dhcp_submode_tree(),
        CONFIG_DNS: build_dns_submode_tree(),
        CONFIG_VLAN: build_vlan_submode_tree(),
        CONFIG_ZONE: build_zone_submode_tree(),
    }
    return _TREES


def build_vlan_submode_tree() -> dict:
    """Build commands for VLAN sub-configuration mode."""
    from cli.handlers import vlan as vlan_h

    tree = {}
    tree['name'] = CommandNode(
        'name', 'Set VLAN name',
        handler=vlan_h.set_vlan_name,
        params=[ParamDef('name', 'VLAN name string')],
    )
    tree['no'] = CommandNode('no', 'Negate a command')
    tree['no'].add_child(CommandNode('name', 'Reset VLAN name to default', handler=vlan_h.no_vlan_name))
    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')
    return tree


def build_zone_submode_tree() -> dict:
    """Build commands for zone sub-configuration mode."""
    from cli.handlers import zone as zone_h

    tree = {}
    tree['description'] = CommandNode(
        'description', 'Set zone description',
        handler=zone_h.set_zone_description,
        params=[ParamDef('text', 'Description text')],
    )
    tree['policy'] = CommandNode(
        'policy', 'Add a zone firewall policy',
        handler=zone_h.add_zone_policy,
        params=[
            ParamDef('source', 'Source zone name'),
            ParamDef('destination', 'Destination zone name'),
            ParamDef('action', 'ACCEPT, DROP, or REJECT', choices=['ACCEPT', 'DROP', 'REJECT']),
            ParamDef('protocol', 'Protocol (optional)', required=False),
            ParamDef('port', 'Port (optional)', required=False),
        ],
    )
    tree['no'] = CommandNode('no', 'Remove a policy')
    tree['no'].add_child(CommandNode(
        'policy', 'Remove a zone policy',
        handler=zone_h.remove_zone_policy,
        params=[ParamDef('id', 'Policy ID')],
    ))
    tree['exit'] = CommandNode('exit', 'Return to configure mode')
    tree['end'] = CommandNode('end', 'Return to privileged mode')
    return tree
