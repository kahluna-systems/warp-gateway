"""
Configuration serializer for running-config and startup-config.
Serializes gateway configuration to/from CLI command text format.
"""
import os
import logging
from datetime import datetime

logger = logging.getLogger('warp.cli.config')

# Default paths for startup-config
APPLIANCE_CONFIG_PATH = '/etc/warp-gateway/startup-config'


class ConfigSerializer:
    """Serializes gateway configuration to/from CLI command text."""

    def __init__(self, app_dir: str = None):
        self.app_dir = app_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def serialize_running_config(self) -> str:
        """
        Query all configuration from the database and serialize
        to a text block of CLI commands.
        """
        # Stub -- will be implemented in Task 14
        from models_new import (
            GatewayConfig, InterfaceConfig, FirewallRule, PortForward,
            VPNNetwork, Endpoint, DhcpConfig, DhcpReservation, DnsOverride,
        )

        lines = []
        lines.append('!')
        lines.append('! WARP Gateway Configuration')
        lines.append(f'! Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}')

        config = GatewayConfig.get_instance()
        lines.append(f'! Software: {config.software_version}')
        lines.append('!')
        lines.append(f'hostname {config.hostname}')
        lines.append('!')

        # Interfaces
        for iface in InterfaceConfig.query.all():
            lines.append(f'interface {iface.name}')
            lines.append(f'  role {iface.role}')
            if iface.mode == 'dhcp':
                lines.append('  ip address dhcp')
            elif iface.ip_address:
                mask = iface.netmask or '255.255.255.0'
                lines.append(f'  ip address {iface.ip_address} {mask}')
            if iface.gateway:
                lines.append(f'  gateway {iface.gateway}')
            lines.append('!')

        # Firewall
        rules = FirewallRule.query.filter_by(is_active=True).all()
        forwards = PortForward.query.filter_by(is_active=True).all()
        if rules or forwards:
            lines.append('firewall')
            for rule in rules:
                src = rule.source or 'any'
                dst = rule.destination or 'any'
                proto = rule.protocol or 'any'
                port_str = f' {rule.port}' if rule.port else ''
                lines.append(f'  rule {rule.chain} {rule.action} {proto} {src} {dst}{port_str}')
            for fwd in forwards:
                proto = fwd.protocol or 'tcp'
                lines.append(f'  port-forward {fwd.wan_port} {fwd.lan_ip} {fwd.lan_port} {proto}')
            lines.append('!')

        # VPN Networks
        for net in VPNNetwork.query.all():
            lines.append(f'vpn network {net.name}')
            lines.append(f'  type {net.network_type}')
            lines.append(f'  subnet {net.subnet}')
            lines.append(f'  port {net.port}')
            for ep in net.endpoints:
                lines.append(f'  peer {ep.name}')
            if net.rate_limit_enabled:
                dl = net.rate_limit_download_mbps or 0
                ul = net.rate_limit_upload_mbps or 0
                lines.append(f'  rate-limit {dl} {ul}')
            lines.append('!')

        # DHCP
        dhcp_configs = DhcpConfig.query.all()
        reservations = DhcpReservation.query.all()
        if dhcp_configs or reservations:
            lines.append('dhcp')
            for dc in dhcp_configs:
                lines.append(f'  pool {dc.interface} range {dc.range_start} {dc.range_end}')
            for res in reservations:
                hostname = f' {res.hostname}' if res.hostname else ''
                lines.append(f'  reservation {res.mac} {res.ip}{hostname}')
            lines.append('!')

        # DNS
        overrides = DnsOverride.query.all()
        if overrides:
            lines.append('dns')
            for ov in overrides:
                lines.append(f'  override {ov.hostname} {ov.ip}')
            lines.append('!')

        # Management mode
        lines.append(f'nexus {config.management_mode}')
        lines.append('!')
        lines.append('end')

        return '\n'.join(lines)

    def parse_config_text(self, text: str) -> list:
        """
        Parse a config text block into a list of command strings
        that can be replayed to reproduce the configuration.
        """
        # Stub -- will be fully implemented in Task 14
        commands = []
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('!') or line == 'end':
                continue
            commands.append(line)
        return commands

    def save_startup_config(self) -> bool:
        """Write running-config to persistent storage."""
        try:
            config_text = self.serialize_running_config()

            # Try appliance path first, fall back to app dir
            config_path = APPLIANCE_CONFIG_PATH
            config_dir = os.path.dirname(config_path)
            if not os.path.isdir(config_dir):
                config_path = os.path.join(self.app_dir, 'startup-config')

            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                f.write(config_text)

            logger.info(f'Startup config saved to {config_path}')
            return True
        except Exception as e:
            logger.error(f'Failed to save startup config: {e}')
            return False

    def load_startup_config(self) -> str:
        """Read startup-config from persistent storage."""
        for path in [APPLIANCE_CONFIG_PATH, os.path.join(self.app_dir, 'startup-config')]:
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as f:
                        return f.read()
                except Exception as e:
                    logger.error(f'Failed to read startup config from {path}: {e}')
        return None
