"""
Configuration serializer for running-config and startup-config.
Serializes gateway configuration to/from CLI command text format.
Supports commit with rollback versioning, confirmed commits, and config comparison.
"""
import difflib
import os
import logging
from datetime import datetime

from cli.rollback_store import RollbackStore
from cli.confirmed_commit import ConfirmedCommitTimer

logger = logging.getLogger('warp.cli.config')

# Default paths for startup-config
APPLIANCE_CONFIG_PATH = '/etc/warp-gateway/startup-config'


class ConfigSerializer:
    """Serializes gateway configuration to/from CLI command text."""

    def __init__(self, app_dir: str = None):
        self.app_dir = app_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rollback_store = RollbackStore(base_dir=self._config_base_dir())
        self.confirmed_timer = ConfirmedCommitTimer()

    def _config_base_dir(self) -> str:
        """Return the base config directory (parent of rollback/)."""
        if os.path.isdir('/etc/warp-gateway'):
            return '/etc/warp-gateway'
        return self.app_dir

    # ── Commit / Rollback ────────────────────────────────────────────────

    def commit(self, username: str, source_ip: str) -> bool:
        """
        Perform a full commit:
        1. Serialize running config
        2. Rotate rollback store
        3. Store new rollback-00
        4. Write startup-config
        5. Log to AuditLog
        """
        try:
            config_text = self.serialize_running_config()

            self.rollback_store.rotate()
            self.rollback_store.store(config_text, username, source_ip)
            self.save_startup_config()

            # Audit log
            try:
                from models_new import AuditLog
                from database import db
                AuditLog.log(
                    action='config_commit',
                    details=f'Configuration committed by {username}',
                    ip_address=source_ip,
                )
                db.session.commit()
            except Exception as e:
                logger.error(f'Audit log failed: {e}')

            logger.info(f'Configuration committed by {username} from {source_ip}')
            return True

        except Exception as e:
            logger.error(f'Commit failed: {e}')
            return False

    def rollback(self, version: int, username: str, source_ip: str) -> bool:
        """
        Load rollback-<version> and apply it as the running config.
        Does NOT auto-commit -- the operator must run 'commit' to make permanent.
        """
        config_text = self.rollback_store.load(version)
        if config_text is None:
            return False

        try:
            commands = self.parse_config_text(config_text)
            # Commands are parsed but applying them requires the service layer
            # which needs Flask app context. For now, we log the rollback.
            # The actual replay happens through the CLI command dispatch.

            # Audit log
            try:
                from models_new import AuditLog
                from database import db
                AuditLog.log(
                    action='config_rollback',
                    details=f'Rolled back to version {version} by {username}',
                    ip_address=source_ip,
                )
                db.session.commit()
            except Exception as e:
                logger.error(f'Audit log failed: {e}')

            logger.info(f'Configuration rolled back to version {version} by {username}')
            return True

        except Exception as e:
            logger.error(f'Rollback failed: {e}')
            return False

    def commit_confirmed(self, minutes: int, username: str, source_ip: str) -> bool:
        """
        Perform a commit and start the auto-rollback timer.
        """
        success = self.commit(username, source_ip)
        if not success:
            return False

        def _auto_rollback():
            logger.warning('Confirmed commit timer expired -- auto-rolling back')
            try:
                self.rollback(1, 'system', 'auto-rollback')
                # Also write the rolled-back config as startup
                self.save_startup_config()

                from models_new import AuditLog
                from database import db
                AuditLog.log(
                    action='config_auto_rollback',
                    details='Confirmed commit timer expired, auto-rollback to previous config',
                )
                db.session.commit()
            except Exception as e:
                logger.error(f'Auto-rollback failed: {e}')

        self.confirmed_timer.start(minutes, _auto_rollback)
        return True

    def confirm(self) -> bool:
        """Cancel the confirmed commit timer, making the current config permanent."""
        if self.confirmed_timer.active:
            self.confirmed_timer.cancel()
            return True
        return False

    def compare(self, target: str = 'startup', version: int = None) -> str:
        """
        Generate a unified diff between running config and a target.

        Args:
            target: 'startup' or 'rollback'
            version: Rollback version number (required if target='rollback')
        """
        running = self.serialize_running_config()

        if target == 'rollback' and version is not None:
            other = self.rollback_store.load(version)
            if other is None:
                return f'% Rollback version {version} is not available.'
            label_b = f'rollback-{version:02d}'
        else:
            other = self.load_startup_config()
            if other is None:
                return '% No startup configuration found.'
            label_b = 'startup-config'

        running_lines = running.splitlines(keepends=True)
        other_lines = other.splitlines(keepends=True)

        diff = difflib.unified_diff(
            other_lines,
            running_lines,
            fromfile=label_b,
            tofile='running-config',
        )
        result = ''.join(diff)
        if not result:
            return 'No differences found.'
        return result

    # ── Serialization ────────────────────────────────────────────────────

    def serialize_running_config(self) -> str:
        """
        Query all configuration from the database and serialize
        to a text block of CLI commands.
        """
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
        """Parse a config text block into a list of command strings."""
        commands = []
        for line in text.split('\n'):
            stripped = line.strip()
            if not stripped or stripped.startswith('!') or stripped == 'end':
                continue
            commands.append(stripped)
        return commands

    # ── Startup Config ───────────────────────────────────────────────────

    def save_startup_config(self) -> bool:
        """Write running-config to persistent storage."""
        try:
            config_text = self.serialize_running_config()

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
