"""
Main CLI shell -- WarpShell(cmd.Cmd).
One instance per session. Provides the Cisco/Juniper-style interactive CLI.
"""
import cmd
import getpass
import logging

from cli.modes import (
    ModeStack, EXEC, PRIVILEGED, CONFIGURE,
    CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
    PROMPT_SUFFIX,
)
from cli.parser import CommandParser, ParseResult
from cli.completer import TabCompleter
from cli.help_system import HelpSystem
from cli.formatter import OutputFormatter

logger = logging.getLogger('warp.cli.shell')


class WarpShell(cmd.Cmd):
    """
    Main CLI shell. One instance per session.
    Provides hierarchical modes, tab completion, help, and command dispatch.
    """

    intro = ''  # Set dynamically in preloop

    def __init__(self, app, user, source_ip, connection_type,
                 session_mgr=None, session_id=None):
        """
        Args:
            app: Flask application instance (context already pushed by caller).
            user: Authenticated User model instance.
            source_ip: Client IP address for audit logging.
            connection_type: 'ssh' or 'console'.
            session_mgr: SessionManager instance (optional).
            session_id: Session ID from SessionManager (optional).
        """
        super().__init__()
        self.app = app
        self.user = user
        self.source_ip = source_ip
        self.connection_type = connection_type
        self.session_mgr = session_mgr
        self.session_id = session_id

        self.mode_stack = ModeStack()
        self.parser = CommandParser()
        self.completer = TabCompleter()
        self.help_sys = HelpSystem()
        self.formatter = OutputFormatter()

        self._hostname = 'warp-gw'
        self._management_mode = 'standalone'
        self._load_gateway_config()

    def _load_gateway_config(self):
        """Load hostname and management mode from the database."""
        try:
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            self._hostname = config.hostname or 'warp-gw'
            self._management_mode = config.management_mode or 'standalone'
        except Exception:
            pass

    @property
    def prompt(self):
        """Generate the mode-aware prompt string."""
        nexus = ' [nexus]' if self._management_mode in ('managed', 'pre_provisioned') else ''
        suffix = PROMPT_SUFFIX.get(self.mode_stack.current, '>')
        return f'{self._hostname}{nexus}{suffix} '

    def preloop(self):
        """Display MOTD when the shell starts."""
        self._show_motd()

    def _show_motd(self):
        """Display the message of the day."""
        try:
            from services.health_service import get_system_health
            from services.interface_service import get_wan_interface
            from system.interfaces import get_public_ip

            health = get_system_health()
            wan = get_wan_interface()
            wan_ip = wan.ip_address if wan else 'not configured'

            try:
                public_ip = get_public_ip()
            except Exception:
                public_ip = wan_ip

            print()
            print(f'KahLuna WARP Gateway v{self._get_version()}')
            print(f'Hostname: {self._hostname}')
            print(f'WAN IP:   {public_ip}')
            print(f'Uptime:   {health.get("uptime", "unknown")}')
            print()
        except Exception:
            print()
            print(f'KahLuna WARP Gateway')
            print(f'Hostname: {self._hostname}')
            print()

    def _get_version(self):
        """Get the software version."""
        try:
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            return config.software_version
        except Exception:
            return '0.1.0'

    # ── Mode transitions ─────────────────────────────────────────────────

    def do_enable(self, args):
        """Enter privileged mode."""
        if self.mode_stack.current != EXEC:
            return

        # Check enable password
        try:
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            if config.enable_password_hash:
                password = getpass.getpass('Password: ')
                if not config.check_enable_password(password):
                    print('% Access denied')
                    return
        except Exception:
            pass

        self.mode_stack.push(PRIVILEGED)
        self._sync_session_mode()

    def do_disable(self, args):
        """Return to exec mode from privileged."""
        if self.mode_stack.current == PRIVILEGED:
            self.mode_stack.reset_to(EXEC)
            self._sync_session_mode()

    def do_configure(self, args):
        """Enter configuration mode."""
        if self.mode_stack.current != PRIVILEGED:
            print('% Must be in privileged mode')
            return

        # Warn about concurrent configure sessions
        if self.session_mgr:
            others = self.session_mgr.get_configure_sessions()
            others = [s for s in others if s.session_id != self.session_id]
            if others:
                for s in others:
                    print(f'% Warning: User "{s.username}" is also in configure mode')

        self.mode_stack.push(CONFIGURE)
        self._sync_session_mode()

    def do_exit(self, args):
        """Exit the current mode or disconnect."""
        current = self.mode_stack.current

        if current == EXEC:
            print('Goodbye.')
            return True  # Exits cmdloop

        if current in (CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS):
            self.mode_stack.pop()
        elif current == CONFIGURE:
            self.mode_stack.reset_to(PRIVILEGED)
        elif current == PRIVILEGED:
            self.mode_stack.reset_to(EXEC)

        self._sync_session_mode()

    def do_end(self, args):
        """Return to privileged mode from any config/sub-config mode."""
        current = self.mode_stack.current
        if current in (CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS):
            self.mode_stack.reset_to(PRIVILEGED)
            self._sync_session_mode()

    # ── Command dispatch ─────────────────────────────────────────────────

    def default(self, line):
        """Route unrecognized input through the command parser."""
        if not line.strip():
            return

        # Check for "?" help request
        if '?' in line:
            help_line = line.split('?')[0]
            help_text = self.help_sys.get_help(help_line, self.mode_stack.current)
            print(help_text)
            return

        # Touch session for idle timeout
        if self.session_mgr and self.session_id:
            self.session_mgr.touch(self.session_id)

        result = self.parser.parse(line, self.mode_stack.current)

        if result.error == 'unknown':
            print(f'% Unknown command "{line.strip()}"')
            return

        if result.error == 'ambiguous':
            names = ', '.join(m.name for m in result.matches)
            first_token = line.strip().split()[0] if line.strip() else ''
            print(f'% Ambiguous command "{first_token}": {names}')
            return

        if result.resolved_node is None:
            return

        node = result.resolved_node

        # Handle mode-entry commands that the parser resolved
        self._handle_mode_entry(node, result)

        # If the node has a handler, call it
        if node.handler:
            # Check role permission
            if not self._check_permission(node.min_role):
                print(f'% Permission denied. Required role: {node.min_role}')
                return

            # Record config commands for audit
            if self.mode_stack.current.startswith('config') and self.session_mgr and self.session_id:
                self.session_mgr.record_command(self.session_id, line.strip())

            try:
                node.handler(self, result.args)
            except Exception as e:
                print(f'% Error: {e}')
                logger.error(f'Command handler error: {e}', exc_info=True)

    def _handle_mode_entry(self, node, result):
        """Handle commands that enter sub-configuration modes."""
        current = self.mode_stack.current

        if current == CONFIGURE:
            if node.name == 'interface' and result.args:
                self.mode_stack.push(CONFIG_IF, {'interface': result.args[0]})
                self._sync_session_mode()
            elif node.name == 'firewall':
                self.mode_stack.push(CONFIG_FW)
                self._sync_session_mode()
            elif node.name == 'network' and result.path == ['vpn', 'network'] and result.args:
                self.mode_stack.push(CONFIG_VPN, {'network': result.args[0]})
                self._sync_session_mode()
            elif node.name == 'dhcp':
                self.mode_stack.push(CONFIG_DHCP)
                self._sync_session_mode()
            elif node.name == 'dns':
                self.mode_stack.push(CONFIG_DNS)
                self._sync_session_mode()

    def _check_permission(self, min_role):
        """Check if the current user has the required role."""
        role_levels = {'viewer': 0, 'operator': 1, 'admin': 2}
        user_level = role_levels.get(self.user.role, 0)
        required_level = role_levels.get(min_role, 0)
        return user_level >= required_level

    def _sync_session_mode(self):
        """Sync the current mode to the session manager."""
        if self.session_mgr and self.session_id:
            self.session_mgr.update_mode(self.session_id, self.mode_stack.current)

    # ── Tab completion ───────────────────────────────────────────────────

    def completedefault(self, text, line, begidx, endidx):
        """Delegate tab completion to the TabCompleter."""
        return self.completer.complete(text, line, self.mode_stack.current)

    def completenames(self, text, *ignored):
        """Override to use our completer for first-token completion too."""
        return self.completer.complete(text, text, self.mode_stack.current)

    # ── Help ─────────────────────────────────────────────────────────────

    def do_help(self, args):
        """Display available commands."""
        help_text = self.help_sys.get_help('', self.mode_stack.current)
        print(help_text)

    # ── Idle timeout check ───────────────────────────────────────────────

    def precmd(self, line):
        """Check idle timeout before processing each command."""
        if self.session_mgr and self.session_id:
            if self.session_mgr.check_idle(self.session_id):
                timeout_min = self.session_mgr.idle_timeout // 60
                print(f'\n% Session timed out after {timeout_min} minutes of inactivity')
                return 'exit'
            self.session_mgr.touch(self.session_id)
        return line

    # ── Prevent cmd.Cmd from handling these directly ─────────────────────

    def emptyline(self):
        """Do nothing on empty input (don't repeat last command)."""
        pass
