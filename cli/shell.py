"""
Main CLI shell -- WarpShell(cmd.Cmd).
One instance per session. Provides the Cisco/Juniper-style interactive CLI.

The "?" key is intercepted in real time (no Enter needed) using readline
key bindings, matching Cisco IOS behavior.
"""
import cmd
import getpass
import logging
import os
import sys

from cli.modes import (
    ModeStack, EXEC, PRIVILEGED, CONFIGURE,
    CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
    CONFIG_PRIVATE, CONFIG_EXCLUSIVE, CONFIG_VLAN, CONFIG_ZONE,
    PROMPT_SUFFIX,
)
from cli.parser import CommandParser, ParseResult
from cli.completer import TabCompleter
from cli.help_system import HelpSystem
from cli.formatter import OutputFormatter
from cli.pipe_filters import parse_pipe, apply_filters, get_filter_help

logger = logging.getLogger('warp.cli.shell')


def _setup_readline_help_binding(shell_ref):
    """
    Bind the '?' key in readline so it triggers help immediately
    without requiring Enter. This is the Cisco IOS behavior.
    """
    try:
        import readline

        def _help_key_handler(count, key):
            """Called when '?' is pressed. Shows help and re-presents the prompt."""
            # Get the current input buffer
            buf = readline.get_line_buffer()

            # Print newline, then help
            print()
            help_text = shell_ref.help_sys.get_help(buf, shell_ref.mode_stack.current)
            print(help_text)

            # Re-display the prompt and current input
            sys.stdout.write(shell_ref.prompt + buf)
            sys.stdout.flush()

            # Tell readline to redisplay
            readline.redisplay()
            return 0

        # Bind '?' (ASCII 63) to our handler
        readline.set_pre_input_hook(None)
        readline.parse_and_bind('"?": "\\C-x?"')

        # Use a startup hook to install the binding after readline is ready
        # We use the callback approach via parse_and_bind with a macro
        # that inserts nothing but triggers our function

        # Alternative approach: use the rl_bind_key via ctypes
        try:
            import ctypes
            import ctypes.util

            # Find the readline library
            lib_name = ctypes.util.find_library('readline')
            if not lib_name:
                # Try common paths
                for candidate in ['libreadline.so', 'libreadline.so.8', 'libreadline.so.6']:
                    try:
                        ctypes.CDLL(candidate)
                        lib_name = candidate
                        break
                    except OSError:
                        continue

            if lib_name:
                rl_lib = ctypes.CDLL(lib_name)

                # Define the callback type: int (*rl_command_func_t)(int, int)
                RL_COMMAND_FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int)

                # Keep a reference to prevent garbage collection
                shell_ref._help_callback = RL_COMMAND_FUNC(_help_key_handler)

                # Bind '?' (key code 63) to our callback
                rl_lib.rl_bind_key(63, shell_ref._help_callback)

                logger.debug('Readline "?" binding installed via ctypes')
                return True
        except Exception as e:
            logger.debug(f'ctypes readline binding failed: {e}')

        # Fallback: use parse_and_bind to make '?' self-insert but we'll
        # catch it in precmd. Not ideal but better than nothing.
        logger.debug('Falling back to precmd-based "?" handling')
        return False

    except ImportError:
        logger.debug('readline not available -- "?" requires Enter')
        return False


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
        self._help_binding_active = False
        self._help_callback = None  # prevent GC of ctypes callback
        self._terminal_length = 24  # pagination page size (0 = disabled)
        self._command_history = []  # session command history
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
        """Display MOTD and set up readline bindings when the shell starts."""
        self._show_motd()
        self._help_binding_active = _setup_readline_help_binding(self)

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
            print(f'Web UI:   http://{wan_ip or "localhost"}:5000')
            print()
        except Exception:
            print()
            print(f'KahLuna WARP Gateway')
            print(f'Hostname: {self._hostname}')
            print(f'Web UI:   http://localhost:5000')
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

        mode_arg = args.strip().lower() if isinstance(args, str) else ''

        # Check exclusive lock for all configure modes
        if self.session_mgr and self.session_id:
            if self.session_mgr.is_exclusive_blocked(self.session_id):
                holder = self.session_mgr.get_exclusive_holder()
                if holder:
                    print(f'% Configuration locked by user "{holder.username}" from {holder.source_ip}')
                else:
                    print('% Configuration is locked by another session')
                return

        if mode_arg == 'private':
            # Configure private -- isolated candidate config
            from cli.config_serializer import ConfigSerializer
            serializer = ConfigSerializer()
            baseline = serializer.serialize_running_config()

            if self.session_mgr and self.session_id:
                self.session_mgr.create_candidate(self.session_id, baseline)

                from models_new import AuditLog
                from database import db
                AuditLog.log('config_private_start',
                             f'Configure private session started',
                             ip_address=self.source_ip)
                db.session.commit()

            self.mode_stack.push(CONFIG_PRIVATE)
            self._sync_session_mode()
            return

        if mode_arg == 'exclusive':
            # Configure exclusive -- acquire lock
            if self.session_mgr and self.session_id:
                acquired = self.session_mgr.acquire_exclusive(self.session_id)
                if not acquired:
                    holder = self.session_mgr.get_exclusive_holder()
                    if holder:
                        print(f'% Configuration locked by user "{holder.username}" from {holder.source_ip}')
                    else:
                        print('% Configuration is locked by another session')
                    return

                from models_new import AuditLog
                from database import db
                AuditLog.log('config_exclusive_lock',
                             f'Exclusive configure lock acquired',
                             ip_address=self.source_ip)
                db.session.commit()

            self.mode_stack.push(CONFIG_EXCLUSIVE)
            self._sync_session_mode()
            return

        # Standard configure terminal
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

        if current in (CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
                       CONFIG_VLAN, CONFIG_ZONE):
            self.mode_stack.pop()
        elif current == CONFIG_PRIVATE:
            # Discard candidate and warn
            if self.session_mgr and self.session_id:
                candidate = self.session_mgr.get_candidate(self.session_id)
                if candidate and candidate.commands:
                    print('% Warning: uncommitted changes discarded')
                self.session_mgr.discard_candidate(self.session_id)

                from models_new import AuditLog
                from database import db
                AuditLog.log('config_private_end', 'Configure private session ended',
                             ip_address=self.source_ip)
                db.session.commit()

            self.mode_stack.reset_to(PRIVILEGED)
        elif current == CONFIG_EXCLUSIVE:
            # Release exclusive lock
            if self.session_mgr and self.session_id:
                self.session_mgr.release_exclusive(self.session_id)

                from models_new import AuditLog
                from database import db
                AuditLog.log('config_exclusive_unlock', 'Exclusive configure lock released',
                             ip_address=self.source_ip)
                db.session.commit()

            self.mode_stack.reset_to(PRIVILEGED)
        elif current == CONFIGURE:
            self.mode_stack.reset_to(PRIVILEGED)
        elif current == PRIVILEGED:
            self.mode_stack.reset_to(EXEC)

        self._sync_session_mode()

    def do_end(self, args):
        """Return to privileged mode from any config/sub-config mode."""
        current = self.mode_stack.current
        if current in (CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
                       CONFIG_PRIVATE, CONFIG_EXCLUSIVE, CONFIG_VLAN, CONFIG_ZONE):
            # Handle private/exclusive cleanup
            if current == CONFIG_PRIVATE:
                if self.session_mgr and self.session_id:
                    candidate = self.session_mgr.get_candidate(self.session_id)
                    if candidate and candidate.commands:
                        print('% Warning: uncommitted changes discarded')
                    self.session_mgr.discard_candidate(self.session_id)
            elif current == CONFIG_EXCLUSIVE:
                if self.session_mgr and self.session_id:
                    self.session_mgr.release_exclusive(self.session_id)

            self.mode_stack.reset_to(PRIVILEGED)
            self._sync_session_mode()

    # ── Command dispatch ─────────────────────────────────────────────────

    def default(self, line):
        """Route unrecognized input through the command parser."""
        if not line.strip():
            return

        # Handle "?" in the input (fallback if readline binding didn't work)
        if '?' in line:
            help_line = line.split('?')[0]
            # Check if asking about pipe filters
            if '|' in help_line:
                print(get_filter_help())
            else:
                help_text = self.help_sys.get_help(help_line, self.mode_stack.current)
                print(help_text)
            return

        # Record in session history
        self._command_history.append(line.strip())

        # Touch session for idle timeout
        if self.session_mgr and self.session_id:
            self.session_mgr.touch(self.session_id)

        # Parse pipe filters
        command, filters = parse_pipe(line)

        if not command.strip():
            return

        result = self.parser.parse(command, self.mode_stack.current)

        if result.error == 'unknown':
            print(f'% Unknown command "{command.strip()}"')
            return

        if result.error == 'ambiguous':
            names = ', '.join(m.name for m in result.matches)
            first_token = command.strip().split()[0] if command.strip() else ''
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
                if filters:
                    # Capture output for pipe filtering
                    import io
                    import sys
                    old_stdout = sys.stdout
                    sys.stdout = capture = io.StringIO()
                    try:
                        node.handler(self, result.args)
                    finally:
                        sys.stdout = old_stdout
                    raw_output = capture.getvalue()

                    # Apply filters
                    filtered, no_more = apply_filters(raw_output.rstrip('\n'), filters)

                    # Output with or without pagination
                    if no_more or self._terminal_length == 0:
                        print(filtered)
                    else:
                        self.formatter.paginate(filtered)
                else:
                    node.handler(self, result.args)
            except Exception as e:
                print(f'% Error: {e}')
                logger.error(f'Command handler error: {e}', exc_info=True)

    def _handle_mode_entry(self, node, result):
        """Handle commands that enter sub-configuration modes."""
        current = self.mode_stack.current

        if current in (CONFIGURE, CONFIG_PRIVATE, CONFIG_EXCLUSIVE):
            if node.name == 'interface' and result.args:
                iface_name = result.args[0]
                # Auto-create VLAN sub-interface if name contains a dot
                if '.' in iface_name:
                    try:
                        parent, vid_str = iface_name.rsplit('.', 1)
                        if vid_str.isdigit():
                            from services.vlan_service import create_sub_interface
                            create_sub_interface(parent, int(vid_str))
                    except Exception:
                        pass
                self.mode_stack.push(CONFIG_IF, {'interface': iface_name})
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
            elif node.name == 'vlan' and result.args:
                vlan_id = int(result.args[0]) if result.args[0].isdigit() else None
                if vlan_id:
                    # Auto-create VLAN if it doesn't exist
                    from services.vlan_service import create_vlan, get_vlan
                    if not get_vlan(vlan_id):
                        create_vlan(vlan_id)
                    self.mode_stack.push(CONFIG_VLAN, {'vlan_id': vlan_id})
                    self._sync_session_mode()
            elif node.name == 'zone' and result.args:
                zone_name = result.args[0]
                # Auto-create zone if it doesn't exist
                from services.zone_service import create_zone, get_zone
                if not get_zone(zone_name):
                    create_zone(zone_name)
                self.mode_stack.push(CONFIG_ZONE, {'zone_name': zone_name})
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
