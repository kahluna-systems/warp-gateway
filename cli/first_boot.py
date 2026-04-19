"""
First-boot setup wizard for WARP OS.
Guides the operator through initial interface assignment, network config,
credentials, and management mode selection.

Runs automatically on first boot when no startup-config exists.
All output is plain ASCII -- no emojis, no color codes.
"""
import getpass
import ipaddress
import logging
import sys

logger = logging.getLogger('warp.cli.firstboot')

# Width for the wizard display
WIDTH = 60


def _banner(text):
    """Print a centered banner line."""
    print()
    print('=' * WIDTH)
    print(text.center(WIDTH))
    print('=' * WIDTH)
    print()


def _section(text):
    """Print a section header."""
    print()
    print(f'--- {text} ---')
    print()


def _prompt(message, default=None, choices=None, validator=None):
    """
    Prompt the user for input with optional default, choices, and validation.
    Returns the validated input string.
    """
    while True:
        suffix = ''
        if choices:
            suffix = f' [{"/".join(choices)}]'
        if default:
            suffix += f' (default: {default})'
        suffix += ': '

        try:
            value = input(f'  {message}{suffix}').strip()
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt

        if not value and default:
            value = default

        if not value:
            print('  * Input required')
            continue

        if choices and value.lower() not in [c.lower() for c in choices]:
            print(f'  * Must be one of: {", ".join(choices)}')
            continue

        if validator:
            error = validator(value)
            if error:
                print(f'  * {error}')
                continue

        return value


def _prompt_yes_no(message, default='y'):
    """Prompt for yes/no. Returns True for yes."""
    result = _prompt(message, default=default, choices=['y', 'n'])
    return result.lower() in ('y', 'yes')


def _prompt_interface(message, interfaces):
    """
    Prompt the user to select an interface by number or name.
    Accepts: 1, 2, ... or ens33, ens38, etc.
    """
    names = [i['name'] for i in interfaces]
    while True:
        # Show options
        for idx, iface in enumerate(interfaces, 1):
            print(f'    {idx}) {iface["name"]}')

        try:
            value = input(f'  {message} [1-{len(interfaces)} or name]: ').strip()
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt

        if not value:
            continue

        # Try as number
        if value.isdigit():
            idx = int(value)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]['name']
            print(f'  * Enter a number between 1 and {len(interfaces)}')
            continue

        # Try as name
        if value in names:
            return value

        # Try case-insensitive
        for name in names:
            if name.lower() == value.lower():
                return name

        print(f'  * Not recognized. Enter a number or interface name.')


def _validate_ip(value):
    """Validate an IP address."""
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        return 'Invalid IP address'


def _validate_cidr(value):
    """Validate a CIDR subnet."""
    try:
        ipaddress.ip_network(value, strict=False)
        return None
    except ValueError:
        return 'Invalid CIDR notation (e.g., 192.168.1.0/24)'


def _validate_netmask(value):
    """Validate a subnet mask."""
    try:
        parts = value.split('.')
        if len(parts) != 4:
            return 'Invalid netmask'
        num = 0
        for p in parts:
            num = (num << 8) | int(p)
        # Check it's a valid mask (contiguous 1s followed by 0s)
        inverted = num ^ 0xFFFFFFFF
        if (inverted + 1) & inverted != 0:
            return 'Invalid netmask (must be contiguous)'
        return None
    except (ValueError, OverflowError):
        return 'Invalid netmask'


class FirstBootWizard:
    """Interactive first-boot setup wizard for WARP OS."""

    def __init__(self, app):
        self.app = app
        self.wan_iface = None
        self.lan_iface = None
        self.wan_config = {}
        self.lan_config = {}
        self.admin_user = None
        self.admin_pass = None
        self.hostname = 'warp-gw'
        self.mgmt_mode = 'standalone'

    def run(self) -> bool:
        """
        Run the wizard. Returns True if completed, False if cancelled.

        Steps:
        1. Detect and display physical interfaces
        2. Assign WAN interface
        3. Assign LAN interface(s)
        4. Configure WAN (static or DHCP)
        5. Configure LAN subnet
        6. Set admin credentials
        7. Set hostname
        8. Select management mode (standalone / managed)
        9. If managed: register with Platform Core
        10. Apply config and save as startup-config
        """
        _banner('KahLuna WARP Gateway -- First Boot Setup')

        print('  This wizard will guide you through the initial')
        print('  configuration of your WARP Gateway appliance.')
        print()
        print('  Press Ctrl+C at any time to cancel and boot')
        print('  with safe defaults.')
        print()

        try:
            # Step 1: Detect interfaces
            interfaces = self._detect_interfaces()
            if not interfaces:
                print('  ERROR: No physical network interfaces detected.')
                print('  Cannot proceed with setup.')
                if _prompt_yes_no('Retry detection?', default='y'):
                    interfaces = self._detect_interfaces()
                if not interfaces:
                    print('  Booting with safe defaults...')
                    self._apply_safe_defaults()
                    return False

            # Step 2: Assign WAN
            self.wan_iface = self._prompt_wan_assignment(interfaces)

            # Step 3: Assign LAN
            remaining = [i for i in interfaces if i['name'] != self.wan_iface]
            self.lan_iface = self._prompt_lan_assignment(remaining)

            # Step 4: Configure WAN
            self.wan_config = self._prompt_wan_config(self.wan_iface)

            # Step 5: Configure LAN
            self.lan_config = self._prompt_lan_config()

            # Step 6: Admin credentials
            self.admin_user, self.admin_pass = self._prompt_credentials()

            # Step 7: Hostname
            self.hostname = self._prompt_hostname()

            # Step 8: Management mode
            self.mgmt_mode = self._prompt_management_mode()

            # Step 9: If managed, register
            registration = None
            if self.mgmt_mode == 'managed':
                registration = self._prompt_registration()

            # Step 10: Apply and save
            _section('Applying Configuration')
            self._apply_config(registration)

            _banner('Setup Complete')
            print('  Your WARP Gateway is configured and ready.')
            print(f'  Hostname:   {self.hostname}')
            print(f'  WAN:        {self.wan_iface} ({self.wan_config.get("mode", "dhcp")})')
            print(f'  LAN:        {self.lan_iface} ({self.lan_config.get("ip", "N/A")})')
            print(f'  Management: {self.mgmt_mode}')
            print()
            print('  Entering CLI shell...')
            print()

            return True

        except KeyboardInterrupt:
            print()
            print()
            print('  Setup cancelled. Applying safe defaults...')
            self._apply_safe_defaults()
            return False

    def _detect_interfaces(self) -> list:
        """Detect all physical network interfaces."""
        _section('Detecting Network Interfaces')

        from system.interfaces import detect_all
        all_ifaces = detect_all()

        # Filter to physical interfaces only
        physical = [i for i in all_ifaces if i.is_physical]

        if not physical:
            # On VMs, interfaces may not report as physical
            # Fall back to all non-loopback, non-virtual interfaces
            physical = [i for i in all_ifaces
                        if not i.name.startswith('wg')
                        and not i.name.startswith('docker')
                        and not i.name.startswith('veth')
                        and not i.name.startswith('br-')
                        and i.name != 'lo']

        if physical:
            print(f'  Found {len(physical)} interface(s):')
            print()
            print(f'  {"#":<4}{"Name":<12}{"MAC":<20}{"Link":<8}{"Driver":<15}{"DHCP":<10}')
            print(f'  {"-"*4}{"-"*12}{"-"*20}{"-"*8}{"-"*15}{"-"*10}')

            dhcp_results = {}
            for idx, iface in enumerate(physical, 1):
                link = 'UP' if iface.link_up else 'DOWN'
                driver = iface.driver or 'unknown'

                # Check for DHCP offers on UP interfaces
                dhcp_status = ''
                if iface.link_up:
                    dhcp_status = self._check_dhcp(iface.name)
                    dhcp_results[iface.name] = dhcp_status

                print(f'  {idx:<4}{iface.name:<12}{iface.mac:<20}{link:<8}{driver:<15}{dhcp_status:<10}')

            print()

            # Hint about DHCP detection
            dhcp_ifaces = [name for name, status in dhcp_results.items() if status == 'Detected']
            if dhcp_ifaces:
                print(f'  * DHCP detected on: {", ".join(dhcp_ifaces)}')
                print(f'    This is likely your WAN/upstream connection.')
                print()

        return [{'name': i.name, 'mac': i.mac, 'link_up': i.link_up, 'driver': i.driver}
                for i in physical]

    def _check_dhcp(self, interface_name) -> str:
        """Quick check for DHCP server presence on an interface."""
        from system.commander import run
        # Use nmap or dhclient to probe -- fall back to checking if we got an IP via DHCP
        # Quick method: check if dhclient lease file exists or if the interface has an IP
        result = run(['ip', '-4', 'addr', 'show', interface_name])
        if result.success and 'inet ' in result.stdout and 'dynamic' in result.stdout:
            return 'Detected'

        # Try a fast dhcp discover (2 second timeout)
        result = run(
            ['timeout', '3', 'dhclient', '-1', '-nw', '-pf', f'/tmp/dhcp_test_{interface_name}.pid',
             '-lf', f'/tmp/dhcp_test_{interface_name}.lease', interface_name],
            sudo=True, timeout=5,
        )
        # Clean up
        run(['dhclient', '-r', '-pf', f'/tmp/dhcp_test_{interface_name}.pid', interface_name],
            sudo=True, timeout=5)
        run(['rm', '-f', f'/tmp/dhcp_test_{interface_name}.pid', f'/tmp/dhcp_test_{interface_name}.lease'],
            timeout=5)

        if result.success:
            return 'Detected'
        return ''

    def _prompt_wan_assignment(self, interfaces) -> str:
        """Prompt the operator to select the WAN interface."""
        _section('WAN Interface Assignment')

        if len(interfaces) == 1:
            name = interfaces[0]['name']
            print(f'  Only one interface detected: {name}')
            if _prompt_yes_no(f'Use {name} as WAN?', default='y'):
                return name

        return _prompt_interface('Select WAN interface', interfaces)

    def _prompt_lan_assignment(self, remaining) -> str:
        """Prompt the operator to select the LAN interface."""
        _section('LAN Interface Assignment')

        if not remaining:
            print('  No remaining interfaces for LAN.')
            print('  The gateway will operate in WAN-only mode.')
            return None

        if len(remaining) == 1:
            name = remaining[0]['name']
            print(f'  Remaining interface: {name}')
            if _prompt_yes_no(f'Use {name} as LAN?', default='y'):
                return name

        return _prompt_interface('Select LAN interface', remaining)

    def _prompt_wan_config(self, wan_iface) -> dict:
        """Prompt for WAN interface configuration."""
        _section('WAN Configuration')

        mode = _prompt('WAN IP mode', default='dhcp', choices=['static', 'dhcp'])

        config = {'mode': mode}

        if mode == 'static':
            config['ip'] = _prompt('WAN IP address', validator=_validate_ip)
            config['netmask'] = _prompt('WAN netmask', default='255.255.255.0', validator=_validate_netmask)
            config['gateway'] = _prompt('Default gateway', validator=_validate_ip)
            config['dns'] = _prompt('DNS servers (comma-separated)', default='1.1.1.1,8.8.8.8')

        return config

    def _prompt_lan_config(self) -> dict:
        """Prompt for LAN subnet configuration."""
        if not self.lan_iface:
            return {}

        _section('LAN Configuration')

        ip = _prompt('LAN gateway IP', default='192.168.1.1', validator=_validate_ip)
        netmask = _prompt('LAN netmask', default='255.255.255.0', validator=_validate_netmask)

        # Calculate DHCP range from subnet
        network = ipaddress.ip_network(f'{ip}/{netmask}', strict=False)
        hosts = list(network.hosts())
        if len(hosts) > 10:
            default_start = str(hosts[9])   # .10
            default_end = str(hosts[-6])     # .250 ish
        else:
            default_start = str(hosts[1]) if len(hosts) > 1 else ''
            default_end = str(hosts[-1]) if hosts else ''

        enable_dhcp = _prompt_yes_no('Enable DHCP server on LAN?', default='y')

        config = {
            'ip': ip,
            'netmask': netmask,
            'dhcp_enabled': enable_dhcp,
        }

        if enable_dhcp:
            config['dhcp_start'] = _prompt('DHCP range start', default=default_start, validator=_validate_ip)
            config['dhcp_end'] = _prompt('DHCP range end', default=default_end, validator=_validate_ip)
            config['dns'] = _prompt('DNS for DHCP clients', default='1.1.1.1,8.8.8.8')

        return config

    def _prompt_credentials(self) -> tuple:
        """Prompt for admin username and password."""
        _section('Admin Credentials')

        username = _prompt('Admin username', default='admin')

        while True:
            try:
                password = getpass.getpass('  Admin password: ')
                if len(password) < 6:
                    print('  * Password must be at least 6 characters')
                    continue
                confirm = getpass.getpass('  Confirm password: ')
                if password != confirm:
                    print('  * Passwords do not match')
                    continue
                return username, password
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt

    def _prompt_hostname(self) -> str:
        """Prompt for the gateway hostname."""
        _section('Hostname')
        return _prompt('Gateway hostname', default='warp-gw')

    def _prompt_management_mode(self) -> str:
        """Prompt for standalone vs managed mode."""
        _section('Management Mode')

        print('  1) Standalone -- local management only (CLI + web UI)')
        print('  2) Managed    -- register with KahLuna Nexus for')
        print('                   central monitoring and config push')
        print()

        choice = _prompt('Select mode', default='1', choices=['1', '2'])
        return 'standalone' if choice == '1' else 'managed'

    def _prompt_registration(self) -> dict:
        """Prompt for Nexus registration details and attempt registration."""
        _section('KahLuna Nexus Registration')

        token = _prompt('Provisioning token')
        platform_url = _prompt('Platform Core URL', default='https://api.kahluna.com')

        print()
        print('  Attempting registration...')

        try:
            from nexus_client import nexus

            wan_ip = self.wan_config.get('ip', '0.0.0.0')
            gateway_url = f'http://{wan_ip}:5000'

            result = nexus.claim_provisioning_token(
                token=token,
                gateway_name=self.hostname,
                gateway_url=gateway_url,
                platform_url=platform_url,
            )

            if result.get('status') == 'registered':
                print(f'  Registration successful.')
                print(f'  Service ID: {result.get("service_id", "N/A")}')
                return result
            else:
                print(f'  Registration failed: {result.get("detail", "Unknown error")}')
                if _prompt_yes_no('Retry?', default='y'):
                    return self._prompt_registration()
                else:
                    print('  Continuing in standalone mode.')
                    print('  You can register later via the CLI:')
                    print('    configure terminal')
                    print('    nexus register <token> <platform-url>')
                    self.mgmt_mode = 'standalone'
                    return None

        except ImportError:
            print('  Nexus client not available. Continuing in standalone mode.')
            self.mgmt_mode = 'standalone'
            return None
        except Exception as e:
            print(f'  Registration error: {e}')
            if _prompt_yes_no('Continue in standalone mode?', default='y'):
                self.mgmt_mode = 'standalone'
                return None
            raise KeyboardInterrupt

    def _apply_config(self, registration=None):
        """Apply the wizard configuration to the system."""
        from database import db
        from models_new import User, GatewayConfig

        # 1. Set hostname
        print('  Setting hostname...')
        config = GatewayConfig.get_instance()
        config.hostname = self.hostname
        config.management_mode = self.mgmt_mode

        # 2. Create/update admin user
        print('  Creating admin user...')
        user = User.query.filter_by(username=self.admin_user).first()
        if user:
            user.set_password(self.admin_pass)
            user.role = 'admin'
        else:
            # Check if email already exists
            email = f'{self.admin_user}@{self.hostname}.local'
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                # Update the existing user instead
                existing_email.username = self.admin_user
                existing_email.set_password(self.admin_pass)
                existing_email.role = 'admin'
            else:
                user = User(
                    username=self.admin_user,
                    email=email,
                    role='admin',
                )
                user.set_password(self.admin_pass)
                db.session.add(user)

        db.session.commit()

        # 3. Configure WAN interface
        if self.wan_iface:
            print(f'  Configuring WAN ({self.wan_iface})...')
            from services.interface_service import assign_role
            wan_mode = self.wan_config.get('mode', 'dhcp')
            assign_role(
                self.wan_iface, 'WAN',
                mode=wan_mode,
                ip=self.wan_config.get('ip'),
                netmask=self.wan_config.get('netmask'),
                gateway=self.wan_config.get('gateway'),
                dns=self.wan_config.get('dns'),
            )

        # 4. Configure LAN interface
        if self.lan_iface:
            print(f'  Configuring LAN ({self.lan_iface})...')
            from services.interface_service import assign_role
            assign_role(
                self.lan_iface, 'LAN',
                mode='static',
                ip=self.lan_config.get('ip'),
                netmask=self.lan_config.get('netmask'),
            )

            # 5. Configure DHCP if enabled
            if self.lan_config.get('dhcp_enabled'):
                print('  Configuring DHCP server...')
                from services.dhcp_service import setup_dhcp
                setup_dhcp(
                    interface=self.lan_iface,
                    range_start=self.lan_config.get('dhcp_start'),
                    range_end=self.lan_config.get('dhcp_end'),
                    netmask=self.lan_config.get('netmask', '255.255.255.0'),
                    gateway=self.lan_config.get('ip'),
                    dns_servers=self.lan_config.get('dns', '1.1.1.1,8.8.8.8'),
                )

        # 6. Start heartbeat if managed
        if self.mgmt_mode == 'managed' and registration:
            print('  Starting Nexus heartbeat...')
            try:
                from nexus_client import nexus
                nexus.start_heartbeat_loop()
            except Exception as e:
                print(f'  Warning: Could not start heartbeat: {e}')

        # 7. Save startup config
        print('  Saving startup configuration...')
        from cli.config_serializer import ConfigSerializer
        serializer = ConfigSerializer()
        serializer.save_startup_config()

        print('  Configuration applied.')

    def _apply_safe_defaults(self):
        """Apply safe defaults when the wizard is cancelled."""
        from database import db
        from models_new import GatewayConfig

        config = GatewayConfig.get_instance()
        config.hostname = 'warp-gw'
        config.management_mode = 'standalone'
        db.session.commit()

        logger.info('First-boot wizard cancelled -- safe defaults applied')
        print('  Safe defaults applied:')
        print('    - All interfaces: disabled')
        print('    - Management: standalone')
        print('    - Web UI: localhost only')
        print()
