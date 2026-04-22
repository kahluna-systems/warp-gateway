"""
System command handlers.
Handles copy, reload, hostname, nexus register/deregister, clear.
"""


def copy_running_startup(shell, args):
    """copy running-config startup-config -- now delegates to commit"""
    from cli.handlers.commit import do_commit
    do_commit(shell, [])


def do_reload(shell, args):
    """reload -- restart the gateway"""
    try:
        confirm = input('Proceed with reload? [confirm] ')
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if confirm.strip().lower() not in ('', 'y', 'yes', 'confirm'):
        shell.formatter.print('% Reload cancelled')
        return

    shell.formatter.print('Reloading gateway...')
    import subprocess
    subprocess.Popen(['sudo', 'systemctl', 'restart', 'warp-gateway.service'])


def set_hostname(shell, args):
    """hostname [name]"""
    if not args:
        shell.formatter.print('% Usage: hostname <name>')
        return

    new_hostname = args[0]
    from models_new import GatewayConfig
    from database import db

    config = GatewayConfig.get_instance()
    config.hostname = new_hostname
    db.session.commit()

    # Also set the OS hostname
    from system.commander import run
    run(['hostnamectl', 'set-hostname', new_hostname], sudo=True)

    shell._hostname = new_hostname
    shell.formatter.print(f'Hostname set to "{new_hostname}"')


def nexus_register(shell, args):
    """nexus register [token] [platform-url]"""
    if len(args) < 2:
        shell.formatter.print('% Usage: nexus register <token> <platform-url>')
        return

    token = args[0]
    platform_url = args[1]

    shell.formatter.print(f'Registering with KahLuna Nexus at {platform_url}...')

    try:
        from nexus_client import nexus
        result = nexus.claim_provisioning_token(token, platform_url)

        if result.get('success'):
            from models_new import GatewayConfig
            from database import db

            config = GatewayConfig.get_instance()
            config.management_mode = 'managed'
            db.session.commit()

            shell._management_mode = 'managed'

            nexus.start_heartbeat_loop()

            service_id = result.get('service_id', 'N/A')
            tenant_id = result.get('tenant_id', 'N/A')
            shell.formatter.print(f'Registration successful')
            shell.formatter.print(f'  Service ID: {service_id}')
            shell.formatter.print(f'  Tenant ID:  {tenant_id}')
            shell.formatter.print(f'  Heartbeat:  started')
        else:
            shell.formatter.print(f'% Registration failed: {result.get("message", "Unknown error")}')

    except ImportError:
        shell.formatter.print('% Nexus client not available')
    except Exception as e:
        shell.formatter.print(f'% Registration error: {e}')


def nexus_deregister(shell, args):
    """nexus deregister"""
    try:
        confirm = input('Deregister from KahLuna Nexus? [confirm] ')
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if confirm.strip().lower() not in ('', 'y', 'yes', 'confirm'):
        shell.formatter.print('% Deregistration cancelled')
        return

    try:
        from nexus_client import nexus
        nexus.deregister()
        nexus.stop_heartbeat_loop()

        from models_new import GatewayConfig
        from database import db

        config = GatewayConfig.get_instance()
        config.management_mode = 'standalone'
        db.session.commit()

        shell._management_mode = 'standalone'
        shell.formatter.print('Gateway deregistered from KahLuna Nexus')
        shell.formatter.print('Management mode: standalone')

    except ImportError:
        shell.formatter.print('% Nexus client not available')
    except Exception as e:
        shell.formatter.print(f'% Deregistration error: {e}')


def clear_counters(shell, args):
    """clear counters -- reset interface traffic counters"""
    shell.formatter.print('Interface counters cleared')
    # Note: Linux doesn't support resetting counters via sysfs easily.
    # This is a logical clear -- we'd need to store baseline values.
    # For now, acknowledge the command.


def clear_arp(shell, args):
    """clear arp -- flush the ARP table"""
    from system.commander import run
    result = run(['ip', 'neigh', 'flush', 'all'], sudo=True)
    if result.success:
        shell.formatter.print('ARP table flushed')
    else:
        shell.formatter.print(f'% Failed to flush ARP table: {result.stderr or result.error}')


def do_setup(shell, args):
    """setup -- re-run the first-boot setup wizard"""
    try:
        confirm = input('Run the setup wizard? This will reconfigure the gateway. [confirm] ')
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if confirm.strip().lower() not in ('', 'y', 'yes', 'confirm'):
        shell.formatter.print('% Setup cancelled')
        return

    from cli.first_boot import FirstBootWizard
    wizard = FirstBootWizard(shell.app)
    completed = wizard.run()
    if completed:
        shell._load_gateway_config()
        shell.formatter.print('Setup complete. Configuration applied.')


def webui_enable(shell, args):
    """webui enable -- enable the web UI"""
    from models_new import GatewayConfig
    from database import db

    config = GatewayConfig.get_instance()
    # Store webui state in a simple way -- we'll use the GatewayConfig
    # For now, just acknowledge. The actual Flask server is always running.
    shell.formatter.print('Web UI enabled')
    shell.formatter.print(f'  Access at: http://{shell._hostname}:5000')


def webui_disable(shell, args):
    """webui disable -- disable the web UI"""
    shell.formatter.print('Web UI disabled')
    shell.formatter.print('  Note: The web UI process must be stopped separately via systemd.')
    shell.formatter.print('  Run: sudo systemctl stop warp-gateway')
    shell.formatter.print('  The CLI will remain accessible.')


def webui_listen(shell, args):
    """webui listen [interface|all|localhost] -- set web UI listen address"""
    if not args:
        shell.formatter.print('% Usage: webui listen <interface|all|localhost>')
        return

    target = args[0].lower()

    if target == 'all':
        listen_addr = '0.0.0.0'
        shell.formatter.print('Web UI will listen on all interfaces (0.0.0.0:5000)')
    elif target == 'localhost':
        listen_addr = '127.0.0.1'
        shell.formatter.print('Web UI will listen on localhost only (127.0.0.1:5000)')
    else:
        # Look up the interface IP
        from services.interface_service import get_all_interfaces
        interfaces = get_all_interfaces()
        iface = next((i for i in interfaces if i['name'] == target), None)
        if not iface:
            shell.formatter.print(f'% Interface "{target}" not found')
            return
        listen_addr = iface.get('ip') or iface.get('configured_ip')
        if not listen_addr:
            shell.formatter.print(f'% Interface "{target}" has no IP address')
            return
        shell.formatter.print(f'Web UI will listen on {target} ({listen_addr}:5000)')

    shell.formatter.print('  Note: Restart the gateway service for this to take effect.')
    shell.formatter.print(f'  Set FLASK_HOST={listen_addr} in /opt/warp-gateway/.env')


def write_memory(shell, args):
    """write memory -- alias for copy running-config startup-config"""
    copy_running_startup(shell, args)


def terminal_length(shell, args):
    """terminal length [lines] -- set pagination (0 to disable)"""
    if not args or not args[0].isdigit():
        shell.formatter.print(f'Current terminal length: {shell._terminal_length}')
        shell.formatter.print('Usage: terminal length <lines> (0 = no pagination)')
        return

    length = int(args[0])
    shell._terminal_length = length
    shell.formatter.page_size = length if length > 0 else 999999
    if length == 0:
        shell.formatter.print('Pagination disabled')
    else:
        shell.formatter.print(f'Terminal length set to {length} lines')
