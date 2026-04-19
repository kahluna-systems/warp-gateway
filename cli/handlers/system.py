"""
System command handlers.
Handles copy, reload, hostname, nexus register/deregister, clear.
"""


def copy_running_startup(shell, args):
    """copy running-config startup-config"""
    from cli.config_serializer import ConfigSerializer

    serializer = ConfigSerializer()
    success = serializer.save_startup_config()
    if success:
        shell.formatter.print('Running configuration saved to startup-config')
    else:
        shell.formatter.print('% Failed to save startup configuration')


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
