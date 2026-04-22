"""
Commit, rollback, and show system rollback handlers.
Implements Juniper JUNOS-style configuration management.
"""


def do_commit(shell, args):
    """
    commit [confirmed <minutes>]
    Commits the running config, creates a rollback snapshot.
    """
    from cli.config_serializer import ConfigSerializer

    serializer = ConfigSerializer()
    username = shell.user.username
    source_ip = shell.source_ip

    # Check if this is a confirming commit (cancels active timer)
    if serializer.confirmed_timer.active and (not args or args[0] != 'confirmed'):
        serializer.confirm()
        # Also do a normal commit
        success = serializer.commit(username, source_ip)
        if success:
            shell.formatter.print('Confirmed commit timer cancelled.')
            shell.formatter.print('Configuration committed (rollback-00)')
        else:
            shell.formatter.print('% Commit failed')
        return

    # Check for 'confirmed' keyword
    if args and args[0] == 'confirmed':
        if len(args) < 2 or not args[1].isdigit():
            shell.formatter.print('% Usage: commit confirmed <minutes>')
            shell.formatter.print('% Valid range: 1 to 60 minutes')
            return

        minutes = int(args[1])
        if minutes < 1 or minutes > 60:
            shell.formatter.print('% Invalid timer value. Valid range: 1 to 60 minutes.')
            return

        success = serializer.commit_confirmed(minutes, username, source_ip)
        if success:
            shell.formatter.print(f'Configuration committed with auto-rollback in {minutes} minutes.')
            shell.formatter.print(f'Run "commit" again within {minutes} minutes to confirm.')
        else:
            shell.formatter.print('% Commit failed')
        return

    # Normal commit
    success = serializer.commit(username, source_ip)
    if success:
        shell.formatter.print('Configuration committed (rollback-00)')
    else:
        shell.formatter.print('% Commit failed')


def do_rollback(shell, args):
    """
    rollback <N>
    Loads rollback version N and applies it as the running config.
    """
    if not args or not args[0].isdigit():
        shell.formatter.print('% Usage: rollback <0-49>')
        return

    version = int(args[0])
    if version < 0 or version > 49:
        shell.formatter.print('% Invalid rollback version. Valid range: 0 to 49.')
        return

    from cli.config_serializer import ConfigSerializer
    serializer = ConfigSerializer()

    if not serializer.rollback_store.exists(version):
        shell.formatter.print(f'% Rollback version {version} is not available.')
        return

    username = shell.user.username
    source_ip = shell.source_ip

    success = serializer.rollback(version, username, source_ip)
    if success:
        shell.formatter.print(f'Loaded rollback version {version}.')
        shell.formatter.print('Run "commit" to make this configuration permanent.')
    else:
        shell.formatter.print(f'% Failed to load rollback version {version}.')


def show_system_rollback(shell, args):
    """
    show system rollback
    Displays available rollback versions.
    """
    from cli.config_serializer import ConfigSerializer
    serializer = ConfigSerializer()

    versions = serializer.rollback_store.list_all()
    if not versions:
        shell.formatter.print('No rollback versions available.')
        return

    headers = ['Version', 'Timestamp', 'User', 'Size']
    rows = []
    for v in versions:
        rows.append([
            str(v['version']),
            v['timestamp'][:19] if len(v['timestamp']) > 19 else v['timestamp'],
            v['username'],
            f'{v["size"]} bytes',
        ])
    print(shell.formatter.table(headers, rows))
