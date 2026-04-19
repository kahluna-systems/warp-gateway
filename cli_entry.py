#!/usr/bin/env python3
"""
CLI entry point. Used as the login shell for the 'warp' system user.
Creates the Flask app, pushes the app context, authenticates, and starts the shell.
"""
import sys
import os


def main():
    # Set up paths
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from gateway import create_app
    app = create_app()

    with app.app_context():
        from cli.session import SessionManager
        from cli.shell import WarpShell
        from cli.config_serializer import ConfigSerializer

        session_mgr = SessionManager()

        # Determine connection type
        source_ip = os.environ.get('SSH_CLIENT', '').split()[0] if 'SSH_CLIENT' in os.environ else 'console'
        conn_type = 'ssh' if 'SSH_CLIENT' in os.environ else 'console'

        # For console (tty) access, prompt for credentials
        if conn_type == 'console':
            user = _console_login(session_mgr)
            if not user:
                sys.exit(1)
        else:
            # SSH: map OS user to DB user
            from models_new import User
            os_user = os.environ.get('USER', '')
            user = User.query.filter_by(username=os_user).first()
            if not user:
                print('% User not found in gateway database')
                sys.exit(1)

        # Check for first boot (no startup-config)
        serializer = ConfigSerializer()
        startup = serializer.load_startup_config()
        if startup is None:
            from cli.first_boot import FirstBootWizard
            wizard = FirstBootWizard(app)
            wizard.run()

        # Create session and start shell
        session_id = session_mgr.create_session(user, source_ip, conn_type)

        shell = WarpShell(
            app=app,
            user=user,
            source_ip=source_ip,
            connection_type=conn_type,
            session_mgr=session_mgr,
            session_id=session_id,
        )
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print('\n')
        finally:
            session_mgr.end_session(session_id)


def _console_login(session_mgr):
    """Prompt for username/password on the console."""
    import getpass
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            username = input('Username: ')
            password = getpass.getpass('Password: ')
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        user = session_mgr.authenticate(username, password)
        if user:
            return user
        print('% Login failed')
    print('% Too many failed attempts')
    return None


if __name__ == '__main__':
    main()
