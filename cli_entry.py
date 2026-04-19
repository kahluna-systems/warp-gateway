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
        ssh_client = os.environ.get('SSH_CLIENT', '')
        conn_type = 'ssh' if ssh_client else 'console'
        try:
            source_ip = ssh_client.split()[0] if ssh_client else 'console'
        except (IndexError, AttributeError):
            source_ip = 'unknown'

        # Check for first boot (no startup-config or empty database)
        from models_new import User, GatewayConfig
        serializer = ConfigSerializer()
        startup = serializer.load_startup_config()
        user_count = User.query.count()

        if startup is None or user_count == 0:
            # First boot -- run the wizard which creates the admin user
            print()
            from cli.first_boot import FirstBootWizard

            # Ensure GatewayConfig exists
            GatewayConfig.get_instance()

            wizard = FirstBootWizard(app)
            completed = wizard.run()

            if completed:
                # Wizard created an admin user -- look them up
                user = User.query.filter_by(role='admin').first()
                if not user:
                    print('% No admin user found after setup')
                    sys.exit(1)
            else:
                # Wizard cancelled -- try console login or create a default admin
                user = User.query.first()
                if not user:
                    # Create a minimal admin so the CLI is accessible
                    from database import db
                    user = User(username='admin', email='admin@warp-gw.local', role='admin')
                    user.set_password('admin')
                    db.session.add(user)
                    db.session.commit()
                    print('  Default admin created (username: admin, password: admin)')
                    print('  Change this immediately with: configure terminal -> hostname')
        else:
            # Normal boot -- authenticate
            if conn_type == 'console':
                user = _console_login(session_mgr)
                if not user:
                    sys.exit(1)
            else:
                # SSH: try to map OS user to DB user, fall back to login prompt
                os_user = os.environ.get('USER', '')
                user = User.query.filter_by(username=os_user).first()
                if not user:
                    # OS user doesn't match a DB user (e.g., 'warp' system user)
                    # Prompt for gateway credentials instead
                    user = _console_login(session_mgr)
                    if not user:
                        sys.exit(1)

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
