"""
Integration tests for CLI workflows.
Tests end-to-end command execution through the shell.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


@pytest.fixture
def app():
    """Create a Flask app with an in-memory SQLite database."""
    from gateway import create_app
    os.environ['DATABASE_URL'] = 'sqlite://'
    os.environ['SECRET_KEY'] = 'test-secret-key'

    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    with app.app_context():
        from database import db
        db.create_all()

        from models_new import User, GatewayConfig
        admin = User(username='admin', email='admin@test.local', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)

        config = GatewayConfig(id=1, hostname='test-gw', management_mode='standalone')
        config.set_enable_password('enable123')
        db.session.add(config)

        db.session.commit()
        yield app


@pytest.fixture
def shell(app):
    """Create a WarpShell instance for integration testing."""
    with app.app_context():
        from models_new import User
        from cli.shell import WarpShell
        admin = User.query.filter_by(username='admin').first()
        s = WarpShell(
            app=app,
            user=admin,
            source_ip='127.0.0.1',
            connection_type='console',
        )
        yield s


class TestConfigWorkflow:
    """Test a full configuration workflow through the CLI."""

    def test_hostname_change(self, shell, app):
        """Changing hostname updates the database and prompt."""
        with app.app_context():
            from cli.modes import PRIVILEGED, CONFIGURE
            shell.mode_stack.push(PRIVILEGED)
            shell.mode_stack.push(CONFIGURE)

            from cli.handlers.system import set_hostname
            set_hostname(shell, ['my-gateway'])

            assert shell._hostname == 'my-gateway'
            assert 'my-gateway' in shell.prompt

            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            assert config.hostname == 'my-gateway'

    def test_show_version_output(self, shell, app, capsys):
        """show version produces expected output."""
        with app.app_context():
            from cli.handlers.show import show_version
            show_version(shell, [])
            captured = capsys.readouterr()
            assert 'KahLuna WARP Gateway' in captured.out
            assert 'test-gw' in captured.out

    def test_show_nexus_standalone(self, shell, app, capsys):
        """show nexus status in standalone mode shows correct message."""
        with app.app_context():
            from cli.handlers.show import show_nexus_status
            show_nexus_status(shell, [])
            captured = capsys.readouterr()
            assert 'standalone' in captured.out
            assert 'nexus register' in captured.out

    def test_show_running_config(self, shell, app, capsys):
        """show running-config produces parseable output."""
        with app.app_context():
            from cli.handlers.show import show_running_config
            show_running_config(shell, [])
            captured = capsys.readouterr()
            assert 'WARP Gateway Configuration' in captured.out
            assert 'hostname test-gw' in captured.out
            assert 'end' in captured.out


class TestConfigSerializer:
    """Test running-config / startup-config serialization."""

    def test_serialize_contains_hostname(self, app):
        """Running config contains the hostname."""
        with app.app_context():
            from cli.config_serializer import ConfigSerializer
            serializer = ConfigSerializer()
            config = serializer.serialize_running_config()
            assert 'hostname test-gw' in config

    def test_serialize_contains_management_mode(self, app):
        """Running config contains the management mode."""
        with app.app_context():
            from cli.config_serializer import ConfigSerializer
            serializer = ConfigSerializer()
            config = serializer.serialize_running_config()
            assert 'nexus standalone' in config

    def test_save_and_load_startup_config(self, app, tmp_path):
        """Saving and loading startup-config round-trips correctly."""
        with app.app_context():
            from cli.config_serializer import ConfigSerializer
            serializer = ConfigSerializer(app_dir=str(tmp_path))

            # Save
            success = serializer.save_startup_config()
            assert success

            # Load
            loaded = serializer.load_startup_config()
            assert loaded is not None
            assert 'hostname test-gw' in loaded
            assert 'end' in loaded

    def test_parse_config_text(self, app):
        """Parsing config text produces command list."""
        with app.app_context():
            from cli.config_serializer import ConfigSerializer
            serializer = ConfigSerializer()

            text = """!
! WARP Gateway Configuration
!
hostname my-gw
!
interface ens3
  role WAN
  ip address dhcp
!
nexus standalone
!
end"""
            commands = serializer.parse_config_text(text)
            assert 'hostname my-gw' in commands
            assert 'interface ens3' in commands
            assert 'role WAN' in commands
            assert 'ip address dhcp' in commands
            assert 'nexus standalone' in commands


class TestSessionManager:
    """Test CLI session management."""

    def test_authenticate_valid(self, app):
        """Valid credentials return a user."""
        with app.app_context():
            from cli.session import SessionManager
            mgr = SessionManager()
            user = mgr.authenticate('admin', 'admin123')
            assert user is not None
            assert user.username == 'admin'

    def test_authenticate_invalid(self, app):
        """Invalid credentials return None."""
        with app.app_context():
            from cli.session import SessionManager
            mgr = SessionManager()
            user = mgr.authenticate('admin', 'wrongpassword')
            assert user is None

    def test_authenticate_unknown_user(self, app):
        """Unknown username returns None."""
        with app.app_context():
            from cli.session import SessionManager
            mgr = SessionManager()
            user = mgr.authenticate('nobody', 'password')
            assert user is None

    def test_session_lifecycle(self, app):
        """Create and end a session, verify audit log entries."""
        with app.app_context():
            from cli.session import SessionManager
            from models_new import User, AuditLog

            mgr = SessionManager()
            user = User.query.filter_by(username='admin').first()

            # Create session
            sid = mgr.create_session(user, '10.0.0.1', 'ssh')
            assert sid is not None
            assert mgr.active_count == 1

            # Verify audit log
            logs = AuditLog.query.filter_by(action='cli_session_start').all()
            assert len(logs) >= 1
            assert '10.0.0.1' in logs[-1].details

            # End session
            mgr.end_session(sid)
            assert mgr.active_count == 0

            end_logs = AuditLog.query.filter_by(action='cli_session_end').all()
            assert len(end_logs) >= 1

    def test_idle_timeout(self, app):
        """Session exceeding idle timeout is detected."""
        with app.app_context():
            from cli.session import SessionManager
            from models_new import User
            import time

            mgr = SessionManager(idle_timeout=1)  # 1 second for testing
            user = User.query.filter_by(username='admin').first()
            sid = mgr.create_session(user, '127.0.0.1', 'console')

            # Not idle yet
            assert not mgr.check_idle(sid)

            # Wait for timeout
            time.sleep(1.5)
            assert mgr.check_idle(sid)

    def test_concurrent_configure_warning(self, app):
        """Multiple sessions in configure mode are detected."""
        with app.app_context():
            from cli.session import SessionManager
            from models_new import User

            mgr = SessionManager()
            user = User.query.filter_by(username='admin').first()

            sid1 = mgr.create_session(user, '10.0.0.1', 'ssh')
            sid2 = mgr.create_session(user, '10.0.0.2', 'ssh')

            mgr.update_mode(sid1, 'configure')
            mgr.update_mode(sid2, 'configure')

            config_sessions = mgr.get_configure_sessions()
            assert len(config_sessions) == 2

    def test_account_lockout(self, app):
        """Account locks after repeated failed attempts."""
        with app.app_context():
            from cli.session import SessionManager
            from models_new import User

            mgr = SessionManager()

            # Fail 5 times (the User model locks at 5)
            for _ in range(5):
                mgr.authenticate('admin', 'wrong')

            # Should be locked now
            user = User.query.filter_by(username='admin').first()
            assert user.is_account_locked()

            # Even correct password should fail
            result = mgr.authenticate('admin', 'admin123')
            assert result is None


class TestFirstBootWizard:
    """Test first-boot wizard components (non-interactive)."""

    def test_safe_defaults(self, app):
        """Cancelled wizard applies safe defaults."""
        with app.app_context():
            from cli.first_boot import FirstBootWizard
            from models_new import GatewayConfig

            wizard = FirstBootWizard(app)
            wizard._apply_safe_defaults()

            config = GatewayConfig.get_instance()
            assert config.management_mode == 'standalone'
            assert config.hostname == 'warp-gw'


class TestGatewayConfig:
    """Test the GatewayConfig singleton model."""

    def test_singleton_creation(self, app):
        """GatewayConfig.get_instance() creates if not exists."""
        with app.app_context():
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            assert config is not None
            assert config.id == 1

    def test_singleton_returns_same(self, app):
        """Multiple calls return the same instance."""
        with app.app_context():
            from models_new import GatewayConfig
            c1 = GatewayConfig.get_instance()
            c2 = GatewayConfig.get_instance()
            assert c1.id == c2.id

    def test_enable_password(self, app):
        """Enable password set and check works."""
        with app.app_context():
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            config.set_enable_password('secret123')
            assert config.check_enable_password('secret123')
            assert not config.check_enable_password('wrong')

    def test_management_mode_persists(self, app):
        """Management mode change persists to database."""
        with app.app_context():
            from models_new import GatewayConfig
            from database import db

            config = GatewayConfig.get_instance()
            config.management_mode = 'managed'
            db.session.commit()

            # Re-fetch
            config2 = GatewayConfig.query.get(1)
            assert config2.management_mode == 'managed'

    def test_to_dict(self, app):
        """to_dict returns expected keys."""
        with app.app_context():
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            d = config.to_dict()
            assert 'hostname' in d
            assert 'management_mode' in d
            assert 'software_version' in d
            assert 'has_enable_password' in d
