"""
Shared fixtures for CLI tests.
Provides a Flask app with in-memory SQLite for isolated testing.
"""
import os
import sys
import pytest

# Ensure the warp-gateway root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


@pytest.fixture
def app():
    """Create a Flask app with an in-memory SQLite database."""
    from gateway import create_app
    os.environ['DATABASE_URL'] = 'sqlite://'  # In-memory
    os.environ['SECRET_KEY'] = 'test-secret-key'

    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    with app.app_context():
        from database import db
        db.create_all()

        # Create a default admin user
        from models_new import User, GatewayConfig
        admin = User(username='admin', email='admin@test.local', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)

        # Create default gateway config
        config = GatewayConfig(id=1, hostname='test-gw', management_mode='standalone')
        config.set_enable_password('enable123')
        db.session.add(config)

        db.session.commit()

        yield app


@pytest.fixture
def admin_user(app):
    """Return the admin user."""
    with app.app_context():
        from models_new import User
        return User.query.filter_by(username='admin').first()


@pytest.fixture
def shell(app, admin_user):
    """Create a WarpShell instance for testing."""
    with app.app_context():
        from cli.shell import WarpShell
        s = WarpShell(
            app=app,
            user=admin_user,
            source_ip='127.0.0.1',
            connection_type='console',
        )
        yield s
