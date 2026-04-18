"""
WARP Gateway — Main Application Entry Point
Network appliance: router, firewall, VPN gateway, DHCP server, diagnostic tool.
"""
import os
import logging
from flask import Flask, redirect, url_for
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from database import db
from models_new import User

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('warp.gateway')


def create_app():
    """Flask application factory."""
    app = Flask(__name__, template_folder='templates')

    # ── Configuration ────────────────────────────────────────────────────
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'warp-gateway-dev-key-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///warp_gateway.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600

    # ── Extensions ───────────────────────────────────────────────────────
    db.init_app(app)
    csrf = CSRFProtect(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Exempt API routes from CSRF ──────────────────────────────────────
    @app.before_request
    def csrf_exempt_api():
        from flask import request
        if request.path.startswith('/api/') or request.path == '/health':
            csrf._exempt_views.add(request.endpoint)

    # ── Register Blueprints ──────────────────────────────────────────────
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.interfaces_routes import interfaces_bp
    from routes.networks import networks_bp
    from routes.endpoints import endpoints_bp
    from routes.firewall_routes import firewall_bp
    from routes.dhcp_routes import dhcp_bp
    from routes.dns_routes import dns_bp
    from routes.clients import clients_bp
    from routes.diagnostics_routes import diagnostics_bp
    from routes.system_routes import system_bp
    from routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(interfaces_bp)
    app.register_blueprint(networks_bp)
    app.register_blueprint(endpoints_bp)
    app.register_blueprint(firewall_bp)
    app.register_blueprint(dhcp_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(system_bp)
    app.register_blueprint(api_bp)

    # ── Root redirect ────────────────────────────────────────────────────
    @app.route('/index')
    def index_redirect():
        return redirect(url_for('dashboard.index'))

    # ── Create tables ────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    return app


def startup_sync(app):
    """
    Run the full startup sequence inside the app context.
    Called once when the gateway starts.
    """
    with app.app_context():
        logger.info('=== WARP Gateway Startup Sequence ===')

        # 1. Dependency check
        logger.info('[1/9] Running dependency check...')
        try:
            from system.checker import refresh_health
            health = refresh_health()
            if health.ready:
                logger.info('  All required dependencies installed')
            else:
                missing = ', '.join(health.to_dict().get('missing_required', []))
                logger.warning(f'  Missing required dependencies: {missing}')
        except Exception as e:
            logger.error(f'  Dependency check failed: {e}')

        # 2. Apply interface configs
        logger.info('[2/9] Applying interface configurations...')
        try:
            from services.interface_service import apply_saved_configs
            apply_saved_configs()
        except Exception as e:
            logger.error(f'  Interface config failed: {e}')

        # 3. Start DHCP on LAN interfaces
        logger.info('[3/9] Starting DHCP on LAN interfaces...')
        try:
            from services.dhcp_service import start_dhcp_on_lan
            start_dhcp_on_lan()
        except Exception as e:
            logger.error(f'  DHCP startup failed: {e}')

        # 4. Sync DNS overrides
        logger.info('[4/9] Syncing DNS overrides...')
        try:
            from services.dns_service import sync_overrides
            sync_overrides()
        except Exception as e:
            logger.error(f'  DNS sync failed: {e}')

        # 5. Apply firewall rules
        logger.info('[5/9] Applying firewall rules...')
        try:
            from services.firewall_service import apply_default_policy, sync_all_rules
            apply_default_policy()
            sync_all_rules()
        except Exception as e:
            logger.error(f'  Firewall setup failed: {e}')

        # 6. Enable IP forwarding + NAT
        logger.info('[6/9] Enabling IP forwarding and NAT...')
        try:
            from system.routing import enable_ip_forwarding
            from services.interface_service import setup_lan_nat
            enable_ip_forwarding()
            setup_lan_nat()
        except Exception as e:
            logger.error(f'  IP forwarding/NAT failed: {e}')

        # 7. Bring up WireGuard interfaces
        logger.info('[7/9] Bringing up WireGuard interfaces...')
        try:
            from services.network_service import bring_up_all
            bring_up_all()
        except Exception as e:
            logger.error(f'  WireGuard startup failed: {e}')

        # 8. Apply rate limits
        logger.info('[8/9] Applying rate limits...')
        try:
            from services.shaping_service import apply_all_limits
            apply_all_limits()
        except Exception as e:
            logger.error(f'  Rate limit setup failed: {e}')

        # 9. Start Nexus heartbeat
        logger.info('[9/9] Starting Nexus heartbeat...')
        try:
            from nexus_client import nexus
            if nexus.is_registered:
                nexus.start_heartbeat_loop()
                logger.info('  Nexus heartbeat started')
            else:
                logger.info('  Gateway not registered with Nexus — skipping heartbeat')
        except Exception as e:
            logger.error(f'  Nexus heartbeat failed: {e}')

        logger.info('=== Startup sequence complete ===')


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = create_app()
    startup_sync(app)

    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    logger.info(f'Starting WARP Gateway on {host}:{port}')
    app.run(host=host, port=port, debug=debug)
