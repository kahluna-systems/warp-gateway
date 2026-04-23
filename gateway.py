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
    # Secret key: read from file if available, fall back to env var, then default
    secret_key = os.environ.get('SECRET_KEY', 'warp-gateway-dev-key-change-me')
    secret_key_file = os.environ.get('SECRET_KEY_FILE', '/etc/warp-gateway/secret.key')
    if os.path.isfile(secret_key_file):
        try:
            with open(secret_key_file) as f:
                secret_key = f.read().strip()
        except Exception:
            pass
    elif os.path.isdir('/etc/warp-gateway'):
        # Generate a secret key on first boot
        import secrets
        secret_key = secrets.token_hex(32)
        try:
            with open(secret_key_file, 'w') as f:
                f.write(secret_key)
            os.chmod(secret_key_file, 0o600)
        except Exception:
            pass
    app.config['SECRET_KEY'] = secret_key

    # Database: use a consistent absolute path so CLI and web UI share the same DB
    default_db = 'sqlite:////var/lib/warp-gateway/gateway.db'
    if not os.path.isdir('/var/lib/warp-gateway'):
        # Fall back to local path for development/testing
        app_dir = os.path.dirname(os.path.abspath(__file__))
        default_db = f'sqlite:///{os.path.join(app_dir, "warp_gateway.db")}'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', default_db)

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

        # 0. Initialize GatewayConfig singleton
        try:
            from models_new import GatewayConfig
            gw_config = GatewayConfig.get_instance()
            mgmt_mode = gw_config.management_mode or 'standalone'
            logger.info(f'  Management mode: {mgmt_mode}')
        except Exception as e:
            logger.error(f'  GatewayConfig init failed: {e}')
            mgmt_mode = 'standalone'

        # 1. Dependency check
        logger.info('[1/12] Running dependency check...')
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

        # 2. Apply switchport modes
        logger.info('[2/12] Applying switchport modes...')
        try:
            from services.vlan_service import sync_switchport_modes_on_boot
            sync_switchport_modes_on_boot()
        except Exception as e:
            logger.error(f'  Switchport mode sync failed: {e}')

        # 3. Create VLAN sub-interfaces
        logger.info('[3/12] Creating VLAN sub-interfaces...')
        try:
            from services.vlan_service import sync_vlans_on_boot
            sync_vlans_on_boot()
        except Exception as e:
            logger.error(f'  VLAN sync failed: {e}')

        # 4. Apply interface configs
        logger.info('[4/12] Applying interface configurations...')
        try:
            from services.interface_service import apply_saved_configs
            apply_saved_configs()
        except Exception as e:
            logger.error(f'  Interface config failed: {e}')

        # 5. Restore security zones
        logger.info('[5/12] Restoring security zones...')
        try:
            from services.zone_service import sync_zones_on_boot
            sync_zones_on_boot()
        except Exception as e:
            logger.error(f'  Zone sync failed: {e}')

        # 6. Start DHCP on LAN interfaces
        logger.info('[6/12] Starting DHCP on LAN interfaces...')
        try:
            from services.dhcp_service import start_dhcp_on_lan
            start_dhcp_on_lan()
        except Exception as e:
            logger.error(f'  DHCP startup failed: {e}')

        # 7. Sync DNS overrides
        logger.info('[7/12] Syncing DNS overrides...')
        try:
            from services.dns_service import sync_overrides
            sync_overrides()
        except Exception as e:
            logger.error(f'  DNS sync failed: {e}')

        # 8. Apply firewall rules + zone policies
        logger.info('[8/12] Applying firewall rules...')
        try:
            from services.firewall_service import apply_default_policy, sync_all_rules
            apply_default_policy()
            sync_all_rules()
        except Exception as e:
            logger.error(f'  Firewall setup failed: {e}')

        # 9. Enable IP forwarding + NAT
        logger.info('[9/12] Enabling IP forwarding and NAT...')
        try:
            from system.routing import enable_ip_forwarding
            from services.interface_service import setup_lan_nat
            enable_ip_forwarding()
            setup_lan_nat()
        except Exception as e:
            logger.error(f'  IP forwarding/NAT failed: {e}')

        # 10. Bring up WireGuard interfaces
        logger.info('[10/12] Bringing up WireGuard interfaces...')
        try:
            from services.network_service import bring_up_all
            bring_up_all()
        except Exception as e:
            logger.error(f'  WireGuard startup failed: {e}')

        # 11. Apply rate limits
        logger.info('[11/12] Applying rate limits...')
        try:
            from services.shaping_service import apply_all_limits
            apply_all_limits()
        except Exception as e:
            logger.error(f'  Rate limit setup failed: {e}')

        # 12. Nexus heartbeat -- management mode aware
        logger.info('[12/12] Nexus heartbeat check...')
        try:
            if mgmt_mode == 'standalone':
                logger.info('  Standalone mode — skipping Nexus heartbeat')
            elif mgmt_mode in ('managed', 'pre_provisioned'):
                from nexus_client import nexus
                if mgmt_mode == 'pre_provisioned' and not nexus.is_registered:
                    # Auto-register with exponential backoff
                    logger.info('  Pre-provisioned mode — attempting auto-registration...')
                    _attempt_pre_provision_registration(gw_config, nexus)
                elif nexus.is_registered:
                    nexus.start_heartbeat_loop()
                    logger.info('  Nexus heartbeat started (managed mode)')
                else:
                    logger.warning('  Managed mode but not registered — run "nexus register" from CLI')
        except Exception as e:
            logger.error(f'  Nexus heartbeat failed: {e}')

        logger.info('=== Startup sequence complete ===')


def _attempt_pre_provision_registration(gw_config, nexus):
    """
    Attempt auto-registration for pre-provisioned gateways.
    Uses exponential backoff: 30s, 60s, 120s, max 300s.
    Runs in a background thread so it doesn't block startup.
    """
    import threading
    import time

    token = gw_config.pre_provision_token
    if not token:
        logger.warning('  Pre-provisioned mode but no embedded token found')
        return

    def _register_loop():
        delay = 30
        max_delay = 300
        while True:
            try:
                result = nexus.claim_provisioning_token(
                    token=token,
                    gateway_name=gw_config.hostname or 'warp-gw',
                    gateway_url='http://0.0.0.0:5000',
                    platform_url=gw_config.pre_provision_url or 'https://api.kahluna.com',
                )
                if result.get('status') == 'registered':
                    logger.info(f'  Pre-provision registration successful: {result.get("service_id")}')
                    from database import db
                    gw_config.management_mode = 'managed'
                    db.session.commit()
                    nexus.start_heartbeat_loop()
                    return
                else:
                    logger.warning(f'  Pre-provision registration failed: {result.get("detail")}')
            except Exception as e:
                logger.warning(f'  Pre-provision registration error: {e}')

            logger.info(f'  Retrying in {delay}s...')
            time.sleep(delay)
            delay = min(delay * 2, max_delay)

    thread = threading.Thread(target=_register_loop, daemon=True, name='pre-provision')
    thread.start()


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = create_app()
    startup_sync(app)

    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    logger.info(f'Starting WARP Gateway on {host}:{port}')
    app.run(host=host, port=port, debug=debug)
