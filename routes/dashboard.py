"""
Main dashboard — interface status, connected clients, recent events, system health.
"""
from flask import Blueprint, render_template
from flask_login import login_required
from services import interface_service, client_service, health_service
from models_new import VPNNetwork, AuditLog, GatewayConfig

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    # Interface overview
    interfaces = interface_service.get_all_interfaces()
    wan = next((i for i in interfaces if i['role'] == 'WAN'), None)
    lan = next((i for i in interfaces if i['role'] == 'LAN'), None)

    # VPN networks summary
    networks = VPNNetwork.query.filter_by(is_active=True).all()

    # Client counts
    client_counts = client_service.get_client_counts()

    # Connected clients (limited for dashboard)
    clients = client_service.get_all_clients()[:20]

    # Recent events
    events = AuditLog.recent(limit=10)

    # System health
    system_health = health_service.get_system_health()

    # Gateway config (management mode)
    gateway_config = GatewayConfig.get_instance()

    return render_template('new/dashboard.html',
                           wan=wan,
                           lan=lan,
                           networks=networks,
                           client_counts=client_counts,
                           clients=clients,
                           events=events,
                           system_health=system_health,
                           gateway_config=gateway_config)
