"""
REST API for Mission Control — /health, /api/status, /api/networks, /api/endpoints, /api/system/deps.
"""
from flask import Blueprint, jsonify
from services import health_service, network_service, endpoint_service, client_service
from models_new import VPNNetwork, Endpoint

api_bp = Blueprint('api', __name__)


@api_bp.route('/health')
def health():
    """Simple health check endpoint."""
    system = health_service.get_system_health()
    return jsonify({
        'status': 'online',
        'hostname': system.get('hostname', ''),
        'uptime': system.get('uptime_human', ''),
        'cpu_percent': system.get('cpu_percent', 0),
        'memory_percent': system.get('memory', {}).get('percent', 0),
    })


@api_bp.route('/api/status')
def status():
    """Full gateway status for Mission Control."""
    client_counts = client_service.get_client_counts()
    networks = VPNNetwork.query.filter_by(is_active=True).all()
    system = health_service.get_system_health()

    return jsonify({
        'status': 'online',
        'hostname': system.get('hostname', ''),
        'uptime': system.get('uptime_human', ''),
        'networks': {
            'total': VPNNetwork.query.count(),
            'active': len(networks),
        },
        'endpoints': {
            'total': Endpoint.query.count(),
            'active': Endpoint.query.filter_by(is_active=True).count(),
        },
        'clients': client_counts,
        'system': {
            'cpu_percent': system.get('cpu_percent', 0),
            'memory_percent': system.get('memory', {}).get('percent', 0),
            'disk_percent': system.get('disk', {}).get('percent', 0),
        },
    })


@api_bp.route('/api/networks')
def api_networks():
    """List all VPN networks."""
    networks = network_service.list_networks()
    return jsonify({
        'networks': [n.to_dict() for n in networks],
    })


@api_bp.route('/api/networks/<int:network_id>')
def api_network_detail(network_id):
    """Get a single network with WireGuard status."""
    status = network_service.get_network_status(network_id)
    if not status:
        return jsonify({'error': 'Network not found'}), 404
    return jsonify(status)


@api_bp.route('/api/endpoints')
def api_endpoints():
    """List all endpoints."""
    endpoints = endpoint_service.list_endpoints()
    return jsonify({
        'endpoints': [e.to_dict() for e in endpoints],
    })


@api_bp.route('/api/endpoints/<int:endpoint_id>')
def api_endpoint_detail(endpoint_id):
    """Get a single endpoint with WireGuard peer status."""
    status = endpoint_service.get_endpoint_status(endpoint_id)
    if not status:
        return jsonify({'error': 'Endpoint not found'}), 404
    return jsonify(status)


@api_bp.route('/api/system/deps')
def api_deps():
    """Get system dependency status."""
    deps = health_service.get_dependency_status()
    return jsonify(deps)


@api_bp.route('/api/system/health')
def api_health():
    """Get full system health report."""
    return jsonify(health_service.get_full_health())


@api_bp.route('/api/clients')
def api_clients():
    """Get all connected clients."""
    clients = client_service.get_all_clients()
    return jsonify({'clients': clients})
