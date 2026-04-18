"""
VPN Network management routes — create, delete, suspend, resume, status.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required
from services import network_service, endpoint_service
from models_new import NETWORK_TYPES

networks_bp = Blueprint('networks', __name__, url_prefix='/networks')


@networks_bp.route('/')
@login_required
def index():
    networks = network_service.list_networks()
    return render_template('new/networks.html', networks=networks, network_types=NETWORK_TYPES)


@networks_bp.route('/create', methods=['POST'])
@login_required
def create():
    name = request.form.get('name', '').strip()
    network_type = request.form.get('network_type', 'secure_internet')
    subnet = request.form.get('subnet', '').strip()
    port = request.form.get('port', '51820')
    rate_limit = request.form.get('rate_limit_enabled') == 'on'
    dl = request.form.get('rate_limit_download_mbps', type=float)
    ul = request.form.get('rate_limit_upload_mbps', type=float)

    if not name or not subnet:
        flash('Name and subnet are required.', 'error')
        return redirect(url_for('networks.index'))

    try:
        port = int(port)
    except ValueError:
        flash('Invalid port number.', 'error')
        return redirect(url_for('networks.index'))

    result = network_service.create_network(
        name=name,
        network_type=network_type,
        subnet=subnet,
        port=port,
        rate_limit_enabled=rate_limit,
        rate_limit_download_mbps=dl,
        rate_limit_upload_mbps=ul,
    )

    if result['success']:
        flash(f'Network "{name}" created successfully.', 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('networks.index'))


@networks_bp.route('/<int:network_id>')
@login_required
def detail(network_id):
    status = network_service.get_network_status(network_id)
    if not status:
        flash('Network not found.', 'error')
        return redirect(url_for('networks.index'))

    network = network_service.get_network(network_id)
    endpoints = endpoint_service.list_endpoints(network_id)
    return render_template('new/network_detail.html',
                           network=network,
                           endpoints=endpoints,
                           wg_status=status['wireguard'],
                           network_types=NETWORK_TYPES)


@networks_bp.route('/<int:network_id>/delete', methods=['POST'])
@login_required
def delete(network_id):
    result = network_service.delete_network(network_id)
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')
    return redirect(url_for('networks.index'))


@networks_bp.route('/<int:network_id>/suspend', methods=['POST'])
@login_required
def suspend(network_id):
    result = network_service.suspend_network(network_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('networks.detail', network_id=network_id))


@networks_bp.route('/<int:network_id>/resume', methods=['POST'])
@login_required
def resume(network_id):
    result = network_service.resume_network(network_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('networks.detail', network_id=network_id))
