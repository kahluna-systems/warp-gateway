"""
VPN Endpoint (peer) management routes — add, remove, QR code, config download.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file, Response
from flask_login import login_required
from services import endpoint_service, network_service

endpoints_bp = Blueprint('endpoints', __name__, url_prefix='/endpoints')


@endpoints_bp.route('/')
@login_required
def index():
    network_id = request.args.get('network_id', type=int)
    endpoints = endpoint_service.list_endpoints(network_id)
    networks = network_service.list_networks()
    return render_template('new/endpoints.html', endpoints=endpoints, networks=networks,
                           selected_network_id=network_id)


@endpoints_bp.route('/add', methods=['POST'])
@login_required
def add():
    network_id = request.form.get('network_id', type=int)
    name = request.form.get('name', '').strip()
    endpoint_type = request.form.get('endpoint_type', 'mobile')
    use_psk = request.form.get('use_psk') != 'off'
    rate_limit = request.form.get('rate_limit_enabled') == 'on'
    dl = request.form.get('rate_limit_download_mbps', type=float)
    ul = request.form.get('rate_limit_upload_mbps', type=float)

    if not network_id or not name:
        flash('Network and name are required.', 'error')
        return redirect(url_for('endpoints.index'))

    result = endpoint_service.add_endpoint(
        network_id=network_id,
        name=name,
        endpoint_type=endpoint_type,
        use_psk=use_psk,
        rate_limit_enabled=rate_limit,
        rate_limit_download_mbps=dl,
        rate_limit_upload_mbps=ul,
    )

    if result['success']:
        ep = result['endpoint']
        flash(f'Endpoint "{name}" added successfully.', 'success')
        return redirect(url_for('endpoints.config', endpoint_id=ep.id))
    else:
        flash(result['message'], 'error')
        return redirect(url_for('endpoints.index', network_id=network_id))


@endpoints_bp.route('/<int:endpoint_id>/config')
@login_required
def config(endpoint_id):
    endpoint = endpoint_service.get_endpoint(endpoint_id)
    if not endpoint:
        flash('Endpoint not found.', 'error')
        return redirect(url_for('endpoints.index'))

    client_config = endpoint_service.generate_client_config(endpoint_id)
    return render_template('new/endpoint_config.html', endpoint=endpoint, client_config=client_config)


@endpoints_bp.route('/<int:endpoint_id>/download')
@login_required
def download(endpoint_id):
    endpoint = endpoint_service.get_endpoint(endpoint_id)
    if not endpoint:
        flash('Endpoint not found.', 'error')
        return redirect(url_for('endpoints.index'))

    config = endpoint_service.generate_client_config(endpoint_id)
    if not config:
        flash('Failed to generate config.', 'error')
        return redirect(url_for('endpoints.config', endpoint_id=endpoint_id))

    return Response(
        config,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={endpoint.name}.conf'}
    )


@endpoints_bp.route('/<int:endpoint_id>/qr')
@login_required
def qr_code(endpoint_id):
    buf = endpoint_service.generate_qr_code(endpoint_id)
    if not buf:
        flash('Failed to generate QR code.', 'error')
        return redirect(url_for('endpoints.config', endpoint_id=endpoint_id))

    return send_file(buf, mimetype='image/png', download_name='qr.png')


@endpoints_bp.route('/<int:endpoint_id>/remove', methods=['POST'])
@login_required
def remove(endpoint_id):
    ep = endpoint_service.get_endpoint(endpoint_id)
    network_id = ep.vpn_network_id if ep else None

    result = endpoint_service.remove_endpoint(endpoint_id)
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('endpoints.index', network_id=network_id))


@endpoints_bp.route('/<int:endpoint_id>/suspend', methods=['POST'])
@login_required
def suspend(endpoint_id):
    result = endpoint_service.suspend_endpoint(endpoint_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('endpoints.index'))


@endpoints_bp.route('/<int:endpoint_id>/resume', methods=['POST'])
@login_required
def resume(endpoint_id):
    result = endpoint_service.resume_endpoint(endpoint_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('endpoints.index'))
