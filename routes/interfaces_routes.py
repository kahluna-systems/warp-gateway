"""
Interface management routes — list NICs, assign WAN/LAN roles, configure IPs.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from services import interface_service

interfaces_bp = Blueprint('interfaces', __name__, url_prefix='/interfaces')


@interfaces_bp.route('/')
@login_required
def index():
    interfaces = interface_service.get_all_interfaces()
    return render_template('new/interfaces.html', interfaces=interfaces)


@interfaces_bp.route('/assign', methods=['POST'])
@login_required
def assign():
    iface_name = request.form.get('interface_name', '')
    role = request.form.get('role', 'DISABLED')
    mode = request.form.get('mode', 'static')
    ip = request.form.get('ip_address', '').strip() or None
    netmask = request.form.get('netmask', '').strip() or None
    gateway = request.form.get('gateway', '').strip() or None
    dns = request.form.get('dns_servers', '').strip() or None

    result = interface_service.assign_role(iface_name, role, mode, ip, netmask, gateway, dns)

    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('interfaces.index'))
