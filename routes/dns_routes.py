"""
DNS settings routes — upstream servers, local overrides.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from services import dns_service

dns_bp = Blueprint('dns', __name__, url_prefix='/dns')


@dns_bp.route('/')
@login_required
def index():
    overrides = dns_service.get_overrides()
    upstream = dns_service.get_upstream_servers()
    return render_template('new/dns.html', overrides=overrides, upstream_servers=upstream)


@dns_bp.route('/overrides/add', methods=['POST'])
@login_required
def add_override():
    hostname = request.form.get('hostname', '').strip()
    ip = request.form.get('ip', '').strip()

    if not hostname or not ip:
        flash('Hostname and IP are required.', 'error')
        return redirect(url_for('dns.index'))

    result = dns_service.add_override(hostname, ip)
    if result['success']:
        flash(result['message'], 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('dns.index'))


@dns_bp.route('/overrides/<int:override_id>/remove', methods=['POST'])
@login_required
def remove_override(override_id):
    result = dns_service.remove_override(override_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('dns.index'))


@dns_bp.route('/upstream', methods=['POST'])
@login_required
def set_upstream():
    servers_str = request.form.get('servers', '').strip()
    if not servers_str:
        flash('At least one DNS server is required.', 'error')
        return redirect(url_for('dns.index'))

    servers = [s.strip() for s in servers_str.split(',') if s.strip()]
    dns_service.set_upstream_servers(servers)
    flash('Upstream DNS servers updated.', 'success')
    return redirect(url_for('dns.index'))
