"""
System settings routes — dependency status, health, backup, reboot.
"""
from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from flask_login import login_required
from services import health_service
from nexus_client import nexus

system_bp = Blueprint('system', __name__, url_prefix='/system')


@system_bp.route('/')
@login_required
def index():
    health = health_service.get_full_health()
    nexus_status = nexus.get_status()
    return render_template('new/system.html', health=health, nexus_status=nexus_status)


@system_bp.route('/nexus/register', methods=['POST'])
@login_required
def nexus_register():
    token = request.form.get('token', '').strip()
    gateway_name = request.form.get('gateway_name', '').strip()
    gateway_url = request.form.get('gateway_url', '').strip()
    platform_url = request.form.get('platform_url', '').strip()

    if not all([token, gateway_name, gateway_url, platform_url]):
        flash('All fields are required for registration.', 'error')
        return redirect(url_for('system.index'))

    result = nexus.claim_provisioning_token(token, gateway_name, gateway_url, platform_url)
    if result.get('status') == 'registered':
        flash('Gateway registered with KahLuna Nexus.', 'success')
    else:
        flash(f'Registration failed: {result.get("detail", "Unknown error")}', 'error')

    return redirect(url_for('system.index'))


@system_bp.route('/nexus/deregister', methods=['POST'])
@login_required
def nexus_deregister():
    nexus.deregister()
    flash('Gateway deregistered from KahLuna Nexus.', 'success')
    return redirect(url_for('system.index'))
