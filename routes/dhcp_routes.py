"""
DHCP settings routes — configure subnet/range, static reservations, view leases.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from services import dhcp_service, interface_service

dhcp_bp = Blueprint('dhcp', __name__, url_prefix='/dhcp')


@dhcp_bp.route('/')
@login_required
def index():
    config = dhcp_service.get_config()
    reservations = dhcp_service.get_reservations()
    leases = dhcp_service.get_leases()
    status = dhcp_service.get_dhcp_status()
    interfaces = interface_service.get_all_interfaces()
    lan_interfaces = [i for i in interfaces if i['role'] == 'LAN']
    return render_template('new/dhcp.html',
                           config=config,
                           reservations=reservations,
                           leases=leases,
                           status=status,
                           lan_interfaces=lan_interfaces)


@dhcp_bp.route('/configure', methods=['POST'])
@login_required
def configure():
    interface = request.form.get('interface', '').strip()
    range_start = request.form.get('range_start', '').strip()
    range_end = request.form.get('range_end', '').strip()
    netmask = request.form.get('netmask', '255.255.255.0').strip()
    gateway = request.form.get('gateway', '').strip() or None
    dns_servers = request.form.get('dns_servers', '1.1.1.1,8.8.8.8').strip()
    lease_time = request.form.get('lease_time', '12h').strip()

    if not interface or not range_start or not range_end:
        flash('Interface, range start, and range end are required.', 'error')
        return redirect(url_for('dhcp.index'))

    result = dhcp_service.setup_dhcp(interface, range_start, range_end, netmask, gateway, dns_servers, lease_time)
    if result['success']:
        flash('DHCP configuration saved and applied.', 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('dhcp.index'))


@dhcp_bp.route('/reservations/add', methods=['POST'])
@login_required
def add_reservation():
    mac = request.form.get('mac', '').strip()
    ip = request.form.get('ip', '').strip()
    hostname = request.form.get('hostname', '').strip()

    if not mac or not ip:
        flash('MAC address and IP are required.', 'error')
        return redirect(url_for('dhcp.index'))

    result = dhcp_service.add_reservation(mac, ip, hostname)
    if result['success']:
        flash('DHCP reservation added.', 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('dhcp.index'))


@dhcp_bp.route('/reservations/<int:res_id>/remove', methods=['POST'])
@login_required
def remove_reservation(res_id):
    result = dhcp_service.remove_reservation(res_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('dhcp.index'))
