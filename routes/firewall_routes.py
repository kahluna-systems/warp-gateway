"""
Firewall routes — list, add, remove custom rules and port forwarding.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from services import firewall_service

firewall_bp = Blueprint('firewall', __name__, url_prefix='/firewall')


@firewall_bp.route('/')
@login_required
def index():
    rules = firewall_service.list_rules()
    port_forwards = firewall_service.list_port_forwards()
    iptables = firewall_service.get_iptables_rules()
    return render_template('new/firewall.html', rules=rules, port_forwards=port_forwards, iptables=iptables)


@firewall_bp.route('/rules/add', methods=['POST'])
@login_required
def add_rule():
    chain = request.form.get('chain', 'INPUT')
    source = request.form.get('source', '').strip() or None
    destination = request.form.get('destination', '').strip() or None
    port = request.form.get('port', type=int)
    protocol = request.form.get('protocol', '').strip() or None
    action = request.form.get('action', 'ACCEPT')
    priority = request.form.get('priority', 100, type=int)
    description = request.form.get('description', '').strip()

    result = firewall_service.add_custom_rule(
        chain=chain, source=source, destination=destination,
        port=port, protocol=protocol, action=action,
        priority=priority, description=description,
    )

    if result['success']:
        flash('Firewall rule added.', 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/rules/<int:rule_id>/remove', methods=['POST'])
@login_required
def remove_rule(rule_id):
    result = firewall_service.remove_custom_rule(rule_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('firewall.index'))


@firewall_bp.route('/forwards/add', methods=['POST'])
@login_required
def add_forward():
    wan_port = request.form.get('wan_port', type=int)
    lan_ip = request.form.get('lan_ip', '').strip()
    lan_port = request.form.get('lan_port', type=int)
    protocol = request.form.get('protocol', 'tcp')
    description = request.form.get('description', '').strip()

    if not wan_port or not lan_ip or not lan_port:
        flash('All port forward fields are required.', 'error')
        return redirect(url_for('firewall.index'))

    result = firewall_service.add_port_forward(wan_port, lan_ip, lan_port, protocol, description)
    if result['success']:
        flash('Port forward added.', 'success')
    else:
        flash(result['message'], 'error')

    return redirect(url_for('firewall.index'))


@firewall_bp.route('/forwards/<int:pf_id>/remove', methods=['POST'])
@login_required
def remove_forward(pf_id):
    result = firewall_service.remove_port_forward(pf_id)
    flash(result['message'], 'success' if result['success'] else 'error')
    return redirect(url_for('firewall.index'))
