"""
Diagnostic tools routes — ping, traceroute, DNS lookup, packet capture.
"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from services import diagnostics_service, interface_service

diagnostics_bp = Blueprint('diagnostics', __name__, url_prefix='/diagnostics')


@diagnostics_bp.route('/')
@login_required
def index():
    tools = diagnostics_service.get_available_tools()
    interfaces = interface_service.get_all_interfaces()
    return render_template('new/diagnostics.html', tools=tools, interfaces=interfaces)


@diagnostics_bp.route('/run', methods=['POST'])
@login_required
def run_tool():
    tool = request.form.get('tool', '')
    target = request.form.get('target', '').strip()

    if tool == 'ping':
        count = request.form.get('count', 4, type=int)
        result = diagnostics_service.ping(target, count=min(count, 20))
    elif tool == 'traceroute':
        result = diagnostics_service.traceroute(target)
    elif tool == 'dns_lookup':
        record_type = request.form.get('record_type', 'A')
        server = request.form.get('server', '').strip() or None
        result = diagnostics_service.dns_lookup(target, record_type, server)
    elif tool == 'mtr':
        result = diagnostics_service.mtr(target)
    elif tool == 'packet_capture':
        interface = request.form.get('interface', 'any')
        filter_expr = request.form.get('filter', '').strip()
        count = request.form.get('count', 50, type=int)
        result = diagnostics_service.packet_capture(interface, filter_expr, count=min(count, 200))
    else:
        result = {'success': False, 'output': f'Unknown tool: {tool}', 'tool': tool}

    if request.headers.get('Accept') == 'application/json':
        return jsonify(result)

    tools = diagnostics_service.get_available_tools()
    interfaces = interface_service.get_all_interfaces()
    return render_template('new/diagnostics.html', tools=tools, interfaces=interfaces, result=result)
