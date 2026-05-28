"""
WiFi management routes — radio info, scanning, client connection, AP mode.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required
from services import wifi_service

wifi_bp = Blueprint('wifi', __name__, url_prefix='/wifi')


@wifi_bp.route('/')
@login_required
def index():
    """WiFi management page — shows radio info and current status."""
    interfaces = wifi_service.get_wireless_interfaces()
    if not interfaces:
        return render_template('new/wifi.html', interfaces=[], status=None, radio=None)

    # Use first wireless interface by default
    active_iface = request.args.get('interface', interfaces[0])
    status = wifi_service.get_status(active_iface)
    radio = status.get('radio', {})

    return render_template('new/wifi.html',
                           interfaces=interfaces,
                           active_iface=active_iface,
                           status=status,
                           radio=radio)


@wifi_bp.route('/scan')
@login_required
def scan():
    """Scan for available networks (returns JSON for AJAX)."""
    interface = request.args.get('interface', 'wlan0')
    networks = wifi_service.scan_networks(interface)
    return jsonify(networks)


@wifi_bp.route('/connect', methods=['POST'])
@login_required
def connect():
    """Connect to a WiFi network in client mode."""
    interface = request.form.get('interface', 'wlan0')
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '').strip()
    security = request.form.get('security', 'WPA2-PSK')

    if not ssid:
        flash('SSID is required', 'error')
        return redirect(url_for('wifi.index', interface=interface))

    result = wifi_service.connect(interface, ssid, password, security)

    if result.get('success'):
        flash(f"Connecting to '{ssid}'...", 'success')
    else:
        flash(result.get('error', 'Connection failed'), 'error')

    return redirect(url_for('wifi.index', interface=interface))


@wifi_bp.route('/disconnect', methods=['POST'])
@login_required
def disconnect():
    """Disconnect from current WiFi network."""
    interface = request.form.get('interface', 'wlan0')
    result = wifi_service.disconnect(interface)

    if result.get('success'):
        flash('Disconnected', 'success')
    else:
        flash(result.get('error', 'Disconnect failed'), 'error')

    return redirect(url_for('wifi.index', interface=interface))


@wifi_bp.route('/ap/start', methods=['POST'])
@login_required
def start_ap():
    """Start WiFi access point."""
    interface = request.form.get('interface', 'wlan0')
    ssid = request.form.get('ssid', '').strip()
    password = request.form.get('password', '').strip()
    channel = int(request.form.get('channel', 6))
    band = request.form.get('band', '2.4GHz')
    security = request.form.get('security', 'WPA2-PSK')
    hidden = request.form.get('hidden') == 'on'
    gateway_ip = request.form.get('gateway_ip', '10.0.0.1').strip()

    if not ssid:
        flash('SSID is required', 'error')
        return redirect(url_for('wifi.index', interface=interface))

    if security != 'Open' and len(password) < 8:
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('wifi.index', interface=interface))

    result = wifi_service.start_access_point(
        interface=interface, ssid=ssid, password=password,
        channel=channel, band=band, security=security,
        hidden=hidden, gateway_ip=gateway_ip,
    )

    if result.get('success'):
        flash(f"AP '{ssid}' started on {interface}", 'success')
    else:
        flash(result.get('error', 'Failed to start AP'), 'error')

    return redirect(url_for('wifi.index', interface=interface))


@wifi_bp.route('/ap/stop', methods=['POST'])
@login_required
def stop_ap():
    """Stop WiFi access point."""
    interface = request.form.get('interface', 'wlan0')
    result = wifi_service.stop_access_point(interface)

    if result.get('success'):
        flash('Access point stopped', 'success')
    else:
        flash(result.get('error', 'Failed to stop AP'), 'error')

    return redirect(url_for('wifi.index', interface=interface))


@wifi_bp.route('/radio', methods=['POST'])
@login_required
def configure_radio():
    """Apply radio configuration changes."""
    interface = request.form.get('interface', 'wlan0')
    tx_power = request.form.get('tx_power')
    channel = request.form.get('channel')
    channel_width = request.form.get('channel_width')
    country_code = request.form.get('country_code', '').strip() or None

    result = wifi_service.set_radio_config(
        interface=interface,
        tx_power=float(tx_power) if tx_power else None,
        channel=int(channel) if channel else None,
        channel_width=channel_width or None,
        country_code=country_code,
    )

    if result.get('success'):
        flash('Radio configuration updated', 'success')
    else:
        flash('Failed to update radio configuration', 'error')

    return redirect(url_for('wifi.index', interface=interface))
