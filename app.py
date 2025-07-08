from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from decouple import config
import os
import tempfile
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY', default='dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL', default='sqlite:///warp_gateway.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from database import db
db.init_app(app)

from models import ServerConfig, VPNNetwork, Endpoint, EndpointConfig, NETWORK_TYPES
from forms import ServerConfigForm, VPNNetworkForm, EndpointForm, BulkEndpointForm
from additional_forms import SearchForm, ServerConfigEditForm, RateLimitForm
from utils import generate_keypair, generate_preshared_key, generate_endpoint_config, generate_qr_code, perform_universal_search, get_system_statistics, format_vcid
from datetime import datetime


# Routes
@app.route('/')
def index():
    server_config = ServerConfig.query.first()
    networks = VPNNetwork.query.all()
    endpoints = Endpoint.query.all()
    return render_template('index.html', server_config=server_config, networks=networks, endpoints=endpoints)


@app.route('/server-config')
def server_config():
    server_config = ServerConfig.query.first()
    return render_template('server_config.html', server_config=server_config)


# Server config edit route moved to avoid duplication


@app.route('/networks')
def networks():
    networks = VPNNetwork.query.all()
    return render_template('networks.html', networks=networks)


@app.route('/networks/<int:network_id>')
def network_detail(network_id):
    network = VPNNetwork.query.get_or_404(network_id)
    endpoints = Endpoint.query.filter_by(vpn_network_id=network_id).all()
    network_config = network.get_network_type_config()
    return render_template('network_detail.html', network=network, endpoints=endpoints, network_config=network_config)


@app.route('/networks/add', methods=['GET', 'POST'])
def add_network():
    form = VPNNetworkForm()
    if form.validate_on_submit():
        private_key, public_key = generate_keypair()
        
        # Create network with VRF fields
        network = VPNNetwork(
            name=form.name.data,
            port=form.port.data,
            subnet=form.subnet.data,
            network_type=form.network_type.data,
            private_key=private_key,
            public_key=public_key,
            custom_allowed_ips=form.custom_allowed_ips.data,
            vlan_id=form.vlan_id.data,
            vlan_range=form.vlan_range.data,
            bridge_name=form.bridge_name.data,
            # New VRF fields
            peer_communication_enabled=form.peer_communication_enabled.data,
            expected_users=form.expected_users.data,
            vrf_name=form.vrf_name.data,
            routing_table_id=form.routing_table_id.data
        )
        
        # Auto-populate VRF fields if not provided
        network.populate_vrf_fields()
        
        db.session.add(network)
        db.session.commit()
        
        # In development, we won't actually create the network
        # network.create_network()  # This would be called in production
        
        flash(f'VPN Network added successfully! VCID: {network.vcid}', 'success')
        return redirect(url_for('networks'))
    return render_template('add_network.html', form=form)


@app.route('/endpoints')
def endpoints():
    endpoints = Endpoint.query.all()
    return render_template('endpoints.html', endpoints=endpoints)


@app.route('/endpoints/add', methods=['GET', 'POST'])
def add_endpoint():
    form = EndpointForm()
    if form.validate_on_submit():
        network = VPNNetwork.query.get(form.vpn_network_id.data)
        if not network:
            flash('VPN Network not found!', 'error')
            return redirect(url_for('add_endpoint'))
        
        # Check endpoint limits for this network type
        if not network.can_add_endpoint():
            network_config = network.get_network_type_config()
            max_endpoints = network_config.get('max_peers', 'unlimited')
            flash(f'Cannot add endpoint: {network_config["name"]} network type limited to {max_endpoints} endpoints', 'error')
            return redirect(url_for('add_endpoint'))
        
        try:
            ip_address = network.get_next_ip()
            private_key, public_key = generate_keypair()
            
            endpoint = Endpoint(
                vpn_network_id=form.vpn_network_id.data,
                name=form.name.data,
                ip_address=ip_address,
                private_key=private_key,
                public_key=public_key,
                preshared_key=generate_preshared_key(),
                endpoint_type=form.endpoint_type.data
            )
            db.session.add(endpoint)
            db.session.commit()
            
            # Generate config
            config_content = generate_endpoint_config(endpoint)
            endpoint_config = EndpointConfig(
                endpoint_id=endpoint.id,
                config_content=config_content,
                version=1
            )
            db.session.add(endpoint_config)
            db.session.commit()
            
            # In development, we won't actually add to network
            # endpoint.add_to_network()  # This would be called in production
            
            flash('Endpoint added successfully!', 'success')
            return redirect(url_for('endpoints'))
        except ValueError as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('add_endpoint.html', form=form)


@app.route('/endpoints/<int:endpoint_id>/config')
def endpoint_config(endpoint_id):
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    latest_config = EndpointConfig.query.filter_by(endpoint_id=endpoint_id).order_by(EndpointConfig.version.desc()).first()
    
    if not latest_config:
        config_content = generate_endpoint_config(endpoint)
        latest_config = EndpointConfig(
            endpoint_id=endpoint_id,
            config_content=config_content,
            version=1
        )
        db.session.add(latest_config)
        db.session.commit()
    
    return render_template('endpoint_config.html', endpoint=endpoint, config=latest_config)


@app.route('/endpoints/<int:endpoint_id>/config/download')
def download_endpoint_config(endpoint_id):
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    latest_config = EndpointConfig.query.filter_by(endpoint_id=endpoint_id).order_by(EndpointConfig.version.desc()).first()
    
    if not latest_config:
        config_content = generate_endpoint_config(endpoint)
    else:
        config_content = latest_config.config_content
    
    response = make_response(config_content)
    response.headers['Content-Disposition'] = f'attachment; filename={endpoint.name}.conf'
    response.headers['Content-Type'] = 'text/plain'
    return response


@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    results = None
    
    if form.validate_on_submit():
        query = form.query.data
        search_type = form.search_type.data
        results = perform_universal_search(query, search_type)
    
    return render_template('search.html', form=form, results=results)


@app.route('/server-config/edit', methods=['GET', 'POST'])
def edit_server_config():
    server_config = ServerConfig.query.first()
    if not server_config:
        flash('Server configuration not found. Please run server initialization first.', 'error')
        return redirect(url_for('index'))
    
    form = ServerConfigEditForm(obj=server_config)
    
    if form.validate_on_submit():
        server_config.hostname = form.hostname.data
        server_config.public_ip = form.public_ip.data
        server_config.location = form.location.data
        server_config.admin_email = form.admin_email.data
        server_config.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Server configuration updated successfully!', 'success')
        return redirect(url_for('server_config'))
    
    return render_template('edit_server_config.html', form=form, server_config=server_config)


@app.route('/statistics')
def statistics():
    stats = get_system_statistics()
    return render_template('statistics.html', stats=stats)


@app.route('/api/statistics')
def api_statistics():
    """API endpoint for real-time statistics"""
    stats = get_system_statistics()
    return jsonify(stats)


@app.route('/circuits')
def circuits():
    """Circuit management interface"""
    networks = VPNNetwork.query.all()
    circuit_info = []
    
    for network in networks:
        circuit_info.append({
            'network': network,
            'vcid_formatted': format_vcid(network.vcid),
            'statistics': network.get_statistics(),
            'capacity': network.get_dynamic_subnet_info()
        })
    
    return render_template('circuits.html', circuits=circuit_info)


@app.route('/networks/<int:network_id>/rate-limit', methods=['GET', 'POST'])
def network_rate_limit(network_id):
    """Configure rate limiting for a network"""
    network = VPNNetwork.query.get_or_404(network_id)
    
    form = RateLimitForm()
    if network.rate_limit_enabled:
        form.enabled.data = True
        form.download_mbps.data = network.rate_limit_download_mbps
        form.upload_mbps.data = network.rate_limit_upload_mbps
        form.burst_factor.data = network.rate_limit_burst_factor
    
    if form.validate_on_submit():
        network.rate_limit_enabled = form.enabled.data
        network.rate_limit_download_mbps = form.download_mbps.data if form.enabled.data else None
        network.rate_limit_upload_mbps = form.upload_mbps.data if form.enabled.data else None
        network.rate_limit_burst_factor = form.burst_factor.data if form.enabled.data else 1.5
        
        db.session.commit()
        flash('Rate limiting configuration updated successfully!', 'success')
        return redirect(url_for('network_detail', network_id=network_id))
    
    return render_template('rate_limit.html', form=form, network=network, target_type='network')


@app.route('/endpoints/<int:endpoint_id>/rate-limit', methods=['GET', 'POST'])
def endpoint_rate_limit(endpoint_id):
    """Configure rate limiting for an endpoint"""
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    
    form = RateLimitForm()
    if endpoint.rate_limit_enabled:
        form.enabled.data = True
        form.download_mbps.data = endpoint.rate_limit_download_mbps
        form.upload_mbps.data = endpoint.rate_limit_upload_mbps
        form.burst_factor.data = endpoint.rate_limit_burst_factor
    
    if form.validate_on_submit():
        endpoint.rate_limit_enabled = form.enabled.data
        endpoint.rate_limit_download_mbps = form.download_mbps.data if form.enabled.data else None
        endpoint.rate_limit_upload_mbps = form.upload_mbps.data if form.enabled.data else None
        endpoint.rate_limit_burst_factor = form.burst_factor.data if form.enabled.data else 1.5
        
        db.session.commit()
        flash('Rate limiting configuration updated successfully!', 'success')
        return redirect(url_for('endpoint_config', endpoint_id=endpoint_id))
    
    return render_template('rate_limit.html', form=form, endpoint=endpoint, target_type='endpoint')


@app.route('/endpoints/<int:endpoint_id>/qr')
def endpoint_qr(endpoint_id):
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    latest_config = EndpointConfig.query.filter_by(endpoint_id=endpoint_id).order_by(EndpointConfig.version.desc()).first()
    
    if not latest_config:
        config_content = generate_endpoint_config(endpoint)
    else:
        config_content = latest_config.config_content
    
    qr_code = generate_qr_code(config_content)
    return jsonify({'qr_code': qr_code})


@app.route('/network-types')
def network_types():
    """Display the built-in network types (read-only)"""
    return render_template('network_types.html', network_types=NETWORK_TYPES)


@app.route('/bulk-endpoints', methods=['GET', 'POST'])
def bulk_endpoints():
    """Bulk endpoint creation"""
    form = BulkEndpointForm()
    if form.validate_on_submit():
        network = VPNNetwork.query.get(form.vpn_network_id.data)
        if not network:
            flash('VPN Network not found!', 'error')
            return redirect(url_for('bulk_endpoints'))
        
        endpoint_names = [name.strip() for name in form.endpoint_names.data.split('\n') if name.strip()]
        created_endpoints = []
        errors = []
        
        for endpoint_name in endpoint_names:
            try:
                # Check if network can accept more endpoints
                if not network.can_add_endpoint():
                    errors.append(f'Network reached max endpoint limit at {endpoint_name}')
                    break
                
                # Generate keypair
                private_key, public_key = generate_keypair()
                preshared_key = generate_preshared_key()
                ip_address = network.get_next_ip()
                
                # Create endpoint
                endpoint = Endpoint(
                    vpn_network_id=network.id,
                    name=endpoint_name,
                    ip_address=ip_address,
                    private_key=private_key,
                    public_key=public_key,
                    preshared_key=preshared_key,
                    endpoint_type=form.endpoint_type.data
                )
                
                db.session.add(endpoint)
                created_endpoints.append(endpoint)
                
            except Exception as e:
                errors.append(f'Error creating endpoint {endpoint_name}: {str(e)}')
        
        if created_endpoints:
            db.session.commit()
            flash(f'Successfully created {len(created_endpoints)} endpoints!', 'success')
        
        for error in errors:
            flash(error, 'error')
        
        return redirect(url_for('endpoints'))
    
    form = BulkEndpointForm()
    return render_template('add_bulk_endpoints.html', form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Server initialization should be done via server_init.py
        # Check if server is configured
        server_config = ServerConfig.query.first()
        if not server_config:
            print("Warning: Server not initialized. Run 'python server_init.py' first.")
    app.run(debug=True, host='0.0.0.0', port=5000)