from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response, session, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from decouple import config
import os
import tempfile
from io import BytesIO
import base64
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY', default='dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL', default='sqlite:///warp_gateway.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Session management configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # 8 hour session timeout
app.config['SESSION_COOKIE_SECURE'] = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'  # Strong session protection

from database import db
db.init_app(app)

from models import ServerConfig, VPNNetwork, Endpoint, EndpointConfig, NETWORK_TYPES, User, AuditLog
from forms import ServerConfigForm, VPNNetworkForm, EndpointForm, BulkEndpointForm
from additional_forms import SearchForm, ServerConfigEditForm, RateLimitForm, LoginForm, CreateUserForm, ChangePasswordForm
from wizard_forms import (NetworkTypeSelectionForm, SecureInternetForm, RemoteResourceGatewayForm, 
                         L3VPNForm, L2PointToPointForm, L2MeshForm, get_rate_limit_values)
from utils import generate_keypair, generate_preshared_key, generate_endpoint_config, generate_qr_code, perform_universal_search, get_system_statistics, format_vcid
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_csrf_token():
    """Make csrf_token() function available in all templates"""
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)


@app.before_request
def before_request():
    """Handle session management and activity tracking"""
    # Make session permanent for timeout control
    session.permanent = True
    
    # Track user activity for session timeout
    if current_user.is_authenticated:
        # Update last activity time
        session['last_activity'] = datetime.utcnow().isoformat()
        
        # Check for session timeout (inactive for more than session lifetime)
        if 'last_activity' in session:
            try:
                last_activity = datetime.fromisoformat(session['last_activity'])
                if datetime.utcnow() - last_activity > app.config['PERMANENT_SESSION_LIFETIME']:
                    # Log session timeout
                    AuditLog.log_event(
                        event_type='session_expired',
                        description=f'Session expired for user {current_user.username}',
                        user=current_user,
                        ip_address=g.user_ip,
                        user_agent=request.headers.get('User-Agent', ''),
                        session_id=session.get('_id'),
                        success=True
                    )
                    db.session.commit()
                    logout_user()
                    flash('Your session has expired. Please log in again.', 'info')
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                # Invalid datetime format, clear session
                session.pop('last_activity', None)
        
        # Security: Check for suspicious session activity
        if 'user_agent' not in session:
            session['user_agent'] = request.headers.get('User-Agent', '')
        elif session['user_agent'] != request.headers.get('User-Agent', ''):
            # User agent changed - potential session hijacking
            logout_user()
            flash('Security warning: Session terminated due to suspicious activity.', 'error')
            return redirect(url_for('login'))
    
    # Store request info for audit logging
    g.request_start_time = datetime.utcnow()
    g.user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)


@app.after_request
def after_request(response):
    """Handle post-request cleanup and security headers"""
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add CSP for additional security
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    
    return response


# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.is_account_locked():
            # Log account lockout attempt
            AuditLog.log_event(
                event_type='account_locked',
                description=f'Login attempt on locked account: {form.username.data}',
                user=user,
                ip_address=g.user_ip,
                user_agent=request.headers.get('User-Agent', ''),
                success=False,
                error_message='Account is locked due to multiple failed attempts'
            )
            db.session.commit()
            flash('Account is locked due to multiple failed attempts. Please try again later.', 'error')
            return render_template('login.html', form=form)
        
        if user and user.check_password(form.password.data):
            user.reset_failed_attempts()
            user.last_login = datetime.utcnow()
            
            login_user(user, remember=form.remember_me.data)
            
            # Set session security information
            session['user_agent'] = request.headers.get('User-Agent', '')
            session['login_ip'] = request.headers.get('X-Forwarded-For', request.remote_addr)
            session['login_time'] = datetime.utcnow().isoformat()
            session['last_activity'] = datetime.utcnow().isoformat()
            
            # Log successful login
            AuditLog.log_event(
                event_type='login',
                description=f'User {user.username} logged in successfully',
                user=user,
                ip_address=g.user_ip,
                user_agent=request.headers.get('User-Agent', ''),
                session_id=session.get('_id'),
                success=True
            )
            db.session.commit()
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            # Log failed login attempt
            AuditLog.log_event(
                event_type='failed_login',
                description=f'Failed login attempt for username: {form.username.data}',
                user=user,  # May be None if user doesn't exist
                ip_address=g.user_ip,
                user_agent=request.headers.get('User-Agent', ''),
                success=False,
                error_message='Invalid username or password'
            )
            
            if user:
                user.increment_failed_attempts()
            db.session.commit()
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    # Log logout event
    AuditLog.log_event(
        event_type='logout',
        description=f'User {current_user.username} logged out',
        user=current_user,
        ip_address=g.user_ip,
        user_agent=request.headers.get('User-Agent', ''),
        session_id=session.get('_id'),
        success=True
    )
    db.session.commit()
    
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'error')
    
    return render_template('change_password.html', form=form)


# User Management Routes (Admin only)
@app.route('/users')
@login_required
def users():
    if not current_user.has_permission('manage_users'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.has_permission('manage_users'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    form = CreateUserForm()
    if form.validate_on_submit():
        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'error')
            return render_template('create_user.html', form=form)
        
        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists.', 'error')
            return render_template('create_user.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.flush()  # Get the user ID
        
        # Log user creation
        AuditLog.log_event(
            event_type='user_created',
            description=f'User {user.username} created with role {user.role}',
            user=current_user,
            resource_type='user',
            resource_id=user.id,
            ip_address=g.user_ip,
            user_agent=request.headers.get('User-Agent', ''),
            success=True
        )
        
        db.session.commit()
        
        flash(f'User {user.username} created successfully!', 'success')
        return redirect(url_for('users'))
    
    return render_template('create_user.html', form=form)


@app.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
def unlock_user(user_id):
    """Unlock a user account"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # CSRF protection for AJAX requests
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except:
        return jsonify({'success': False, 'message': 'CSRF token validation failed'}), 400
    
    user = User.query.get_or_404(user_id)
    user.reset_failed_attempts()
    
    # Log user unlock
    AuditLog.log_event(
        event_type='user_unlocked',
        description=f'User {user.username} account unlocked by {current_user.username}',
        user=current_user,
        resource_type='user',
        resource_id=user.id,
        ip_address=g.user_ip,
        user_agent=request.headers.get('User-Agent', ''),
        success=True
    )
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.username} unlocked successfully'})


@app.route('/users/<int:user_id>/enable', methods=['POST'])
@login_required
def enable_user(user_id):
    """Enable a user account"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # CSRF protection for AJAX requests
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except:
        return jsonify({'success': False, 'message': 'CSRF token validation failed'}), 400
    
    user = User.query.get_or_404(user_id)
    user.is_active = True
    
    # Log user enable
    AuditLog.log_event(
        event_type='user_enabled',
        description=f'User {user.username} enabled by {current_user.username}',
        user=current_user,
        resource_type='user',
        resource_id=user.id,
        ip_address=g.user_ip,
        user_agent=request.headers.get('User-Agent', ''),
        success=True
    )
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.username} enabled successfully'})


@app.route('/users/<int:user_id>/disable', methods=['POST'])
@login_required
def disable_user(user_id):
    """Disable a user account"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # CSRF protection for AJAX requests
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except:
        return jsonify({'success': False, 'message': 'CSRF token validation failed'}), 400
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot disable your own account'}), 400
    
    user.is_active = False
    
    # Log user disable
    AuditLog.log_event(
        event_type='user_disabled',
        description=f'User {user.username} disabled by {current_user.username}',
        user=current_user,
        resource_type='user',
        resource_id=user.id,
        ip_address=g.user_ip,
        user_agent=request.headers.get('User-Agent', ''),
        success=True
    )
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {user.username} disabled successfully'})


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user account"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # CSRF protection for AJAX requests
    from flask_wtf.csrf import validate_csrf
    try:
        validate_csrf(request.headers.get('X-CSRFToken'))
    except:
        return jsonify({'success': False, 'message': 'CSRF token validation failed'}), 400
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400
    
    username = user.username
    
    # Log user deletion
    AuditLog.log_event(
        event_type='user_deleted',
        description=f'User {username} deleted by {current_user.username}',
        user=current_user,
        resource_type='user',
        resource_id=user.id,
        ip_address=g.user_ip,
        user_agent=request.headers.get('User-Agent', ''),
        success=True
    )
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'User {username} deleted successfully'})


@app.route('/audit-logs')
@login_required
def audit_logs():
    """View audit logs (Admin only)"""
    if not current_user.has_permission('manage_users'):
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get filter parameters
    event_type = request.args.get('event_type', 'all')
    user_filter = request.args.get('user_filter', '')
    limit = min(int(request.args.get('limit', 100)), 500)  # Max 500 records
    
    # Build query
    query = AuditLog.query
    
    if event_type != 'all':
        query = query.filter(AuditLog.event_type == event_type)
    
    if user_filter:
        query = query.join(User).filter(User.username.ilike(f'%{user_filter}%'))
    
    # Get logs
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    # Get unique event types for filter dropdown
    event_types = db.session.query(AuditLog.event_type).distinct().all()
    event_types = [e[0] for e in event_types]
    
    return render_template('audit_logs.html', 
                         logs=logs, 
                         event_types=event_types,
                         current_filters={'event_type': event_type, 'user_filter': user_filter, 'limit': limit})


@app.route('/api/audit-logs')
@login_required
def api_audit_logs():
    """API endpoint for audit logs"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'error': 'Access denied'}), 403
    
    limit = min(int(request.args.get('limit', 50)), 100)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total': AuditLog.query.count()
    })


# Main Routes (Protected)
@app.route('/')
@login_required
def index():
    server_config = ServerConfig.query.first()
    networks = VPNNetwork.query.all()
    endpoints = Endpoint.query.all()
    return render_template('index.html', server_config=server_config, networks=networks, endpoints=endpoints)


@app.route('/server-config')
@login_required
def server_config():
    server_config = ServerConfig.query.first()
    return render_template('server_config.html', server_config=server_config)


# Server config edit route moved to avoid duplication


@app.route('/networks')
@login_required
def networks():
    networks = VPNNetwork.query.all()
    return render_template('networks.html', networks=networks)


@app.route('/networks/<int:network_id>')
@login_required
def network_detail(network_id):
    network = VPNNetwork.query.get_or_404(network_id)
    endpoints = Endpoint.query.filter_by(vpn_network_id=network_id).all()
    network_config = network.get_network_type_config()
    return render_template('network_detail.html', network=network, endpoints=endpoints, network_config=network_config)


# Network Creation Wizard Routes

@app.route('/networks/wizard/step1', methods=['GET', 'POST'])
@login_required
def network_wizard_step1():
    """Step 1: Select Network Type"""
    form = NetworkTypeSelectionForm()
    
    if form.validate_on_submit():
        network_type = form.network_type.data
        session['wizard_network_type'] = network_type
        return redirect(url_for('network_wizard_step2'))
    
    # Network type descriptions
    network_descriptions = {
        'secure_internet': 'Full tunnel VPN for secure internet access',
        'remote_resource_gw': 'Split tunnel for corporate resource access',
        'l3vpn_gateway': 'Site-to-site Layer 3 VPN with routing',
        'l2_point_to_point': 'Layer 2 bridging between two locations',
        'l2_mesh': 'Layer 2 mesh with VXLAN and VLAN support'
    }
    
    return render_template('wizard_step1_type.html', 
                         form=form, 
                         network_descriptions=network_descriptions,
                         current_step=1,
                         total_steps=4,
                         progress=25)


@app.route('/networks/wizard/step2', methods=['GET', 'POST'])
@login_required
def network_wizard_step2():
    """Step 2: Network Configuration"""
    network_type = session.get('wizard_network_type')
    if not network_type:
        return redirect(url_for('network_wizard_step1'))
    
    # Route to appropriate configuration form based on network type
    if network_type == 'secure_internet':
        return network_wizard_secure_internet()
    elif network_type == 'remote_resource_gw':
        return network_wizard_remote_resource()
    elif network_type == 'l3vpn_gateway':
        return network_wizard_l3vpn()
    elif network_type == 'l2_point_to_point':
        return network_wizard_l2_p2p()
    elif network_type == 'l2_mesh':
        return network_wizard_l2_mesh()
    else:
        flash('Invalid network type selected', 'error')
        return redirect(url_for('network_wizard_step1'))


def network_wizard_secure_internet():
    """Secure Internet network configuration"""
    form = SecureInternetForm()
    
    if form.validate_on_submit():
        # Create the network
        network = create_network_from_wizard(
            name=form.name.data,
            network_type='secure_internet',
            rate_limiting=form.rate_limiting.data,
            additional_config={
                'network_isolation': form.network_isolation.data,
                'content_filtering': form.content_filtering.data
            }
        )
        
        if network:
            session.pop('wizard_network_type', None)
            flash(f'Secure Internet network "{network.name}" created successfully!', 'success')
            return redirect(url_for('network_detail', network_id=network.id))
    
    return render_template('wizard_step2_secure_internet.html',
                         form=form,
                         current_step=2,
                         total_steps=2,  # Secure Internet only has 2 steps
                         progress=100,
                         network_type='secure_internet',
                         network_type_display='Secure Internet',
                         network_type_description='Full tunnel VPN for secure internet access',
                         back_url=url_for('network_wizard_step1'))


def create_network_from_wizard(name, network_type, rate_limiting=None, additional_config=None):
    """Create a network from wizard configuration"""
    from utils import get_next_available_port, get_dynamic_subnet_for_network
    
    # Generate keypair
    private_key, public_key = generate_keypair()
    
    # Auto-allocate port and subnet
    port = get_next_available_port()
    if not port:
        flash('No available ports for network creation', 'error')
        return None
    
    # Get default expected users based on network type
    expected_users = {
        'secure_internet': 10,
        'remote_resource_gw': 5,
        'l3vpn_gateway': 3,
        'l2_point_to_point': 2,
        'l2_mesh': 5
    }.get(network_type, 5)
    
    subnet = get_dynamic_subnet_for_network(network_type, expected_users)
    if not subnet:
        flash('No available subnets for network creation', 'error')
        return None
    
    # Create network
    network = VPNNetwork(
        name=name,
        port=port,
        subnet=subnet,
        network_type=network_type,
        private_key=private_key,
        public_key=public_key,
        expected_users=expected_users,
        # Set peer communication based on network isolation for secure internet
        peer_communication_enabled=not additional_config.get('network_isolation', True) if network_type == 'secure_internet' else False
    )
    
    # Auto-populate VRF fields
    network.populate_vrf_fields()
    
    # Apply rate limiting if configured
    if rate_limiting and rate_limiting.get('enabled'):
        profile = rate_limiting.get('profile')
        rate_values = get_rate_limit_values(
            profile,
            rate_limiting.get('custom_download'),
            rate_limiting.get('custom_upload')
        )
        
        network.rate_limit_enabled = True
        network.rate_limit_download_mbps = rate_values.get('download')
        network.rate_limit_upload_mbps = rate_values.get('upload')
        network.rate_limit_burst_factor = float(rate_limiting.get('burst_factor', 1.5))
    
    # Save to database
    db.session.add(network)
    db.session.commit()
    
    # Create the actual WireGuard network interface
    try:
        network.create_network()
        print(f"✅ WireGuard network {network.name} created successfully")
    except Exception as e:
        print(f"⚠️ Failed to create WireGuard network: {e}")
        # Don't fail the request - network is still created in database
    
    return network


@app.route('/networks/add', methods=['GET', 'POST'])
@login_required
def add_network():
    """Redirect to new wizard"""
    return redirect(url_for('network_wizard_step1'))


@app.route('/endpoints')
@login_required
def endpoints():
    endpoints = Endpoint.query.all()
    return render_template('endpoints.html', endpoints=endpoints)


@app.route('/endpoints/add', methods=['GET', 'POST'])
@login_required
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
            
            # Add endpoint to actual WireGuard network
            try:
                endpoint.add_to_network()
                print(f"✅ Endpoint {endpoint.name} added to WireGuard network {network.name}")
            except Exception as e:
                print(f"⚠️ Failed to add endpoint to WireGuard: {e}")
                # Don't fail the request - endpoint is still created in database
            
            flash('Endpoint added successfully!', 'success')
            return redirect(url_for('endpoints'))
        except ValueError as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('add_endpoint.html', form=form)


@app.route('/endpoints/<int:endpoint_id>/config')
@login_required
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
@login_required
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
@login_required
def search():
    form = SearchForm()
    results = None
    
    if form.validate_on_submit():
        query = form.query.data
        search_type = form.search_type.data
        results = perform_universal_search(query, search_type)
    
    return render_template('search.html', form=form, results=results)


@app.route('/server-config/edit', methods=['GET', 'POST'])
@login_required
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
@login_required
def statistics():
    stats = get_system_statistics()
    return render_template('statistics.html', stats=stats)


@app.route('/api/statistics')
@login_required
def api_statistics():
    """API endpoint for real-time statistics"""
    stats = get_system_statistics()
    return jsonify(stats)


@app.route('/circuits')
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def network_types():
    """Display the built-in network types (read-only)"""
    return render_template('network_types.html', network_types=NETWORK_TYPES)


@app.route('/endpoints/<int:endpoint_id>/delete', methods=['POST'])
@login_required
def delete_endpoint(endpoint_id):
    """Delete an endpoint"""
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    
    endpoint_name = endpoint.name
    network_name = endpoint.vpn_network.name
    
    try:
        # Remove endpoint from actual WireGuard network
        endpoint.remove_from_network()
        print(f"✅ Endpoint {endpoint_name} removed from WireGuard network {network_name}")
    except Exception as e:
        print(f"⚠️ Failed to remove endpoint from WireGuard: {e}")
        # Continue with database deletion even if system cleanup fails
    
    # Delete from database (configs will be deleted automatically due to cascade)
    db.session.delete(endpoint)
    db.session.commit()
    
    flash(f'Endpoint "{endpoint_name}" deleted successfully!', 'success')
    return redirect(url_for('endpoints'))


@app.route('/networks/<int:network_id>/delete', methods=['POST'])
@login_required
def delete_network(network_id):
    """Delete a VPN network"""
    network = VPNNetwork.query.get_or_404(network_id)
    
    # Check if network has endpoints
    if network.endpoints:
        flash(f'Cannot delete network "{network.name}" - it has {len(network.endpoints)} endpoints. Remove all endpoints first.', 'error')
        return redirect(url_for('networks'))
    
    network_name = network.name
    
    try:
        # Remove the actual WireGuard network interface
        network.remove_network()
        print(f"✅ WireGuard network {network_name} removed successfully")
    except Exception as e:
        print(f"⚠️ Failed to remove WireGuard network: {e}")
        # Continue with database deletion even if system cleanup fails
    
    # Delete from database
    db.session.delete(network)
    db.session.commit()
    
    flash(f'VPN Network "{network_name}" deleted successfully!', 'success')
    return redirect(url_for('networks'))


@app.route('/networks/<int:network_id>/suspend', methods=['POST'])
@login_required
def suspend_network(network_id):
    """Suspend a VPN network"""
    network = VPNNetwork.query.get_or_404(network_id)
    
    if network.suspend_network():
        db.session.commit()
        flash(f'Network "{network.name}" suspended successfully!', 'success')
    else:
        flash(f'Failed to suspend network "{network.name}"', 'error')
    
    return redirect(url_for('network_detail', network_id=network_id))


@app.route('/networks/<int:network_id>/resume', methods=['POST'])
@login_required
def resume_network(network_id):
    """Resume a VPN network"""
    network = VPNNetwork.query.get_or_404(network_id)
    
    if network.resume_network():
        db.session.commit()
        flash(f'Network "{network.name}" resumed successfully!', 'success')
    else:
        flash(f'Failed to resume network "{network.name}"', 'error')
    
    return redirect(url_for('network_detail', network_id=network_id))


@app.route('/endpoints/<int:endpoint_id>/suspend', methods=['POST'])
@login_required
def suspend_endpoint(endpoint_id):
    """Suspend an endpoint"""
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    
    if endpoint.suspend_endpoint():
        db.session.commit()
        flash(f'Endpoint "{endpoint.name}" suspended successfully!', 'success')
    else:
        flash(f'Failed to suspend endpoint "{endpoint.name}"', 'error')
    
    return redirect(url_for('endpoints'))


@app.route('/endpoints/<int:endpoint_id>/resume', methods=['POST'])
@login_required
def resume_endpoint(endpoint_id):
    """Resume an endpoint"""
    endpoint = Endpoint.query.get_or_404(endpoint_id)
    
    if endpoint.resume_endpoint():
        db.session.commit()
        flash(f'Endpoint "{endpoint.name}" resumed successfully!', 'success')
    else:
        flash(f'Failed to resume endpoint "{endpoint.name}"', 'error')
    
    return redirect(url_for('endpoints'))


@app.route('/networks/<int:network_id>/status/refresh', methods=['POST'])
@login_required
def refresh_network_status(network_id):
    """Refresh network status based on WireGuard state"""
    network = VPNNetwork.query.get_or_404(network_id)
    
    old_status = network.status
    network.update_dynamic_status()
    
    # Update endpoint statuses as well
    for endpoint in network.endpoints:
        endpoint.update_handshake_status()
    
    db.session.commit()
    
    if old_status != network.status:
        flash(f'Network status updated from "{old_status}" to "{network.status}"', 'info')
    else:
        flash('Network status refreshed', 'info')
    
    return redirect(url_for('network_detail', network_id=network_id))


@app.route('/bulk-endpoints', methods=['GET', 'POST'])
@login_required
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