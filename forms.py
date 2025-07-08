from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Length, ValidationError, Optional
from models import VPNNetwork, NETWORK_TYPES


class ServerConfigForm(FlaskForm):
    hostname = StringField('Hostname', validators=[DataRequired(), Length(min=2, max=255)])
    public_ip = StringField('Public IP', validators=[DataRequired(), IPAddress()])
    location = StringField('Location', validators=[Length(max=100)])
    admin_email = StringField('Admin Email', validators=[Length(max=255)])


class VPNNetworkForm(FlaskForm):
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    port = IntegerField('Port', validators=[DataRequired(), NumberRange(min=1024, max=65535)])
    subnet = StringField('Subnet', validators=[DataRequired()])
    network_type = SelectField('Network Type', validators=[DataRequired()])
    custom_allowed_ips = TextAreaField('Custom Allowed IPs (optional)')
    vlan_id = IntegerField('VLAN ID', validators=[Optional(), NumberRange(min=1, max=4094)])
    vlan_range = StringField('VLAN Range', validators=[Optional(), Length(max=50)])
    bridge_name = StringField('Bridge Name', validators=[Optional(), Length(max=50)])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate network type choices from fixed types
        self.network_type.choices = [
            (key, config['name']) for key, config in NETWORK_TYPES.items()
        ]
    
    def validate_name(self, field):
        # Check for unique network name
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')
    
    def validate_port(self, field):
        # Check for unique port
        existing = VPNNetwork.query.filter_by(port=field.data).first()
        if existing:
            raise ValidationError('Port already in use.')
    
    def validate_subnet(self, field):
        # Validate subnet format
        try:
            import ipaddress
            network = ipaddress.ip_network(field.data, strict=False)
            if network.prefixlen > 30:
                raise ValidationError('Subnet too small (minimum /30).')
        except ValueError:
            raise ValidationError('Invalid subnet format.')


class EndpointForm(FlaskForm):
    vpn_network_id = SelectField('VPN Network', coerce=int, validators=[DataRequired()])
    name = StringField('Endpoint Name', validators=[DataRequired(), Length(min=2, max=100)])
    endpoint_type = SelectField('Endpoint Type', validators=[DataRequired()])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show active networks
        networks = VPNNetwork.query.all()
        self.vpn_network_id.choices = [
            (n.id, f"{n.name} ({NETWORK_TYPES[n.network_type]['name']})") 
            for n in networks
        ]
        # Endpoint type choices (must match database constraints)
        self.endpoint_type.choices = [
            ('mobile', 'Mobile Device'),
            ('cpe', 'CPE Device'),
            ('gateway', 'Gateway')
        ]
    
    def validate_name(self, field):
        # Check for unique endpoint name within network
        if hasattr(self, 'vpn_network_id') and self.vpn_network_id.data:
            from models import Endpoint
            existing = Endpoint.query.filter_by(
                vpn_network_id=self.vpn_network_id.data,
                name=field.data
            ).first()
            if existing:
                raise ValidationError('Endpoint name already exists on this network.')


class BulkEndpointForm(FlaskForm):
    """Form for creating multiple endpoints at once"""
    vpn_network_id = SelectField('VPN Network', coerce=int, validators=[DataRequired()])
    endpoint_names = TextAreaField('Endpoint Names', validators=[DataRequired()],
                                  description='One endpoint name per line')
    endpoint_type = SelectField('Endpoint Type', validators=[DataRequired()])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        networks = VPNNetwork.query.all()
        self.vpn_network_id.choices = [
            (n.id, f"{n.name} ({NETWORK_TYPES[n.network_type]['name']})") 
            for n in networks
        ]
        # Endpoint type choices (must match database constraints)
        self.endpoint_type.choices = [
            ('mobile', 'Mobile Device'),
            ('cpe', 'CPE Device'),
            ('gateway', 'Gateway')
        ]