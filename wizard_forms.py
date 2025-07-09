from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, RadioField, FieldList, FormField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Length, ValidationError, Optional
from models import VPNNetwork, NETWORK_TYPES


class NetworkTypeSelectionForm(FlaskForm):
    """First step: Select network type"""
    network_type = SelectField('Network Type', validators=[DataRequired()])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.network_type.choices = [
            (key, config['name']) for key, config in NETWORK_TYPES.items()
        ]


class RateLimitProfileForm(FlaskForm):
    """Rate limiting configuration"""
    enabled = BooleanField('Enable Rate Limiting', default=False)
    profile = SelectField('Bandwidth Profile', validators=[Optional()])
    custom_download = IntegerField('Custom Download (Mbps)', validators=[Optional(), NumberRange(min=1, max=10000)])
    custom_upload = IntegerField('Custom Upload (Mbps)', validators=[Optional(), NumberRange(min=1, max=10000)])
    burst_factor = SelectField('Burst Factor', validators=[Optional()], default='1.5')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.profile.choices = [
            ('', 'Select a profile...'),
            ('residential_basic', 'Residential Basic (25/5 Mbps)'),
            ('residential_standard', 'Residential Standard (100/20 Mbps)'),
            ('residential_premium', 'Residential Premium (300/50 Mbps)'),
            ('business_basic', 'Business Basic (50/10 Mbps)'),
            ('business_standard', 'Business Standard (200/50 Mbps)'),
            ('business_premium', 'Business Premium (500/100 Mbps)'),
            ('enterprise', 'Enterprise (1000/200 Mbps)'),
            ('custom', 'Custom (specify below)')
        ]
        self.burst_factor.choices = [
            ('1.0', '1.0x (No burst)'),
            ('1.5', '1.5x (Recommended)'),
            ('2.0', '2.0x (High burst)'),
            ('3.0', '3.0x (Maximum burst)')
        ]


class SecureInternetForm(FlaskForm):
    """Secure Internet network configuration"""
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    network_isolation = BooleanField('Enable Network Isolation', default=True)
    rate_limiting = FormField(RateLimitProfileForm)
    content_filtering = BooleanField('Enable Content Filtering', default=False)
    
    def validate_name(self, field):
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')


class LocalSubnetForm(FlaskForm):
    """Form for local subnet configuration"""
    subnet = StringField('Local Subnet', validators=[DataRequired()], 
                        render_kw={'placeholder': '192.168.1.0/24'})
    description = StringField('Description', validators=[Optional(), Length(max=100)],
                            render_kw={'placeholder': 'Office LAN'})


class RemoteResourceGatewayForm(FlaskForm):
    """Remote Resource Gateway configuration"""
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    rate_limiting = FormField(RateLimitProfileForm)
    
    # CPE Configuration
    cpe_name = StringField('CPE Device Name', validators=[DataRequired(), Length(min=2, max=50)])
    local_subnets = FieldList(FormField(LocalSubnetForm), min_entries=1, max_entries=10)
    
    def validate_name(self, field):
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')


class L3VPNForm(FlaskForm):
    """L3VPN network configuration"""
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    rate_limiting = FormField(RateLimitProfileForm)
    site_count = IntegerField('Number of Sites', validators=[DataRequired(), NumberRange(min=2, max=20)])
    dynamic_routing = BooleanField('Enable Dynamic Routing', default=False)
    routing_protocol = SelectField('Routing Protocol', validators=[Optional()])
    routing_config = SelectField('Routing Configuration', validators=[Optional()])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.routing_protocol.choices = [
            ('ospf', 'OSPF (Recommended)'),
            ('bgp', 'BGP (Advanced)')
        ]
        self.routing_config.choices = [
            ('auto', 'Automatic Configuration'),
            ('manual', 'Manual Configuration')
        ]
    
    def validate_name(self, field):
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')


class L3VPNSiteForm(FlaskForm):
    """L3VPN site/CPE configuration"""
    site_name = StringField('Site Name', validators=[DataRequired(), Length(min=2, max=50)])
    cpe_name = StringField('CPE Device Name', validators=[DataRequired(), Length(min=2, max=50)])
    local_subnets = FieldList(FormField(LocalSubnetForm), min_entries=1, max_entries=10)


class L2PointToPointForm(FlaskForm):
    """L2 Point-to-Point network configuration"""
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    rate_limiting = FormField(RateLimitProfileForm)
    mac_address_limit = SelectField('MAC Address Limit', validators=[DataRequired()], default='128')
    
    # A-Side CPE
    a_side_name = StringField('A-Side CPE Name', validators=[DataRequired(), Length(min=2, max=50)])
    a_side_location = StringField('A-Side Location', validators=[Optional(), Length(max=100)])
    
    # Z-Side CPE
    z_side_name = StringField('Z-Side CPE Name', validators=[DataRequired(), Length(min=2, max=50)])
    z_side_location = StringField('Z-Side Location', validators=[Optional(), Length(max=100)])
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_address_limit.choices = [
            ('128', '128 (Recommended)'),
            ('256', '256'),
            ('384', '384'),
            ('512', '512 (Maximum)')
        ]
    
    def validate_name(self, field):
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')


class L2MeshForm(FlaskForm):
    """L2 Mesh network configuration"""
    name = StringField('Network Name', validators=[DataRequired(), Length(min=2, max=50)])
    rate_limiting = FormField(RateLimitProfileForm)
    mac_address_limit = SelectField('MAC Address Limit', validators=[DataRequired()], default='128')
    site_count = IntegerField('Number of Sites', validators=[DataRequired(), NumberRange(min=2, max=20)])
    topology = SelectField('Topology', validators=[DataRequired()], default='full_mesh')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_address_limit.choices = [
            ('128', '128 (Recommended)'),
            ('256', '256'),
            ('384', '384'),
            ('512', '512 (Maximum)')
        ]
        self.topology.choices = [
            ('full_mesh', 'Full Mesh'),
            ('hub_spoke', 'Hub and Spoke')
        ]
    
    def validate_name(self, field):
        existing = VPNNetwork.query.filter_by(name=field.data).first()
        if existing:
            raise ValidationError('Network name already exists.')


class L2MeshSiteForm(FlaskForm):
    """L2 Mesh site configuration"""
    site_name = StringField('Site Name', validators=[DataRequired(), Length(min=2, max=50)])
    cpe_name = StringField('CPE Device Name', validators=[DataRequired(), Length(min=2, max=50)])
    location = StringField('Location', validators=[Optional(), Length(max=100)])
    is_hub = BooleanField('Hub Site', default=False)


# Rate limiting profiles configuration
RATE_LIMIT_PROFILES = {
    'residential_basic': {'download': 25, 'upload': 5},
    'residential_standard': {'download': 100, 'upload': 20},
    'residential_premium': {'download': 300, 'upload': 50},
    'business_basic': {'download': 50, 'upload': 10},
    'business_standard': {'download': 200, 'upload': 50},
    'business_premium': {'download': 500, 'upload': 100},
    'enterprise': {'download': 1000, 'upload': 200}
}


def get_rate_limit_values(profile_name, custom_download=None, custom_upload=None):
    """Get rate limit values from profile or custom values"""
    if profile_name == 'custom':
        return {
            'download': custom_download or 100,
            'upload': custom_upload or 20
        }
    elif profile_name in RATE_LIMIT_PROFILES:
        return RATE_LIMIT_PROFILES[profile_name]
    else:
        return {'download': None, 'upload': None}