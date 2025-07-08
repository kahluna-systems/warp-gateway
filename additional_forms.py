from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, SubmitField, FloatField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Length, ValidationError, Optional


class SearchForm(FlaskForm):
    """Universal search form for networks, endpoints, and VCIDs"""
    query = StringField('Search', validators=[DataRequired(), Length(min=1, max=100)])
    search_type = SelectField('Search In', choices=[
        ('all', 'All'),
        ('networks', 'Networks'),
        ('endpoints', 'Endpoints'),
        ('vcids', 'VCIDs')
    ], default='all')
    submit = SubmitField('Search')


class ServerConfigEditForm(FlaskForm):
    """Form for editing server configuration"""
    hostname = StringField('Hostname', validators=[DataRequired(), Length(min=2, max=255)])
    public_ip = StringField('Public IP', validators=[DataRequired(), IPAddress()])
    location = StringField('Location', validators=[Length(max=100)])
    admin_email = StringField('Admin Email', validators=[Length(max=255)])
    submit = SubmitField('Update Server Config')


class RateLimitForm(FlaskForm):
    """Form for configuring rate limits"""
    enabled = BooleanField('Enable Rate Limiting', default=False)
    download_mbps = FloatField('Download Limit (Mbps)', validators=[Optional(), NumberRange(min=0.1, max=10000)])
    upload_mbps = FloatField('Upload Limit (Mbps)', validators=[Optional(), NumberRange(min=0.1, max=10000)])
    burst_factor = FloatField('Burst Factor', validators=[Optional(), NumberRange(min=1.0, max=10.0)], default=1.5)
    submit = SubmitField('Apply Rate Limits')
    
    def validate_download_mbps(self, field):
        if self.enabled.data and not field.data:
            raise ValidationError('Download limit is required when rate limiting is enabled.')
    
    def validate_upload_mbps(self, field):
        if self.enabled.data and not field.data:
            raise ValidationError('Upload limit is required when rate limiting is enabled.')