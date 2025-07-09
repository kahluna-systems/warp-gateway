from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, IntegerField, BooleanField, SubmitField, FloatField, PasswordField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Length, ValidationError, Optional, Email, EqualTo


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


class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me', default=False)
    submit = SubmitField('Login')


class CreateUserForm(FlaskForm):
    """Form for creating new users"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=128, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    role = SelectField('Role', choices=[
        ('admin', 'Administrator'),
        ('operator', 'Operator'),
        ('viewer', 'Viewer')
    ], default='operator')
    submit = SubmitField('Create User')


class ChangePasswordForm(FlaskForm):
    """Form for changing user password"""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, max=128, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')