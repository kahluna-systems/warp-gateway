"""
Authentication routes — login, logout, user management, change password.
"""
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from database import db
from models_new import User, AuditLog

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.is_account_locked():
            flash('Account is locked due to too many failed attempts. Try again later.', 'error')
            return render_template('new/login.html')

        if user and user.check_password(password):
            user.reset_failed_attempts()
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user)
            AuditLog.log('login', f'User {username} logged in', user=user, ip_address=request.remote_addr)
            db.session.commit()

            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            if user:
                user.increment_failed_attempts()
                db.session.commit()
            AuditLog.log('failed_login', f'Failed login attempt for {username}', ip_address=request.remote_addr)
            db.session.commit()
            flash('Invalid username or password.', 'error')

    return render_template('new/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    AuditLog.log('logout', f'User {current_user.username} logged out', user=current_user)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not current_user.check_password(current_pw):
            flash('Current password is incorrect.', 'error')
        elif new_pw != confirm_pw:
            flash('New passwords do not match.', 'error')
        elif len(new_pw) < 8:
            flash('Password must be at least 8 characters.', 'error')
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            AuditLog.log('password_change', 'Password changed', user=current_user)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard.index'))

    return render_template('new/login.html')
