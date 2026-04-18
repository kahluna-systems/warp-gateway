"""
Connected clients routes — unified view of all LAN + VPN clients.
"""
from flask import Blueprint, render_template
from flask_login import login_required
from services import client_service

clients_bp = Blueprint('clients', __name__, url_prefix='/clients')


@clients_bp.route('/')
@login_required
def index():
    clients = client_service.get_all_clients()
    counts = client_service.get_client_counts()
    return render_template('new/clients.html', clients=clients, counts=counts)
