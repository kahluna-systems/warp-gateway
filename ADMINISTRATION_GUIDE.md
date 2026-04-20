# KahLuna WARP Gateway -- Administration Guide

## Day-to-Day Operations

This guide covers routine administration tasks after the gateway is deployed and the first-boot wizard has been completed.

---

## Accessing the Gateway

### CLI via SSH

```bash
ssh admin@<gateway-ip>
```

If the OS username doesn't match a gateway user, you'll be prompted for gateway credentials. After login, you're in exec mode:

```
kahluna-gw>
```

Type `enable` and enter the enable password to access privileged mode:

```
kahluna-gw> enable
Password:
kahluna-gw#
```

### CLI via Serial Console

Connect a USB-to-serial cable to the console port. Open a terminal at 115200 baud, 8N1:

```bash
screen /dev/ttyUSB0 115200
```

### Web UI

Open `http://<gateway-ip>:5000` in a browser. Log in with the admin credentials set during setup.

The web UI provides the same functionality as the CLI: dashboard, interface management, VPN networks, firewall rules, DHCP, DNS, diagnostics, and system status.

---

## Interface Management

### View Interfaces

```
kahluna-gw# show interfaces
```

### Assign a Role

```
kahluna-gw# configure terminal
kahluna-gw(config)# interface ens38
kahluna-gw(config-if)# role LAN
kahluna-gw(config-if)# ip address 10.246.247.1 255.255.255.0
kahluna-gw(config-if)# exit
```

### Set WAN to DHCP

```
kahluna-gw(config)# interface ens33
kahluna-gw(config-if)# role WAN
kahluna-gw(config-if)# ip address dhcp
kahluna-gw(config-if)# exit
```

### Disable an Interface

```
kahluna-gw(config-if)# shutdown
```

---

## VPN Management

### Create a VPN Network

```
kahluna-gw(config)# vpn network corporate
kahluna-gw(config-vpn)# type secure_internet
kahluna-gw(config-vpn)# subnet 10.100.0.0/24
kahluna-gw(config-vpn)# port 51820
kahluna-gw(config-vpn)# exit
```

### Add a Peer

```
kahluna-gw(config)# vpn network corporate
kahluna-gw(config-vpn)# peer laptop-john
```

The gateway generates keys, allocates an IP, and displays the client configuration. Share this with the user for their WireGuard client.

### View Peer Status

```
kahluna-gw# show vpn peers
Name         Network     IP          Status     Last Handshake       RX        TX
-----------  ----------  ----------  ---------  -------------------  --------  --------
laptop-john  corporate   10.100.0.2  Connected  2026-04-19 20:15:00  45.2 MB   12.1 MB
phone-jane   corporate   10.100.0.3  Offline    Never                0 B       0 B
```

### Set Rate Limits

```
kahluna-gw(config-vpn)# rate-limit 100 50
Rate limit set: 100 Mbps down / 50 Mbps up
```

### Remove a Peer

```
kahluna-gw(config-vpn)# no peer laptop-john
```

---

## Firewall Management

### View Current Rules

```
kahluna-gw# show firewall rules
```

### Add a Rule

```
kahluna-gw(config)# firewall
kahluna-gw(config-fw)# rule INPUT ACCEPT tcp any any 443
kahluna-gw(config-fw)# exit
```

### Add Port Forwarding

```
kahluna-gw(config-fw)# port-forward 8080 10.246.247.100 80 tcp
```

### Remove a Rule

```
kahluna-gw(config-fw)# no rule 5
```

---

## DHCP Management

### Configure DHCP

```
kahluna-gw(config)# dhcp
kahluna-gw(config-dhcp)# pool ens38 range 10.246.247.10 10.246.247.199
kahluna-gw(config-dhcp)# exit
```

### Add a Static Reservation

```
kahluna-gw(config-dhcp)# reservation aa:bb:cc:dd:ee:ff 10.246.247.50 printer
```

### View Leases

```
kahluna-gw# show dhcp leases
```

---

## DNS Management

### Add a Local Override

```
kahluna-gw(config)# dns
kahluna-gw(config-dns)# override intranet.company.com 10.246.247.10
kahluna-gw(config-dns)# exit
```

### Set Upstream Servers

```
kahluna-gw(config-dns)# upstream 1.1.1.1 8.8.8.8
```

---

## Saving Configuration

Changes made in configure mode are applied immediately but are not persisted across reboots until you save:

```
kahluna-gw# copy running-config startup-config
Running configuration saved to startup-config
```

To view the current configuration:

```
kahluna-gw# show running-config
```

---

## Diagnostics

### Ping

```
kahluna-gw> ping 8.8.8.8
```

### Traceroute

```
kahluna-gw> traceroute google.com
```

### DNS Lookup

```
kahluna-gw> nslookup api.kahluna.com
```

### Packet Capture (Privileged Mode)

```
kahluna-gw# capture ens33 tcp port 443 20
```

### Bandwidth Test (Privileged Mode)

```
kahluna-gw# iperf 10.0.0.1
```

---

## Central Management (KahLuna Nexus)

### Register with Platform Core

```
kahluna-gw(config)# nexus register <token> https://api.kahluna.com
```

After registration, the prompt changes to show the Nexus indicator:

```
kahluna-gw [nexus]#
```

### Check Registration Status

```
kahluna-gw# show nexus status
```

### Deregister

```
kahluna-gw(config)# nexus deregister
```

---

## System Management

### View System Health

```
kahluna-gw# show system health
```

### Change Hostname

```
kahluna-gw(config)# hostname new-name
```

### Restart the Gateway

```
kahluna-gw# reload
```

### Re-run Setup Wizard

```
kahluna-gw# setup
```

### Web UI Access Control

```
kahluna-gw(config)# webui listen all          # Listen on all interfaces
kahluna-gw(config)# webui listen localhost     # Localhost only
kahluna-gw(config)# webui listen ens38         # Specific interface
```

---

## Service Management (systemd)

The gateway runs as a systemd service:

```bash
sudo systemctl status warp-gateway    # Check status
sudo systemctl restart warp-gateway   # Restart
sudo systemctl stop warp-gateway      # Stop
sudo journalctl -u warp-gateway -f    # View logs
```

---

## Backup and Restore

### Backup

The running configuration can be exported as text:

```
kahluna-gw# show running-config
```

Copy the output and save it. This text can be pasted back into configure mode to reproduce the configuration.

The startup-config file is stored at:
- `/etc/warp-gateway/startup-config` (appliance)
- `/opt/warp-gateway/startup-config` (software install)

### Restore

Paste the saved configuration commands into configure mode, or replace the startup-config file and reboot.

---

## Password Recovery

If you forget the admin password, boot into recovery mode (GRUB menu option 2) and run:

```bash
cd /opt/warp-gateway
source venv/bin/activate
python3 -c "
from gateway import create_app
from database import db
from models_new import User
app = create_app()
with app.app_context():
    user = User.query.filter_by(username='admin').first()
    user.set_password('newpassword')
    db.session.commit()
    print('Password reset.')
"
```

---

## Functional Testing

Run the built-in test suite on the deployed gateway:

```bash
bash /opt/warp-gateway/tests/functional_test.sh
```

This verifies the database, CLI components, service layer, system dependencies, web UI, and network tools.
