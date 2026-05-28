"""
WiFi service layer — business logic for wireless management.
Coordinates between the system/wifi.py layer, the database, and the UI/CLI.
"""
import logging
from typing import Optional, List
from system import wifi as wifi_sys

logger = logging.getLogger("warp.services.wifi")


def get_wireless_interfaces() -> List[str]:
    """Get all wireless interface names on the system."""
    from system.interfaces import detect_all
    return [i.name for i in detect_all() if i.is_wireless]


def get_radio_info(interface: str) -> dict:
    """Get full radio information for a wireless interface."""
    if not wifi_sys.is_wireless(interface):
        return {"error": f"{interface} is not a wireless interface"}
    info = wifi_sys.get_radio_info(interface)
    return info.to_dict()


def scan_networks(interface: str) -> List[dict]:
    """Scan for available WiFi networks."""
    if not wifi_sys.is_wireless(interface):
        return []
    networks = wifi_sys.scan_networks(interface)
    return [n.to_dict() for n in networks]


def get_status(interface: str) -> dict:
    """
    Get the current WiFi status for an interface.
    Returns client connection status or AP status depending on mode.
    """
    if not wifi_sys.is_wireless(interface):
        return {"error": f"{interface} is not a wireless interface"}

    radio = wifi_sys.get_radio_info(interface)

    # Check if running as AP
    ap_status = wifi_sys.get_ap_status(interface)
    if ap_status.active:
        clients = wifi_sys.get_ap_clients(interface)
        return {
            "mode": "ap",
            "radio": radio.to_dict(),
            "ap": ap_status.to_dict(),
            "clients": [c.to_dict() for c in clients],
        }

    # Check if connected as client
    client_status = wifi_sys.get_client_status(interface)
    return {
        "mode": "client" if client_status.connected else "disconnected",
        "radio": radio.to_dict(),
        "connection": client_status.to_dict(),
    }


def connect(interface: str, ssid: str, password: str,
            security: str = "WPA2-PSK", use_dhcp: bool = True) -> dict:
    """
    Connect to a WiFi network in client mode.
    Optionally starts DHCP client for automatic IP assignment.
    """
    if not wifi_sys.is_wireless(interface):
        return {"success": False, "error": f"{interface} is not a wireless interface"}

    success = wifi_sys.connect_client(interface, ssid, password, security)

    if not success:
        return {"success": False, "error": "Failed to start wpa_supplicant"}

    # Start DHCP client if requested
    if use_dhcp:
        from system.commander import run
        # Give wpa_supplicant a moment to associate
        import time
        time.sleep(3)
        run(["dhclient", "-v", interface], sudo=True, timeout=30)

    return {"success": True, "message": f"Connecting to '{ssid}' on {interface}"}


def disconnect(interface: str) -> dict:
    """Disconnect from the current WiFi network."""
    if not wifi_sys.is_wireless(interface):
        return {"success": False, "error": f"{interface} is not a wireless interface"}

    wifi_sys.disconnect_client(interface)
    return {"success": True, "message": f"Disconnected {interface}"}


def start_access_point(interface: str, ssid: str, password: str,
                       channel: int = 6, band: str = "2.4GHz",
                       security: str = "WPA2-PSK", hidden: bool = False,
                       max_clients: int = 32, gateway_ip: str = "10.0.0.1",
                       netmask: str = "255.255.255.0",
                       dhcp_start: str = "10.0.0.10",
                       dhcp_end: str = "10.0.0.200") -> dict:
    """
    Start a WiFi access point with DHCP server on the interface.
    This sets up the full AP stack: hostapd + static IP + DHCP.
    """
    if not wifi_sys.is_wireless(interface):
        return {"success": False, "error": f"{interface} is not a wireless interface"}

    # Check if AP mode is supported
    radio = wifi_sys.get_radio_info(interface)
    if not radio.supports_ap:
        return {"success": False, "error": f"{interface} does not support AP mode"}

    # Start hostapd
    success = wifi_sys.start_ap(
        interface=interface,
        ssid=ssid,
        password=password,
        channel=channel,
        band=band,
        security=security,
        hidden=hidden,
        max_clients=max_clients,
    )

    if not success:
        return {"success": False, "error": "Failed to start hostapd"}

    # Assign static IP to the AP interface
    from system.interfaces import set_ip, bring_up
    bring_up(interface)
    set_ip(interface, gateway_ip, netmask)

    # Start DHCP server on the AP interface
    from services.dhcp_service import setup_dhcp
    setup_dhcp(
        interface=interface,
        range_start=dhcp_start,
        range_end=dhcp_end,
        netmask=netmask,
        gateway=gateway_ip,
        dns_servers="1.1.1.1,8.8.8.8",
    )

    return {
        "success": True,
        "message": f"AP '{ssid}' started on {interface}",
        "gateway_ip": gateway_ip,
    }


def stop_access_point(interface: str) -> dict:
    """Stop the access point and associated DHCP server."""
    if not wifi_sys.is_wireless(interface):
        return {"success": False, "error": f"{interface} is not a wireless interface"}

    wifi_sys.stop_ap(interface)

    # Stop DHCP on this interface
    from services.dhcp_service import stop_dhcp
    try:
        stop_dhcp(interface)
    except Exception:
        pass  # May not have been running

    return {"success": True, "message": f"AP stopped on {interface}"}


def set_radio_config(interface: str, tx_power: Optional[float] = None,
                     channel: Optional[int] = None,
                     channel_width: Optional[str] = None,
                     country_code: Optional[str] = None) -> dict:
    """Apply radio configuration changes."""
    results = []

    if country_code:
        if wifi_sys.set_country(country_code):
            results.append(f"Country set to {country_code}")
        else:
            results.append(f"Failed to set country {country_code}")

    if channel:
        width = channel_width or "20"
        if wifi_sys.set_channel(interface, channel, width):
            results.append(f"Channel set to {channel} ({width} MHz)")
        else:
            results.append(f"Failed to set channel {channel}")

    if tx_power is not None:
        if wifi_sys.set_tx_power(interface, tx_power):
            results.append(f"TX power set to {tx_power} dBm")
        else:
            results.append(f"Failed to set TX power")

    return {"success": True, "results": results}
