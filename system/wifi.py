"""
WiFi radio management via iw, wpa_supplicant, and hostapd.
Provides low-level wireless operations: scanning, connecting, AP creation,
and radio statistics via nl80211/iw.
"""
import json
import os
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, List
from system.commander import run

logger = logging.getLogger("warp.system.wifi")


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class RadioInfo:
    """Physical radio capabilities and current state."""
    interface: str = ""
    phy: str = ""
    driver: str = ""
    chipset: str = ""
    firmware_version: str = ""
    bands: List[str] = field(default_factory=list)
    supported_modes: List[str] = field(default_factory=list)
    current_mode: str = ""  # managed, AP, monitor
    current_channel: Optional[int] = None
    current_frequency: Optional[int] = None  # MHz
    channel_width: Optional[str] = None  # 20/40/80/160 MHz
    tx_power: Optional[float] = None  # dBm
    tx_power_max: Optional[float] = None  # dBm
    country_code: str = ""
    supports_ap: bool = False
    supports_monitor: bool = False

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ScannedNetwork:
    """A WiFi network found during scanning."""
    ssid: str = ""
    bssid: str = ""
    frequency: int = 0  # MHz
    channel: int = 0
    signal: int = 0  # dBm
    signal_quality: int = 0  # 0-100%
    security: str = ""  # Open, WPA2-PSK, WPA3-SAE, WPA2/3, Enterprise
    band: str = ""  # 2.4GHz, 5GHz, 6GHz

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class ConnectionStatus:
    """Current WiFi connection state (client mode)."""
    connected: bool = False
    ssid: str = ""
    bssid: str = ""
    frequency: int = 0
    channel: int = 0
    signal: int = 0  # dBm
    signal_quality: int = 0  # 0-100%
    tx_rate: float = 0.0  # Mbps
    rx_rate: float = 0.0  # Mbps
    tx_bytes: int = 0
    rx_bytes: int = 0
    connected_time: int = 0  # seconds
    security: str = ""

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class APStatus:
    """Current AP state (hostapd mode)."""
    active: bool = False
    ssid: str = ""
    channel: int = 0
    frequency: int = 0
    band: str = ""
    security: str = ""
    clients_connected: int = 0
    hidden: bool = False

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class StationInfo:
    """A connected WiFi client (in AP mode)."""
    mac: str = ""
    signal: int = 0  # dBm
    tx_rate: float = 0.0  # Mbps
    rx_rate: float = 0.0  # Mbps
    tx_bytes: int = 0
    rx_bytes: int = 0
    connected_time: int = 0  # seconds
    inactive_time: int = 0  # ms

    def to_dict(self):
        return self.__dict__.copy()


# ── Radio Information ────────────────────────────────────────────────────────

def get_radio_info(interface: str) -> RadioInfo:
    """Get radio capabilities and current state for a wireless interface."""
    info = RadioInfo(interface=interface)

    # Get PHY name
    result = run(["iw", "dev", interface, "info"])
    if result.success:
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("wiphy"):
                info.phy = f"phy{line.split()[-1]}"
            elif line.startswith("type"):
                info.current_mode = line.split()[-1]
            elif line.startswith("channel"):
                match = re.match(r"channel\s+(\d+)\s+\((\d+)\s+MHz\).*width:\s+(\d+)", line)
                if match:
                    info.current_channel = int(match.group(1))
                    info.current_frequency = int(match.group(2))
                    info.channel_width = f"{match.group(3)} MHz"
            elif line.startswith("txpower"):
                match = re.search(r"([\d.]+)\s+dBm", line)
                if match:
                    info.tx_power = float(match.group(1))

    # Get PHY capabilities
    if info.phy:
        result = run(["iw", "phy", info.phy, "info"])
    else:
        result = run(["iw", "phy"])
    if result.success:
        _parse_phy_info(result.stdout, info)

    # Get driver info
    driver_result = run(["readlink", "-f", f"/sys/class/net/{interface}/device/driver"])
    if driver_result.success:
        info.driver = driver_result.stdout.split("/")[-1]

    # Get firmware version
    result = run(["ethtool", "-i", interface])
    if result.success:
        for line in result.stdout.split("\n"):
            if line.startswith("firmware-version:"):
                info.firmware_version = line.split(":", 1)[1].strip()

    # Get regulatory domain
    result = run(["iw", "reg", "get"])
    if result.success:
        match = re.search(r"country\s+(\w+):", result.stdout)
        if match:
            info.country_code = match.group(1)

    return info


def _parse_phy_info(output: str, info: RadioInfo):
    """Parse iw phy info output for capabilities."""
    in_band_section = False
    current_band = ""

    for line in output.split("\n"):
        stripped = line.strip()

        # Detect band sections
        if "Band 1:" in line or "2.4 GHz" in line.lower():
            current_band = "2.4GHz"
            if current_band not in info.bands:
                info.bands.append(current_band)
            in_band_section = True
        elif "Band 2:" in line or "5 GHz" in line.lower():
            current_band = "5GHz"
            if current_band not in info.bands:
                info.bands.append(current_band)
            in_band_section = True
        elif "Band 4:" in line or "6 GHz" in line.lower():
            current_band = "6GHz"
            if current_band not in info.bands:
                info.bands.append(current_band)
            in_band_section = True

        # Supported interface modes
        if "Supported interface modes:" in line:
            in_band_section = False
        elif stripped.startswith("* ") and not in_band_section:
            mode = stripped[2:].strip()
            if mode in ("AP", "managed", "monitor", "P2P-client", "P2P-GO", "mesh point"):
                if mode not in info.supported_modes:
                    info.supported_modes.append(mode)
                if mode == "AP":
                    info.supports_ap = True
                elif mode == "monitor":
                    info.supports_monitor = True

        # Max TX power
        if "Maximum TX power:" in stripped:
            match = re.search(r"([\d.]+)\s+dBm", stripped)
            if match:
                info.tx_power_max = float(match.group(1))


# ── Scanning ─────────────────────────────────────────────────────────────────

def scan_networks(interface: str) -> List[ScannedNetwork]:
    """Scan for available WiFi networks. Requires interface to be up."""
    # Ensure interface is up
    run(["ip", "link", "set", interface, "up"], sudo=True)

    result = run(["iw", "dev", interface, "scan"], sudo=True, timeout=30)
    if not result.success:
        logger.warning(f"WiFi scan failed on {interface}: {result.stderr}")
        return []

    return _parse_scan_results(result.stdout)


def _parse_scan_results(output: str) -> List[ScannedNetwork]:
    """Parse iw scan output into ScannedNetwork objects."""
    networks = []
    current = None

    for line in output.split("\n"):
        # New BSS entry
        match = re.match(r"BSS\s+([0-9a-f:]+)", line)
        if match:
            if current and current.ssid:
                networks.append(current)
            current = ScannedNetwork(bssid=match.group(1))
            continue

        if not current:
            continue

        stripped = line.strip()

        if stripped.startswith("SSID:"):
            current.ssid = stripped[5:].strip()
        elif stripped.startswith("freq:"):
            try:
                current.frequency = int(stripped[5:].strip())
                current.channel = _freq_to_channel(current.frequency)
                current.band = _freq_to_band(current.frequency)
            except ValueError:
                pass
        elif stripped.startswith("signal:"):
            match = re.search(r"(-?\d+\.?\d*)", stripped)
            if match:
                current.signal = int(float(match.group(1)))
                current.signal_quality = _dbm_to_quality(current.signal)
        elif "WPA" in stripped or "RSN" in stripped:
            current.security = _parse_security(stripped, current.security)

    # Don't forget the last one
    if current and current.ssid:
        networks.append(current)

    # Mark open networks
    for net in networks:
        if not net.security:
            net.security = "Open"

    # Sort by signal strength (strongest first)
    networks.sort(key=lambda n: n.signal, reverse=True)
    return networks


# ── Client Mode (wpa_supplicant) ─────────────────────────────────────────────

WPA_SUPPLICANT_CONF = "/etc/warp-gateway/wpa_supplicant-{interface}.conf"
WPA_SUPPLICANT_SERVICE = "wpa_supplicant@{interface}"


def connect_client(interface: str, ssid: str, password: str,
                   security: str = "WPA2-PSK") -> bool:
    """Connect to a WiFi network in client (managed) mode."""
    conf_path = WPA_SUPPLICANT_CONF.format(interface=interface)

    # Stop any existing hostapd on this interface
    stop_ap(interface)

    # Stop existing wpa_supplicant
    run(["systemctl", "stop", f"wpa_supplicant@{interface}"], sudo=True)
    run(["killall", "-q", "wpa_supplicant"], sudo=True)

    # Ensure interface is in managed mode
    run(["ip", "link", "set", interface, "down"], sudo=True)
    run(["iw", "dev", interface, "set", "type", "managed"], sudo=True)
    run(["ip", "link", "set", interface, "up"], sudo=True)

    # Generate wpa_supplicant config
    config = _generate_wpa_config(ssid, password, security)
    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    with open(conf_path, "w") as f:
        f.write(config)
    os.chmod(conf_path, 0o600)

    # Create systemd override for wpa_supplicant on this interface
    override_dir = f"/etc/systemd/system/wpa_supplicant@{interface}.service.d"
    os.makedirs(override_dir, exist_ok=True)
    with open(f"{override_dir}/override.conf", "w") as f:
        f.write(f"[Service]\nExecStart=\n"
                f"ExecStart=/sbin/wpa_supplicant -i{interface} "
                f"-c{conf_path} -Dnl80211,wext\n")

    run(["systemctl", "daemon-reload"], sudo=True)
    result = run(["systemctl", "start", f"wpa_supplicant@{interface}"], sudo=True)

    if not result.success:
        logger.error(f"wpa_supplicant start failed: {result.stderr}")
        return False

    # Enable on boot
    run(["systemctl", "enable", f"wpa_supplicant@{interface}"], sudo=True)

    logger.info(f"WiFi client connecting to '{ssid}' on {interface}")
    return True


def disconnect_client(interface: str) -> bool:
    """Disconnect from the current WiFi network."""
    run(["systemctl", "stop", f"wpa_supplicant@{interface}"], sudo=True)
    run(["systemctl", "disable", f"wpa_supplicant@{interface}"], sudo=True)
    run(["ip", "addr", "flush", "dev", interface], sudo=True)
    logger.info(f"WiFi client disconnected on {interface}")
    return True


def get_client_status(interface: str) -> ConnectionStatus:
    """Get current WiFi client connection status."""
    status = ConnectionStatus()

    result = run(["iw", "dev", interface, "link"])
    if not result.success or "Not connected" in result.stdout:
        return status

    status.connected = True

    for line in result.stdout.split("\n"):
        stripped = line.strip()
        if stripped.startswith("Connected to"):
            match = re.search(r"([0-9a-f:]+)", stripped)
            if match:
                status.bssid = match.group(1)
        elif stripped.startswith("SSID:"):
            status.ssid = stripped[5:].strip()
        elif stripped.startswith("freq:"):
            try:
                status.frequency = int(stripped[5:].strip())
                status.channel = _freq_to_channel(status.frequency)
            except ValueError:
                pass
        elif stripped.startswith("signal:"):
            match = re.search(r"(-?\d+)", stripped)
            if match:
                status.signal = int(match.group(1))
                status.signal_quality = _dbm_to_quality(status.signal)
        elif "tx bitrate:" in stripped.lower():
            match = re.search(r"([\d.]+)\s+MBit", stripped)
            if match:
                status.tx_rate = float(match.group(1))
        elif "rx bitrate:" in stripped.lower():
            match = re.search(r"([\d.]+)\s+MBit", stripped)
            if match:
                status.rx_rate = float(match.group(1))

    # Get traffic stats
    result = run(["cat", f"/sys/class/net/{interface}/statistics/tx_bytes"])
    if result.success:
        try:
            status.tx_bytes = int(result.stdout)
        except ValueError:
            pass
    result = run(["cat", f"/sys/class/net/{interface}/statistics/rx_bytes"])
    if result.success:
        try:
            status.rx_bytes = int(result.stdout)
        except ValueError:
            pass

    return status


# ── AP Mode (hostapd) ────────────────────────────────────────────────────────

HOSTAPD_CONF = "/etc/warp-gateway/hostapd-{interface}.conf"
HOSTAPD_SERVICE = "hostapd@{interface}"


def start_ap(interface: str, ssid: str, password: str, channel: int = 6,
             band: str = "2.4GHz", security: str = "WPA2-PSK",
             hidden: bool = False, max_clients: int = 32) -> bool:
    """Start a WiFi access point on the given interface."""
    conf_path = HOSTAPD_CONF.format(interface=interface)

    # Stop any existing client connection
    disconnect_client(interface)

    # Set interface to AP mode
    run(["ip", "link", "set", interface, "down"], sudo=True)
    run(["iw", "dev", interface, "set", "type", "__ap"], sudo=True)
    run(["ip", "link", "set", interface, "up"], sudo=True)

    # Determine hw_mode and channel based on band
    hw_mode = "g"  # 2.4GHz default
    if band == "5GHz":
        hw_mode = "a"
    elif band == "6GHz":
        hw_mode = "a"  # 6GHz also uses 'a' mode with HE

    # Generate hostapd config
    config = _generate_hostapd_config(
        interface=interface,
        ssid=ssid,
        password=password,
        channel=channel,
        hw_mode=hw_mode,
        security=security,
        hidden=hidden,
        max_clients=max_clients,
    )

    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    with open(conf_path, "w") as f:
        f.write(config)
    os.chmod(conf_path, 0o600)

    # Create systemd service for hostapd on this interface
    service_path = f"/etc/systemd/system/hostapd@{interface}.service"
    with open(service_path, "w") as f:
        f.write(f"""[Unit]
Description=WARP Gateway WiFi AP on %i
After=network.target warp-gateway.service

[Service]
Type=forking
PIDFile=/run/hostapd-{interface}.pid
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd-{interface}.pid {conf_path}
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""")

    run(["systemctl", "daemon-reload"], sudo=True)
    result = run(["systemctl", "start", f"hostapd@{interface}"], sudo=True)

    if not result.success:
        logger.error(f"hostapd start failed: {result.stderr}")
        return False

    run(["systemctl", "enable", f"hostapd@{interface}"], sudo=True)
    logger.info(f"WiFi AP '{ssid}' started on {interface} (ch {channel})")
    return True


def stop_ap(interface: str) -> bool:
    """Stop the access point on the given interface."""
    run(["systemctl", "stop", f"hostapd@{interface}"], sudo=True)
    run(["systemctl", "disable", f"hostapd@{interface}"], sudo=True)
    logger.info(f"WiFi AP stopped on {interface}")
    return True


def get_ap_status(interface: str) -> APStatus:
    """Get current AP status."""
    status = APStatus()

    # Check if hostapd is running
    result = run(["systemctl", "is-active", f"hostapd@{interface}"])
    if not result.success or result.stdout.strip() != "active":
        return status

    status.active = True

    # Read config for SSID and channel
    conf_path = HOSTAPD_CONF.format(interface=interface)
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ssid="):
                    status.ssid = line[5:]
                elif line.startswith("channel="):
                    try:
                        status.channel = int(line[8:])
                    except ValueError:
                        pass
                elif line.startswith("ignore_broadcast_ssid="):
                    status.hidden = line.split("=")[1].strip() == "1"
                elif line.startswith("hw_mode="):
                    mode = line[8:].strip()
                    status.band = "5GHz" if mode == "a" else "2.4GHz"

    # Count connected clients
    result = run(["iw", "dev", interface, "station", "dump"], sudo=True)
    if result.success:
        status.clients_connected = result.stdout.count("Station ")

    return status


def get_ap_clients(interface: str) -> List[StationInfo]:
    """Get list of connected WiFi clients (AP mode)."""
    clients = []

    result = run(["iw", "dev", interface, "station", "dump"], sudo=True)
    if not result.success:
        return clients

    current = None
    for line in result.stdout.split("\n"):
        match = re.match(r"Station\s+([0-9a-f:]+)", line)
        if match:
            if current:
                clients.append(current)
            current = StationInfo(mac=match.group(1))
            continue

        if not current:
            continue

        stripped = line.strip()
        if "signal:" in stripped:
            match = re.search(r"(-?\d+)", stripped)
            if match:
                current.signal = int(match.group(1))
        elif "tx bitrate:" in stripped:
            match = re.search(r"([\d.]+)\s+MBit", stripped)
            if match:
                current.tx_rate = float(match.group(1))
        elif "rx bitrate:" in stripped:
            match = re.search(r"([\d.]+)\s+MBit", stripped)
            if match:
                current.rx_rate = float(match.group(1))
        elif "tx bytes:" in stripped:
            match = re.search(r"(\d+)", stripped)
            if match:
                current.tx_bytes = int(match.group(1))
        elif "rx bytes:" in stripped:
            match = re.search(r"(\d+)", stripped)
            if match:
                current.rx_bytes = int(match.group(1))
        elif "connected time:" in stripped:
            match = re.search(r"(\d+)", stripped)
            if match:
                current.connected_time = int(match.group(1))
        elif "inactive time:" in stripped:
            match = re.search(r"(\d+)", stripped)
            if match:
                current.inactive_time = int(match.group(1))

    if current:
        clients.append(current)

    return clients


# ── Radio Configuration ──────────────────────────────────────────────────────

def set_tx_power(interface: str, power_dbm: float) -> bool:
    """Set transmit power in dBm."""
    # iw expects mBm (millidBm)
    mbm = int(power_dbm * 100)
    result = run(["iw", "dev", interface, "set", "txpower", "fixed", str(mbm)], sudo=True)
    return result.success


def set_channel(interface: str, channel: int, width: str = "20") -> bool:
    """Set the radio channel. Interface must be down or in AP mode."""
    ht_map = {"20": "HT20", "40": "HT40+", "80": "80MHz"}
    ht = ht_map.get(width, "HT20")
    result = run(["iw", "dev", interface, "set", "channel", str(channel), ht], sudo=True)
    return result.success


def set_country(country_code: str) -> bool:
    """Set the regulatory domain (country code)."""
    result = run(["iw", "reg", "set", country_code.upper()], sudo=True)
    return result.success


# ── Helper Functions ─────────────────────────────────────────────────────────

def _generate_wpa_config(ssid: str, password: str, security: str) -> str:
    """Generate wpa_supplicant configuration file content."""
    config = "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev\n"
    config += "update_config=1\n\n"

    if security == "WPA3-SAE":
        config += "network={\n"
        config += f'    ssid="{ssid}"\n'
        config += f'    sae_password="{password}"\n'
        config += "    key_mgmt=SAE\n"
        config += "    ieee80211w=2\n"
        config += "}\n"
    elif security == "WPA2-PSK" or security == "WPA2/3":
        config += "network={\n"
        config += f'    ssid="{ssid}"\n'
        config += f'    psk="{password}"\n'
        config += "    key_mgmt=WPA-PSK"
        if security == "WPA2/3":
            config += " SAE"
        config += "\n"
        config += "    proto=RSN\n"
        config += "    pairwise=CCMP\n"
        config += "}\n"
    else:
        # Open network
        config += "network={\n"
        config += f'    ssid="{ssid}"\n'
        config += "    key_mgmt=NONE\n"
        config += "}\n"

    return config


def _generate_hostapd_config(interface: str, ssid: str, password: str,
                              channel: int, hw_mode: str, security: str,
                              hidden: bool, max_clients: int) -> str:
    """Generate hostapd configuration file content."""
    config = f"""# KahLuna WARP Gateway — WiFi AP Configuration
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
wmm_enabled=1
macaddr_acl=0
ignore_broadcast_ssid={'1' if hidden else '0'}
max_num_sta={max_clients}

# 802.11n/ac support
ieee80211n=1
"""

    if hw_mode == "a":
        config += "ieee80211ac=1\n"

    # Security
    if security == "WPA2-PSK":
        config += f"""
# WPA2-PSK
auth_algs=1
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    elif security == "WPA3-SAE":
        config += f"""
# WPA3-SAE
auth_algs=1
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
sae_password={password}
ieee80211w=2
"""
    elif security == "WPA2/3":
        config += f"""
# WPA2/WPA3 Transitional
auth_algs=1
wpa=2
wpa_passphrase={password}
sae_password={password}
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
ieee80211w=1
"""
    # else: Open (no security block)

    return config


def _freq_to_channel(freq: int) -> int:
    """Convert frequency (MHz) to channel number."""
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    elif 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    elif 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def _freq_to_band(freq: int) -> str:
    """Convert frequency to band name."""
    if 2400 <= freq <= 2500:
        return "2.4GHz"
    elif 5000 <= freq <= 5900:
        return "5GHz"
    elif 5925 <= freq <= 7125:
        return "6GHz"
    return "Unknown"


def _dbm_to_quality(dbm: int) -> int:
    """Convert signal strength (dBm) to quality percentage (0-100)."""
    if dbm >= -50:
        return 100
    elif dbm <= -100:
        return 0
    else:
        return 2 * (dbm + 100)


def _parse_security(line: str, existing: str) -> str:
    """Parse security type from iw scan output."""
    if "WPA2" in line or "RSN" in line:
        if "SAE" in line:
            return "WPA3-SAE" if not existing else "WPA2/3"
        return "WPA2-PSK" if not existing else existing
    elif "WPA" in line:
        return "WPA-PSK" if not existing else existing
    return existing


def is_wireless(interface: str) -> bool:
    """Check if an interface is a wireless interface."""
    import subprocess
    try:
        result = subprocess.run(
            ["test", "-d", f"/sys/class/net/{interface}/wireless"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False
