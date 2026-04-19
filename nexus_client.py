"""
KahLuna Nexus Platform Integration
Handles gateway registration, heartbeats, and config sync with platform-core.
"""
import json
import os
import time
import logging
import threading
import requests
from pathlib import Path

logger = logging.getLogger('warp.nexus')

NEXUS_CONFIG_FILE = "nexus_config.json"


class NexusClient:
    """Client for communicating with KahLuna Platform Core."""

    def __init__(self, config_path: str = NEXUS_CONFIG_FILE):
        self.config_path = config_path
        self.config = self._load_config()
        self._heartbeat_thread = None
        self._running = False

    def _load_config(self) -> dict:
        """Load nexus connection config from file."""
        if os.path.exists(self.config_path):
            with open(self.config_path) as f:
                return json.load(f)
        return {}

    def _save_config(self):
        """Save nexus connection config to file."""
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    @property
    def is_registered(self) -> bool:
        return bool(self.config.get("service_id") and self.config.get("api_key"))

    @property
    def platform_url(self) -> str:
        return self.config.get("platform_url", "")

    @property
    def api_key(self) -> str:
        return self.config.get("api_key", "")

    @property
    def service_id(self) -> str:
        return self.config.get("service_id", "")

    def claim_provisioning_token(self, token: str, gateway_name: str,
                                  gateway_url: str, platform_url: str,
                                  version: str = "0.1.0") -> dict:
        """Claim a provisioning token to register this gateway with platform-core."""
        url = f"{platform_url}/api/v1/provisioning/claim"
        payload = {
            "token": token,
            "name": gateway_name,
            "service_type": "warp-gateway",
            "base_url": gateway_url,
            "version": version,
            "health_endpoint": "/health",
        }

        try:
            resp = requests.post(url, json=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            # Save registration info
            self.config = {
                "platform_url": data.get("platform_url", platform_url),
                "service_id": data["service_id"],
                "tenant_id": data["tenant_id"],
                "site_id": data.get("site_id"),
                "api_key": data["api_key"],
                "gateway_config": data.get("gateway_config", {}),
                "registered_at": time.time(),
                "gateway_name": gateway_name,
            }
            self._save_config()

            return {"status": "registered", "service_id": data["service_id"]}

        except requests.exceptions.HTTPError as e:
            return {"status": "error", "detail": str(e), "response": e.response.text if e.response else None}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "detail": f"Cannot reach platform at {platform_url}"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def send_heartbeat(self) -> dict:
        """Send a heartbeat to platform-core to report this gateway is alive."""
        if not self.is_registered:
            return {"status": "not_registered"}

        url = f"{self.platform_url}/api/v1/services/{self.service_id}/heartbeat"
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        payload = {"status": "online", "version": "0.1.0"}

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def start_heartbeat_loop(self, interval_seconds: int = 60):
        """Start a background thread that sends periodic heartbeats."""
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        self._running = True

        def _loop():
            while self._running:
                if self.is_registered:
                    result = self.send_heartbeat()
                    if result["status"] != "ok":
                        logger.warning(f"Heartbeat failed: {result.get('detail', 'unknown')}")
                time.sleep(interval_seconds)

        self._heartbeat_thread = threading.Thread(target=_loop, daemon=True)
        self._heartbeat_thread.start()
        logger.info(f"Heartbeat loop started (every {interval_seconds}s)")

    def stop_heartbeat_loop(self):
        """Stop the heartbeat background thread."""
        self._running = False

    def get_status(self) -> dict:
        """Get the current nexus registration status."""
        if not self.is_registered:
            return {
                "registered": False,
                "platform_url": None,
                "message": "Gateway not registered with KahLuna Nexus",
            }
        return {
            "registered": True,
            "platform_url": self.platform_url,
            "service_id": self.service_id,
            "tenant_id": self.config.get("tenant_id"),
            "site_id": self.config.get("site_id"),
            "gateway_name": self.config.get("gateway_name"),
        }

    def deregister(self) -> dict:
        """Deregister this gateway from platform-core."""
        if not self.is_registered:
            return {"status": "not_registered"}

        url = f"{self.platform_url}/api/v1/services/{self.service_id}"
        headers = {"X-API-Key": self.api_key}

        try:
            resp = requests.delete(url, headers=headers, timeout=10)
            resp.raise_for_status()
        except Exception:
            pass  # Best effort

        # Clear local config
        self.config = {}
        self._save_config()
        self.stop_heartbeat_loop()
        return {"status": "deregistered"}


# Global instance
nexus = NexusClient()
