"""
Rollback configuration store.
Manages numbered rollback files (rollback-00 through rollback-49)
with JSON metadata sidecars for commit history.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone

logger = logging.getLogger('warp.cli.rollback')

MAX_VERSIONS = 50


class RollbackStore:
    """
    Manages numbered rollback configuration files.
    Files are stored as rollback-00 through rollback-49 with
    JSON metadata sidecars (rollback-00.meta, etc.).
    """

    def __init__(self, base_dir: str = None):
        if base_dir:
            self._rollback_dir = os.path.join(base_dir, 'rollback')
        else:
            appliance_dir = '/etc/warp-gateway/rollback'
            if os.path.isdir('/etc/warp-gateway'):
                self._rollback_dir = appliance_dir
            else:
                app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                self._rollback_dir = os.path.join(app_dir, 'rollback')

    @property
    def rollback_dir(self) -> str:
        return self._rollback_dir

    def _version_path(self, version: int) -> str:
        return os.path.join(self._rollback_dir, f'rollback-{version:02d}')

    def _meta_path(self, version: int) -> str:
        return os.path.join(self._rollback_dir, f'rollback-{version:02d}.meta')

    def _ensure_dir(self):
        os.makedirs(self._rollback_dir, exist_ok=True)

    def rotate(self) -> None:
        """
        Shift all rollback files down by one (N -> N+1).
        Discard rollback-49 if it exists. Makes slot 00 available.
        """
        self._ensure_dir()

        # Discard the oldest if at max
        if os.path.exists(self._version_path(MAX_VERSIONS - 1)):
            os.remove(self._version_path(MAX_VERSIONS - 1))
        if os.path.exists(self._meta_path(MAX_VERSIONS - 1)):
            os.remove(self._meta_path(MAX_VERSIONS - 1))

        # Shift down from 48 to 0
        for i in range(MAX_VERSIONS - 2, -1, -1):
            src = self._version_path(i)
            dst = self._version_path(i + 1)
            if os.path.exists(src):
                os.rename(src, dst)
            src_meta = self._meta_path(i)
            dst_meta = self._meta_path(i + 1)
            if os.path.exists(src_meta):
                os.rename(src_meta, dst_meta)

    def store(self, config_text: str, username: str, source_ip: str) -> None:
        """
        Write config_text to rollback-00 and create the metadata sidecar.
        Caller must call rotate() first.
        """
        self._ensure_dir()

        with open(self._version_path(0), 'w') as f:
            f.write(config_text)

        meta = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'username': username,
            'source_ip': source_ip,
            'software_version': '0.1.0',
        }
        try:
            from models_new import GatewayConfig
            config = GatewayConfig.get_instance()
            meta['software_version'] = config.software_version
        except Exception:
            pass

        with open(self._meta_path(0), 'w') as f:
            json.dump(meta, f, indent=2)

    def load(self, version: int) -> str:
        """Load the config text from rollback-<version>. Returns None if missing."""
        path = self._version_path(version)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            logger.error(f'Failed to read {path}: {e}')
            return None

    def load_meta(self, version: int) -> dict:
        """Load the metadata sidecar. Returns None if missing."""
        path = self._meta_path(version)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f'Failed to read metadata {path}: {e}')
            return None

    def exists(self, version: int) -> bool:
        return os.path.isfile(self._version_path(version))

    def list_all(self) -> list:
        """
        Return a list of dicts for all available rollback versions.
        Sorted by version number ascending.
        """
        result = []
        for i in range(MAX_VERSIONS):
            path = self._version_path(i)
            if os.path.isfile(path):
                meta = self.load_meta(i) or {}
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                result.append({
                    'version': i,
                    'timestamp': meta.get('timestamp', '(no metadata)'),
                    'username': meta.get('username', '(no metadata)'),
                    'size': size,
                })
        return result

    def verify(self) -> list:
        """
        Check integrity of the rollback directory.
        Returns a list of warning strings.
        """
        warnings = []

        if not os.path.isdir(self._rollback_dir):
            return ['Rollback directory does not exist']

        for i in range(MAX_VERSIONS):
            config_exists = os.path.isfile(self._version_path(i))
            meta_exists = os.path.isfile(self._meta_path(i))

            if config_exists and not meta_exists:
                warnings.append(f'rollback-{i:02d}: config file exists but metadata sidecar is missing')
            elif meta_exists and not config_exists:
                warnings.append(f'rollback-{i:02d}: orphaned metadata sidecar (no config file)')

            if config_exists:
                try:
                    with open(self._version_path(i), 'r') as f:
                        content = f.read()
                    if not content.strip():
                        warnings.append(f'rollback-{i:02d}: config file is empty')
                except Exception as e:
                    warnings.append(f'rollback-{i:02d}: unreadable ({e})')

        return warnings
