"""
Confirmed commit timer for auto-rollback.
If the operator doesn't confirm within the specified time,
the system automatically reverts to the previous configuration.
"""
import logging
import threading
import time

logger = logging.getLogger('warp.cli.commit')


class ConfirmedCommitTimer:
    """
    Background timer for confirmed commits.
    If not cancelled within the specified duration, triggers auto-rollback.
    """

    def __init__(self):
        self._timer = None
        self._expiry = None
        self._lock = threading.Lock()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._timer is not None and self._timer.is_alive()

    @property
    def remaining(self) -> int:
        """Return remaining seconds before auto-rollback, or 0 if inactive."""
        with self._lock:
            if self._expiry is None:
                return 0
            left = self._expiry - time.time()
            return max(0, int(left))

    def start(self, minutes: int, callback) -> None:
        """
        Start the auto-rollback timer.

        Args:
            minutes: Duration in minutes (1-60).
            callback: Function to call when the timer expires.
        """
        with self._lock:
            # Cancel any existing timer
            if self._timer is not None:
                self._timer.cancel()

            seconds = minutes * 60
            self._expiry = time.time() + seconds
            self._timer = threading.Timer(seconds, self._on_expire, args=[callback])
            self._timer.daemon = True
            self._timer.start()

        logger.info(f'Confirmed commit timer started: {minutes} minutes')

    def cancel(self) -> None:
        """Cancel the active timer."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
                self._expiry = None
        logger.info('Confirmed commit timer cancelled')

    def _on_expire(self, callback):
        """Called when the timer expires."""
        with self._lock:
            self._timer = None
            self._expiry = None

        logger.warning('Confirmed commit timer expired -- triggering auto-rollback')
        try:
            callback()
        except Exception as e:
            logger.error(f'Auto-rollback failed: {e}')
