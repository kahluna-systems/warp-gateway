"""
CLI session manager.
Handles authentication, idle timeouts, concurrent session tracking, and audit logging.
"""
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger('warp.cli.session')


@dataclass
class SessionInfo:
    """Information about an active CLI session."""
    session_id: str
    user_id: int
    username: str
    source_ip: str
    connection_type: str  # 'ssh' or 'console'
    current_mode: str = 'exec'
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)


class SessionManager:
    """Manages CLI session lifecycle."""

    def __init__(self, idle_timeout: int = 600):
        self.idle_timeout = idle_timeout  # 10 minutes default
        self._active_sessions: dict[str, SessionInfo] = {}

    def authenticate(self, username: str, password: str):
        """
        Authenticate against the User model. Respects account lockout.

        Returns:
            User instance on success, None on failure.
        """
        from models_new import User
        from database import db

        user = User.query.filter_by(username=username).first()
        if not user:
            logger.warning(f'CLI login failed: unknown user "{username}"')
            return None

        if user.is_account_locked():
            logger.warning(f'CLI login failed: account locked for "{username}"')
            return None

        if not user.check_password(password):
            user.increment_failed_attempts()
            db.session.commit()
            logger.warning(f'CLI login failed: bad password for "{username}" '
                           f'(attempt {user.failed_login_attempts})')
            return None

        user.reset_failed_attempts()
        db.session.commit()
        logger.info(f'CLI login successful: "{username}"')
        return user

    def create_session(self, user, source_ip: str, conn_type: str) -> str:
        """
        Create a new CLI session and log it to AuditLog.

        Returns:
            session_id string.
        """
        from models_new import AuditLog
        from database import db

        session_id = str(uuid.uuid4())
        info = SessionInfo(
            session_id=session_id,
            user_id=user.id,
            username=user.username,
            source_ip=source_ip,
            connection_type=conn_type,
        )
        self._active_sessions[session_id] = info

        AuditLog.log(
            action='cli_session_start',
            details=f'CLI session started via {conn_type} from {source_ip}',
            user=user,
            ip_address=source_ip,
        )
        db.session.commit()

        logger.info(f'CLI session created: {session_id} ({user.username} via {conn_type})')
        return session_id

    def end_session(self, session_id: str) -> None:
        """End a CLI session and log it."""
        from models_new import AuditLog
        from database import db

        info = self._active_sessions.pop(session_id, None)
        if info:
            AuditLog.log(
                action='cli_session_end',
                details=f'CLI session ended ({info.connection_type})',
                ip_address=info.source_ip,
            )
            db.session.commit()
            logger.info(f'CLI session ended: {session_id} ({info.username})')

    def check_idle(self, session_id: str) -> bool:
        """Return True if the session has exceeded the idle timeout."""
        info = self._active_sessions.get(session_id)
        if not info:
            return True
        return (time.time() - info.last_activity) > self.idle_timeout

    def touch(self, session_id: str) -> None:
        """Reset the idle timer for a session."""
        info = self._active_sessions.get(session_id)
        if info:
            info.last_activity = time.time()

    def update_mode(self, session_id: str, mode: str) -> None:
        """Update the current mode for a session."""
        info = self._active_sessions.get(session_id)
        if info:
            info.current_mode = mode

    def get_configure_sessions(self) -> list:
        """Return sessions currently in configure mode (for conflict warning)."""
        return [
            info for info in self._active_sessions.values()
            if info.current_mode.startswith('config')
        ]

    def record_command(self, session_id: str, command: str) -> None:
        """Log a configuration command to AuditLog."""
        from models_new import AuditLog
        from database import db

        info = self._active_sessions.get(session_id)
        if not info:
            return

        AuditLog.log(
            action='cli_command',
            details=command,
            ip_address=info.source_ip,
        )
        db.session.commit()

    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """Get session info by ID."""
        return self._active_sessions.get(session_id)

    @property
    def active_count(self) -> int:
        """Return the number of active sessions."""
        return len(self._active_sessions)
