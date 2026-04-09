import logging
import uuid
from typing import Dict, Optional

from server.models import PendingHandshake, ActiveSession

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self) -> None:
        self.pending: Dict[str, PendingHandshake] = {}
        self.active: Dict[str, ActiveSession] = {}

    def create_pending(self, server_nonce: bytes) -> PendingHandshake:
        session_init_id = str(uuid.uuid4())
        pending = PendingHandshake(session_init_id=session_init_id, server_nonce=server_nonce)
        self.pending[session_init_id] = pending
        logger.info("Pending handshake created: %s", session_init_id)
        return pending

    def get_pending(self, session_init_id: str) -> Optional[PendingHandshake]:
        return self.pending.get(session_init_id)

    def remove_pending(self, session_init_id: str) -> None:
        self.pending.pop(session_init_id, None)

    def activate_session(
        self,
        client_to_server_key: bytes,
        server_to_client_key: bytes,
        client_nonce: bytes,
        server_nonce: bytes,
        client_id: str | None = None,
    ) -> ActiveSession:
        session_id = str(uuid.uuid4())
        session = ActiveSession(
            session_id=session_id,
            client_to_server_key=client_to_server_key,
            server_to_client_key=server_to_client_key,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            client_id=client_id,
        )
        self.active[session_id] = session
        logger.info("Session activated: %s", session_id)
        return session

    def get_active(self, session_id: str) -> Optional[ActiveSession]:
        return self.active.get(session_id)

    def close_session(self, session_id: str) -> bool:
        session = self.active.get(session_id)
        if not session:
            return False
        session.active = False
        del self.active[session_id]
        logger.info("Session closed: %s", session_id)
        return True

session_manager = SessionManager()
