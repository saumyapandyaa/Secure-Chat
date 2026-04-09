from dataclasses import dataclass
from typing import Optional
import time

@dataclass
class PendingHandshake:
    session_init_id: str
    server_nonce: bytes
    created_at: float = time.time()

@dataclass
class ActiveSession:
    session_id: str
    client_to_server_key: bytes
    server_to_client_key: bytes
    client_nonce: bytes
    server_nonce: bytes
    last_client_seq: int = 0
    last_server_seq: int = 0
    established_at: float = time.time()
    active: bool = True
    client_id: Optional[str] = None
