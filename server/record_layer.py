import json
import logging
import os
from cryptography.exceptions import InvalidTag

from server.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt, b64_encode, b64_decode
from server.models import ActiveSession

logger = logging.getLogger(__name__)

class ReplayError(Exception):
    pass

class IntegrityError(Exception):
    pass

def build_aad(session_id: str, seq: int) -> bytes:
    return f"{session_id}:{seq}".encode("utf-8")

def protect_outgoing_message(session: ActiveSession, payload: dict, direction: str) -> dict:
    if direction == "server_to_client":
        key = session.server_to_client_key
        session.last_server_seq += 1
        seq = session.last_server_seq
    else:
        key = session.client_to_server_key
        session.last_client_seq += 1
        seq = session.last_client_seq

    nonce = os.urandom(12)
    plaintext = json.dumps(payload).encode("utf-8")
    aad = build_aad(session.session_id, seq)
    ciphertext = aes_gcm_encrypt(key, nonce, plaintext, aad)

    return {
        "session_id": session.session_id,
        "seq": seq,
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
    }

def unprotect_incoming_message(session: ActiveSession, record: dict, direction: str) -> dict:
    seq = int(record["seq"])
    nonce = b64_decode(record["nonce"])
    ciphertext = b64_decode(record["ciphertext"])

    if direction == "client_to_server":
        if seq <= session.last_client_seq:
            logger.warning("Replay detected: session_id=%s seq=%s", session.session_id, seq)
            raise ReplayError("Replay or stale message detected")
        key = session.client_to_server_key
    else:
        if seq <= session.last_server_seq:
            logger.warning("Replay detected: session_id=%s seq=%s", session.session_id, seq)
            raise ReplayError("Replay or stale message detected")
        key = session.server_to_client_key

    aad = build_aad(session.session_id, seq)

    try:
        plaintext = aes_gcm_decrypt(key, nonce, ciphertext, aad)
    except InvalidTag as exc:
        logger.error("AES-GCM authentication failed for session_id=%s seq=%s", session.session_id, seq)
        raise IntegrityError("Ciphertext integrity/authentication check failed") from exc

    message = json.loads(plaintext.decode("utf-8"))

    if direction == "client_to_server":
        session.last_client_seq = seq
    else:
        session.last_server_seq = seq

    return message
