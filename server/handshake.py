import logging
import os

from server.crypto_utils import (
    load_public_key_pem,
    get_server_public_key_fingerprint,
    rsa_decrypt,
    hkdf_derive_keys,
    b64_decode,
    b64_encode,
)
from server.session_manager import session_manager

logger = logging.getLogger(__name__)

SERVER_ID = "SecureChat-Server"

def start_handshake(client_id: str | None = None) -> dict:
    server_nonce = os.urandom(16)
    pending = session_manager.create_pending(server_nonce)

    public_key_pem = load_public_key_pem()
    fingerprint = get_server_public_key_fingerprint()

    logger.info("Handshake started for client_id=%s init_id=%s", client_id, pending.session_init_id)

    return {
        "server_id": SERVER_ID,
        "server_nonce": b64_encode(server_nonce),
        "server_public_key_pem": public_key_pem,
        "public_key_fingerprint": fingerprint,
        "cipher_selected": "AES-256-GCM",
        "kdf_selected": "HKDF-SHA256",
        "session_init_id": pending.session_init_id,
    }

def complete_handshake(payload: dict) -> dict:
    session_init_id = payload["session_init_id"]
    client_nonce = b64_decode(payload["client_nonce"])
    encrypted_premaster_secret = b64_decode(payload["encrypted_premaster_secret"])
    client_id = payload.get("client_id", "client1")

    pending = session_manager.get_pending(session_init_id)
    if pending is None:
        raise ValueError("Invalid or expired session_init_id")

    premaster_secret = rsa_decrypt(encrypted_premaster_secret)
    c2s_key, s2c_key = hkdf_derive_keys(
        premaster_secret=premaster_secret,
        client_nonce=client_nonce,
        server_nonce=pending.server_nonce,
    )

    session = session_manager.activate_session(
        client_to_server_key=c2s_key,
        server_to_client_key=s2c_key,
        client_nonce=client_nonce,
        server_nonce=pending.server_nonce,
        client_id=client_id,
    )
    session_manager.remove_pending(session_init_id)

    logger.info("Handshake completed successfully for session_id=%s", session.session_id)

    return {
        "status": "ok",
        "session_id": session.session_id,
        "message": "Secure session established",
    }
