import json
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.crypto_utils import (
    b64_encode,
    b64_decode,
    fingerprint_public_key_pem,
    hkdf_derive_keys,
    rsa_encrypt_with_pem,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)

SERVER_URL = "http://127.0.0.1:5000"
FINGERPRINT_FILE = Path(__file__).resolve().parent / "pinned_server_fingerprint.txt"

def load_expected_fingerprint() -> str:
    value = FINGERPRINT_FILE.read_text(encoding="utf-8").strip()
    if not value or value == "PASTE_SERVER_FINGERPRINT_HERE":
        raise RuntimeError(
            "Open client/pinned_server_fingerprint.txt and paste the server fingerprint into it first."
        )
    return value

class SecureClient:
    def __init__(self) -> None:
        self.client_id = "client1"
        self.session_id = None
        self.client_to_server_key = None
        self.server_to_client_key = None
        self.client_seq = 0
        self.server_seq = 0

    def start_handshake(self) -> None:
        expected_fingerprint = load_expected_fingerprint()

        r1 = requests.post(
            f"{SERVER_URL}/api/handshake/start",
            json={"client_id": self.client_id, "supported_kdf": "HKDF-SHA256", "supported_cipher": "AES-256-GCM"},
            timeout=10,
        )
        r1.raise_for_status()
        server_hello = r1.json()

        server_public_key_pem = server_hello["server_public_key_pem"]
        actual_fingerprint = fingerprint_public_key_pem(server_public_key_pem)

        if actual_fingerprint != expected_fingerprint:
            raise RuntimeError(
                f"Server fingerprint mismatch.\nExpected: {expected_fingerprint}\nActual:   {actual_fingerprint}"
            )

        server_nonce = b64_decode(server_hello["server_nonce"])
        client_nonce = os.urandom(16)
        premaster_secret = os.urandom(32)
        encrypted_premaster = rsa_encrypt_with_pem(server_public_key_pem, premaster_secret)

        r2 = requests.post(
            f"{SERVER_URL}/api/handshake/complete",
            json={
                "session_init_id": server_hello["session_init_id"],
                "client_id": self.client_id,
                "client_nonce": b64_encode(client_nonce),
                "encrypted_premaster_secret": b64_encode(encrypted_premaster),
            },
            timeout=10,
        )
        r2.raise_for_status()
        result = r2.json()

        c2s_key, s2c_key = hkdf_derive_keys(
            premaster_secret=premaster_secret,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        self.session_id = result["session_id"]
        self.client_to_server_key = c2s_key
        self.server_to_client_key = s2c_key

        print("[OK] Handshake complete")
        print("Session ID:", self.session_id)

    def encrypt_record(self, message: str) -> dict:
        self.client_seq += 1
        seq = self.client_seq
        nonce = os.urandom(12)
        aad = f"{self.session_id}:{seq}".encode("utf-8")
        plaintext = json.dumps({
            "type": "chat",
            "sender": self.client_id,
            "message": message,
            "timestamp": int(time.time()),
        }).encode("utf-8")
        ciphertext = aes_gcm_encrypt(self.client_to_server_key, nonce, plaintext, aad)

        return {
            "session_id": self.session_id,
            "seq": seq,
            "nonce": b64_encode(nonce),
            "ciphertext": b64_encode(ciphertext),
        }

    def decrypt_server_reply(self, record: dict) -> dict:
        seq = int(record["seq"])
        if seq <= self.server_seq:
            raise RuntimeError("Replay detected in server reply")

        aad = f"{self.session_id}:{seq}".encode("utf-8")
        plaintext = aes_gcm_decrypt(
            self.server_to_client_key,
            b64_decode(record["nonce"]),
            b64_decode(record["ciphertext"]),
            aad,
        )
        self.server_seq = seq
        return json.loads(plaintext.decode("utf-8"))

    def send_message(self, message: str) -> None:
        record = self.encrypt_record(message)
        response = requests.post(
            f"{SERVER_URL}/api/message/send",
            json=record,
            timeout=10,
        )
        print("Server status:", response.status_code)
        body = response.json()
        print("Server JSON:", json.dumps(body, indent=2))

        if body.get("status") == "ok":
            reply_plaintext = self.decrypt_server_reply(body["reply_record"])
            print("[OK] Decrypted server reply:", json.dumps(reply_plaintext, indent=2))

    def close(self) -> None:
        if not self.session_id:
            return
        requests.post(f"{SERVER_URL}/api/session/close", json={"session_id": self.session_id}, timeout=10)
        print("[OK] Session closed")

def main() -> None:
    client = SecureClient()
    client.start_handshake()
    client.send_message("Hello from SecureChat client")
    client.close()

if __name__ == "__main__":
    main()
