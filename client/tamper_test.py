import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.client import SecureClient
from server.crypto_utils import b64_decode, b64_encode

SERVER_URL = "http://127.0.0.1:5000"

def main() -> None:
    client = SecureClient()
    client.start_handshake()

    record = client.encrypt_record("This message will be tampered with")

    raw = bytearray(b64_decode(record["ciphertext"]))
    raw[0] ^= 0x01
    record["ciphertext"] = b64_encode(bytes(raw))

    response = requests.post(f"{SERVER_URL}/api/message/send", json=record, timeout=10)
    print("Status:", response.status_code)
    print(json.dumps(response.json(), indent=2))

    client.close()

if __name__ == "__main__":
    main()
