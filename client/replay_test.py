import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.client import SecureClient

SERVER_URL = "http://127.0.0.1:5000"

def main() -> None:
    client = SecureClient()
    client.start_handshake()

    record = client.encrypt_record("This message will be replayed")

    r1 = requests.post(f"{SERVER_URL}/api/message/send", json=record, timeout=10)
    print("First send:", r1.status_code)
    print(json.dumps(r1.json(), indent=2))

    r2 = requests.post(f"{SERVER_URL}/api/message/send", json=record, timeout=10)
    print("Replay send:", r2.status_code)
    print(json.dumps(r2.json(), indent=2))

    client.close()

if __name__ == "__main__":
    main()
