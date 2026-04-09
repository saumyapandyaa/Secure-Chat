import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.client import SecureClient, FINGERPRINT_FILE

def main() -> None:
    original = FINGERPRINT_FILE.read_text(encoding="utf-8")
    try:
        FINGERPRINT_FILE.write_text("deadbeef" * 8, encoding="utf-8")
        client = SecureClient()
        client.start_handshake()
    except Exception as exc:
        print("[EXPECTED FAILURE]", exc)
    finally:
        FINGERPRINT_FILE.write_text(original, encoding="utf-8")

if __name__ == "__main__":
    main()
