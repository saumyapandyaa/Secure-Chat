import base64
import hashlib
import logging
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

KEY_DIR = Path("server/keys")
PRIVATE_KEY_PATH = KEY_DIR / "server_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "server_public.pem"

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))

def ensure_server_keys() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return

    logger.info("Generating new RSA server key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

def load_private_key():
    ensure_server_keys()
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )

def load_public_key():
    ensure_server_keys()
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())

def load_public_key_pem() -> str:
    ensure_server_keys()
    return PUBLIC_KEY_PATH.read_text(encoding="utf-8")

def fingerprint_public_key_pem(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()

def get_server_public_key_fingerprint() -> str:
    return fingerprint_public_key_pem(load_public_key_pem())

def rsa_encrypt_with_pem(public_key_pem: str, plaintext: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(ciphertext: bytes) -> bytes:
    private_key = load_private_key()
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def hkdf_derive_keys(premaster_secret: bytes, client_nonce: bytes, server_nonce: bytes) -> Tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=client_nonce + server_nonce,
        info=b"SecureChat v1 session",
    )
    material = hkdf.derive(premaster_secret)
    return material[:32], material[32:]

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
