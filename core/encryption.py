import secrets
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils.exceptions import ValueError, EncryptionError
from utils.logger import logger

def generate_key() -> bytes:
    key = secrets.token_bytes(32)
    logger.info("[+] Generated new 32-byte AES-256 key")
    return key

def encrypt(data: bytes, key: bytes) -> str:
    if not isinstance(data, bytes):
        msg = "[-] Data must be bytes"
        logger.error(msg)
        raise ValueError(msg)
    if not isinstance(key, bytes) or len(key) != 32:
        msg = "[-] Key must be 32 bytes (AES-256)"
        logger.error(msg)
        raise ValueError(msg)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    b64_data = base64.b64encode(nonce + ciphertext).decode()
    logger.info("[+] Data encrypted successfully")
    return b64_data

def decrypt(encrypted_data: str, key: bytes) -> bytes:
    if not isinstance(encrypted_data, str):
        msg = "[-] Encrypted data must be a string"
        logger.error(msg)
        raise ValueError(msg)
    if not isinstance(key, bytes) or len(key) != 32:
        msg = "[-] Key must be 32 bytes (AES-256)"
        logger.error(msg)
        raise ValueError(msg)

    try:
        raw = base64.b64decode(encrypted_data)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        logger.info("[+] Data decrypted successfully")
        return plaintext
    except Exception as e:
        msg = f"[-] Decryption failed: {e}"
        logger.error(msg)
        raise EncryptionError(msg)

def encrypt_file(filepath: str, key: bytes) -> str:
    file_path = Path(filepath)
    if not file_path.exists():
        msg = f"[-] File not found: {filepath}"
        logger.error(msg)
        raise EncryptionError(msg)
    if not isinstance(key, bytes) or len(key) != 32:
        msg = "[-] Invalid encryption key: must be 32 bytes (AES-256)"
        logger.error(msg)
        raise EncryptionError(msg)

    try:
        data = file_path.read_bytes()
        b64_data = encrypt(data, key)
        enc_path = file_path.with_suffix(file_path.suffix + ".enc")
        enc_path.write_text(b64_data)
        logger.info(f"[+] Encrypted file saved: {enc_path}")
        return str(enc_path)
    except Exception as e:
        msg = f"[-] File encryption failed for {filepath}: {e}"
        logger.error(msg)
        raise EncryptionError(msg)

def decrypt_file(encrypted_filepath: str, key: bytes) -> bytes:
    file_path = Path(encrypted_filepath)
    if not file_path.exists():
        msg = f"[-] Encrypted file not found: {encrypted_filepath}"
        logger.error(msg)
        raise EncryptionError(msg)
    if not isinstance(key, bytes) or len(key) != 32:
        msg = "[-] Invalid decryption key: must be 32 bytes (AES-256)"
        logger.error(msg)
        raise EncryptionError(msg)

    try:
        b64_data = file_path.read_text()
        plaintext = decrypt(b64_data, key)
        logger.info(f"[+] Decrypted file successfully: {encrypted_filepath}")
        return plaintext
    except Exception as e:
        msg = f"[-] File decryption failed for {encrypted_filepath}: {e}"
        logger.error(msg)
        raise EncryptionError(msg)
