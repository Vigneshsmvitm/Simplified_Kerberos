import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000,
        dklen=32
    )


def generate_key() -> bytes:
    """
    Generate a random 256-bit AES key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt(data: str, key: bytes) -> str:
    """
    Encrypt a string using AES-256-GCM.
    Returns Base64 encoded ciphertext.
    """

    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        data.encode("utf-8"),
        None
    )

    # Store nonce + ciphertext together
    encrypted_data = nonce + ciphertext

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt Base64 encoded AES-GCM ciphertext.
    """

    encrypted_bytes = base64.b64decode(encrypted_data)

    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")