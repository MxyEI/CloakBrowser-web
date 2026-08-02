"""Authenticated encryption for environment runtime secrets."""

from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_BYTES = 12


class SecretCryptoError(RuntimeError):
    pass


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise SecretCryptoError("secret envelope encoding is invalid") from exc


def _aad(organization_id: str, environment_id: str, kind: str, version: int) -> bytes:
    return (
        f"cloakbrowser:environment-secret:v1:{organization_id}:{environment_id}:"
        f"{kind}:{version}"
    ).encode("ascii")


def encrypt_environment_secret(
    master_key: bytes,
    organization_id: str,
    environment_id: str,
    kind: str,
    version: int,
    plaintext: str,
) -> str:
    if len(master_key) != 32 or version < 1 or not plaintext:
        raise SecretCryptoError("secret encryption parameters are invalid")
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(master_key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        _aad(organization_id, environment_id, kind, version),
    )
    return f"v1.{_encode(nonce + ciphertext)}"


def decrypt_environment_secret(
    master_key: bytes,
    organization_id: str,
    environment_id: str,
    kind: str,
    version: int,
    envelope: str,
) -> str:
    if len(master_key) != 32 or version < 1 or not envelope.startswith("v1."):
        raise SecretCryptoError("secret envelope is invalid")
    payload = _decode(envelope[3:])
    if len(payload) <= NONCE_BYTES + 16:
        raise SecretCryptoError("secret envelope is truncated")
    try:
        plaintext = AESGCM(master_key).decrypt(
            payload[:NONCE_BYTES],
            payload[NONCE_BYTES:],
            _aad(organization_id, environment_id, kind, version),
        )
        return plaintext.decode("utf-8")
    except Exception as exc:
        raise SecretCryptoError("secret envelope could not be decrypted") from exc
