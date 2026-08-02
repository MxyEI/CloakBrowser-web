"""Password, session, and CSRF primitives for the cloud service."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .constants import AGENT_TOKEN_PREFIX, LEASE_TOKEN_PREFIX, TASK_TOKEN_PREFIX

SESSION_COOKIE = "cloak_cloud_session"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise ValueError("enter a valid email address")
    return email


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerifyMismatchError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def session_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_agent_token() -> str:
    return f"{AGENT_TOKEN_PREFIX}{secrets.token_urlsafe(48)}"


def agent_token_digest(token: str) -> str:
    return hashlib.sha256(f"agent:{token}".encode("utf-8")).hexdigest()


def new_lease_token() -> str:
    return f"{LEASE_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def lease_token_digest(token: str) -> str:
    return hashlib.sha256(f"lease:{token}".encode("utf-8")).hexdigest()


def new_task_token() -> str:
    return f"{TASK_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def task_token_digest(token: str) -> str:
    return hashlib.sha256(f"task:{token}".encode("utf-8")).hexdigest()


def csrf_token(secret_key: str, session_token: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"),
        f"csrf:{session_token}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def csrf_matches(secret_key: str, session_token: str, supplied: str) -> bool:
    return bool(supplied) and hmac.compare_digest(
        csrf_token(secret_key, session_token), supplied
    )
