"""Encryption and safe archive helpers for opaque browser profile snapshots."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import secrets
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SNAPSHOT_MAGIC = b"CBSNAP1\x00"
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250_000
_LOCK_FILES = {
    "DevToolsActivePort",
    "SingletonCookie",
    "SingletonLock",
    "SingletonSocket",
}


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class SnapshotArtifact:
    path: Path
    size: int
    plaintext_size: int
    sha256: str


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError) as exc:
        raise SnapshotError("snapshot key encoding is invalid") from exc


def encode_snapshot_key(value: bytes) -> str:
    if len(value) != 32:
        raise SnapshotError("snapshot keys must contain 32 bytes")
    return _b64encode(value)


def decode_snapshot_key(value: str) -> bytes:
    decoded = _b64decode(value)
    if len(decoded) != 32:
        raise SnapshotError("snapshot key must contain 32 bytes")
    return decoded


def _key_aad(organization_id: str, environment_id: str) -> bytes:
    return f"cloakbrowser:key:v1:{organization_id}:{environment_id}".encode("ascii")


def wrap_snapshot_key(
    master_key: bytes,
    organization_id: str,
    environment_id: str,
    snapshot_key: bytes,
) -> str:
    if len(master_key) != 32 or len(snapshot_key) != 32:
        raise SnapshotError("snapshot encryption keys must contain 32 bytes")
    nonce = secrets.token_bytes(NONCE_BYTES)
    encrypted = AESGCM(master_key).encrypt(
        nonce,
        snapshot_key,
        _key_aad(organization_id, environment_id),
    )
    return f"v1.{_b64encode(nonce + encrypted)}"


def unwrap_snapshot_key(
    master_key: bytes,
    organization_id: str,
    environment_id: str,
    envelope: str,
) -> bytes:
    if len(master_key) != 32 or not envelope.startswith("v1."):
        raise SnapshotError("snapshot key envelope is invalid")
    payload = _b64decode(envelope[3:])
    if len(payload) <= NONCE_BYTES + TAG_BYTES:
        raise SnapshotError("snapshot key envelope is truncated")
    try:
        value = AESGCM(master_key).decrypt(
            payload[:NONCE_BYTES],
            payload[NONCE_BYTES:],
            _key_aad(organization_id, environment_id),
        )
    except Exception as exc:
        raise SnapshotError("snapshot key could not be decrypted") from exc
    if len(value) != 32:
        raise SnapshotError("snapshot key has an invalid length")
    return value


def snapshot_aad(environment_id: str, version: int) -> bytes:
    return f"cloakbrowser:snapshot:v1:{environment_id}:{version}".encode("ascii")


def _archive_filter(info: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
    if info.name.rsplit("/", 1)[-1] in _LOCK_FILES:
        return None
    if info.issym() or info.islnk() or info.isdev() or info.isfifo():
        return None
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _write_encrypted_file(
    source: Path,
    destination: Path,
    key: bytes,
    aad: bytes,
) -> SnapshotArtifact:
    nonce = secrets.token_bytes(NONCE_BYTES)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    digest = hashlib.sha256()
    plaintext_size = source.stat().st_size
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as source_handle, destination.open("xb") as output:
            try:
                os.chmod(destination, 0o600)
            except OSError:
                pass
            header = SNAPSHOT_MAGIC + nonce
            output.write(header)
            digest.update(header)
            while True:
                block = source_handle.read(CHUNK_BYTES)
                if not block:
                    break
                encrypted = encryptor.update(block)
                output.write(encrypted)
                digest.update(encrypted)
            final = encryptor.finalize()
            if final:
                output.write(final)
                digest.update(final)
            output.write(encryptor.tag)
            digest.update(encryptor.tag)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return SnapshotArtifact(
        path=destination,
        size=destination.stat().st_size,
        plaintext_size=plaintext_size,
        sha256=digest.hexdigest(),
    )


def create_encrypted_snapshot(
    browser_data_dir: Path,
    destination: Path,
    key: bytes,
    environment_id: str,
    version: int,
    *,
    max_snapshot_bytes: int,
) -> SnapshotArtifact:
    if len(key) != 32:
        raise SnapshotError("snapshot key must contain 32 bytes")
    if not browser_data_dir.is_dir():
        raise SnapshotError("browser data directory does not exist")
    archive_path = destination.with_name(f".{destination.name}.tar.gz")
    archive_path.unlink(missing_ok=True)
    destination.unlink(missing_ok=True)
    try:
        with tarfile.open(archive_path, "w:gz", compresslevel=6) as archive:
            for child in sorted(browser_data_dir.iterdir(), key=lambda item: item.name):
                archive.add(child, arcname=child.name, recursive=True, filter=_archive_filter)
        try:
            os.chmod(archive_path, 0o600)
        except OSError:
            pass
        if archive_path.stat().st_size + len(SNAPSHOT_MAGIC) + NONCE_BYTES + TAG_BYTES > max_snapshot_bytes:
            raise SnapshotError("encrypted browser snapshot exceeds the cloud size limit")
        return _write_encrypted_file(
            archive_path,
            destination,
            key,
            snapshot_aad(environment_id, version),
        )
    finally:
        archive_path.unlink(missing_ok=True)


def _decrypt_snapshot(
    source: Path,
    destination: Path,
    key: bytes,
    aad: bytes,
) -> None:
    total_size = source.stat().st_size
    header_size = len(SNAPSHOT_MAGIC) + NONCE_BYTES
    if total_size <= header_size + TAG_BYTES:
        raise SnapshotError("encrypted browser snapshot is truncated")
    with source.open("rb") as source_handle:
        header = source_handle.read(header_size)
        if not header.startswith(SNAPSHOT_MAGIC):
            raise SnapshotError("encrypted browser snapshot has an invalid format")
        nonce = header[len(SNAPSHOT_MAGIC):]
        source_handle.seek(-TAG_BYTES, os.SEEK_END)
        tag = source_handle.read(TAG_BYTES)
        source_handle.seek(header_size)
        remaining = total_size - header_size - TAG_BYTES
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(aad)
        try:
            with destination.open("xb") as output:
                try:
                    os.chmod(destination, 0o600)
                except OSError:
                    pass
                while remaining:
                    block = source_handle.read(min(CHUNK_BYTES, remaining))
                    if not block:
                        raise SnapshotError("encrypted browser snapshot is truncated")
                    remaining -= len(block)
                    output.write(decryptor.update(block))
                final = decryptor.finalize()
                if final:
                    output.write(final)
        except SnapshotError:
            destination.unlink(missing_ok=True)
            raise
        except Exception as exc:
            destination.unlink(missing_ok=True)
            raise SnapshotError("encrypted browser snapshot authentication failed") from exc


def _safe_member_path(root: Path, name: str) -> Path:
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise SnapshotError("snapshot archive contains an unsafe path")
    return root.joinpath(*pure.parts)


def _extract_archive(archive_path: Path, destination: Path, max_unpacked_bytes: int) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    total_size = 0
    members = 0
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for info in archive:
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    raise SnapshotError("snapshot archive contains too many files")
                target = _safe_member_path(destination, info.name)
                if info.issym() or info.islnk() or info.isdev() or info.isfifo():
                    raise SnapshotError("snapshot archive contains an unsupported entry")
                if info.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not info.isfile():
                    raise SnapshotError("snapshot archive contains an unsupported entry")
                total_size += info.size
                if total_size > max_unpacked_bytes:
                    raise SnapshotError("snapshot archive exceeds the unpacked size limit")
                source = archive.extractfile(info)
                if source is None:
                    raise SnapshotError("snapshot archive entry could not be read")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, CHUNK_BYTES)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def restore_encrypted_snapshot(
    encrypted_path: Path,
    browser_data_dir: Path,
    key: bytes,
    environment_id: str,
    version: int,
    *,
    max_unpacked_bytes: int,
) -> None:
    parent = browser_data_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    suffix = secrets.token_hex(6)
    archive_path = parent / f".snapshot-{suffix}.tar.gz"
    restore_path = parent / f".restore-{suffix}"
    backup_path = parent / f".previous-{suffix}"
    try:
        _decrypt_snapshot(
            encrypted_path,
            archive_path,
            key,
            snapshot_aad(environment_id, version),
        )
        _extract_archive(archive_path, restore_path, max_unpacked_bytes)
        if browser_data_dir.exists():
            browser_data_dir.rename(backup_path)
        try:
            restore_path.rename(browser_data_dir)
        except Exception:
            if backup_path.exists() and not browser_data_dir.exists():
                backup_path.rename(browser_data_dir)
            raise
        shutil.rmtree(backup_path, ignore_errors=True)
    finally:
        archive_path.unlink(missing_ok=True)
        shutil.rmtree(restore_path, ignore_errors=True)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK_BYTES)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()
