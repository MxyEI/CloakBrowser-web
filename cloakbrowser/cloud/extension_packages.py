"""Validation and safe installation for unpacked Chromium extension ZIPs."""

from __future__ import annotations

import json
import shutil
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Optional


MAX_EXTENSION_MEMBERS = 20_000
MAX_MANIFEST_BYTES = 1024 * 1024
COPY_BYTES = 1024 * 1024


class ExtensionPackageError(RuntimeError):
    pass


def _member_parts(info: zipfile.ZipInfo) -> tuple[str, ...]:
    if "\\" in info.filename or "\x00" in info.filename:
        raise ExtensionPackageError("extension package contains an unsafe path")
    path = PurePosixPath(info.filename)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ExtensionPackageError("extension package contains an unsafe path")
    return path.parts


def _validate_member_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise ExtensionPackageError("encrypted ZIP entries are not supported")
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if file_type and not (
        stat.S_ISREG(mode) or stat.S_ISDIR(mode)
    ):
        raise ExtensionPackageError("extension package contains an unsupported entry")


def inspect_extension_zip(path: Path, *, max_unpacked_bytes: int) -> dict[str, Any]:
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_EXTENSION_MEMBERS:
                raise ExtensionPackageError("extension package file count is invalid")
            manifest_info: Optional[zipfile.ZipInfo] = None
            for info in infos:
                parts = _member_parts(info)
                _validate_member_type(info)
                if not info.is_dir():
                    total += info.file_size
                    if total > max_unpacked_bytes:
                        raise ExtensionPackageError(
                            "extension package exceeds the unpacked size limit"
                        )
                    if parts == ("manifest.json",):
                        manifest_info = info
            if manifest_info is None or manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise ExtensionPackageError(
                    "extension package must contain a root manifest.json"
                )
            try:
                manifest = json.loads(archive.read(manifest_info).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
                raise ExtensionPackageError("extension manifest is invalid") from exc
            if (
                not isinstance(manifest, dict)
                or manifest.get("manifest_version") not in {2, 3}
                or not isinstance(manifest.get("name"), str)
                or not isinstance(manifest.get("version"), str)
            ):
                raise ExtensionPackageError("extension manifest metadata is invalid")
            # Fully read each entry to verify CRCs and reject truncated archives.
            actual = 0
            for info in infos:
                if info.is_dir():
                    continue
                with archive.open(info) as source:
                    while True:
                        block = source.read(COPY_BYTES)
                        if not block:
                            break
                        actual += len(block)
                        if actual > max_unpacked_bytes:
                            raise ExtensionPackageError(
                                "extension package exceeds the unpacked size limit"
                            )
            return manifest
    except ExtensionPackageError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        raise ExtensionPackageError("extension package is not a valid ZIP archive") from exc


def install_extension_zip(
    archive_path: Path,
    destination: Path,
    *,
    expected_sha256: str,
    max_unpacked_bytes: int,
) -> None:
    manifest = inspect_extension_zip(
        archive_path,
        max_unpacked_bytes=max_unpacked_bytes,
    )
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".extension-{uuid.uuid4().hex}.tmp"
    previous = parent / f".extension-{uuid.uuid4().hex}.previous"
    temporary.mkdir(mode=0o700)
    total = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                parts = _member_parts(info)
                _validate_member_type(info)
                target = temporary.joinpath(*parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    while True:
                        block = source.read(COPY_BYTES)
                        if not block:
                            break
                        total += len(block)
                        if total > max_unpacked_bytes:
                            raise ExtensionPackageError(
                                "extension package exceeds the unpacked size limit"
                            )
                        output.write(block)
        (temporary / ".cloakbrowser-package.json").write_text(
            json.dumps(
                {
                    "sha256": expected_sha256,
                    "name": manifest["name"],
                    "version": manifest["version"],
                },
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            destination.rename(previous)
        try:
            temporary.rename(destination)
        except Exception:
            if previous.exists() and not destination.exists():
                previous.rename(destination)
            raise
        shutil.rmtree(previous, ignore_errors=True)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
