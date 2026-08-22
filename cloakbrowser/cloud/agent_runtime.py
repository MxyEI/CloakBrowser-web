"""Remote task worker and persistent browser lifecycle for Cloud Agents."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote, urlsplit

import httpx

from ..browser import launch_persistent_context
from ..profile_manager import (
    _LOCATION_PRESETS,
    _apply_browser_locale_preferences,
    _fingerprint_launch_args,
)
from .snapshot_crypto import (
    SnapshotArtifact,
    create_encrypted_snapshot,
    decode_snapshot_key,
    file_sha256,
    restore_encrypted_snapshot,
)
from .extension_packages import install_extension_zip


LEASE_HEARTBEAT_SECONDS = 20.0
TASK_HEARTBEAT_SECONDS = 30.0
PROFILE_CRYPTO_FILENAME = ".cloakbrowser-cloud-profile.json"
PROFILE_CRYPTO_VERSION = 1


def _load_or_create_agent_instance_id(root: Path) -> str:
    path = root / "agent-instance.json"

    def read_existing() -> str:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            instance_id = str(uuid.UUID(str(value.get("instance_id"))))
        except FileNotFoundError:
            raise
        except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Agent instance identity is invalid: {path}") from exc
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise RuntimeError(f"Agent instance identity must use owner-only permissions: {path}")
        return instance_id

    try:
        return read_existing()
    except FileNotFoundError:
        pass

    instance_id = str(uuid.uuid4())
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump({"instance_id": instance_id}, output, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        return read_existing()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return instance_id


def _profile_crypto_descriptor(
    agent_instance_id: str,
    system_name: Optional[str] = None,
) -> dict[str, Any]:
    current_system = system_name or platform.system()
    if current_system == "Darwin":
        return {
            "version": PROFILE_CRYPTO_VERSION,
            "platform": "macos",
            "backend": "mock-keychain",
            "portable": True,
        }
    if current_system == "Linux":
        return {
            "version": PROFILE_CRYPTO_VERSION,
            "platform": "linux",
            "backend": "basic-password-store",
            "portable": True,
        }
    platform_name = "windows" if current_system == "Windows" else current_system.lower()
    backend = "dpapi" if current_system == "Windows" else "native-key-store"
    return {
        "version": PROFILE_CRYPTO_VERSION,
        "platform": platform_name,
        "backend": backend,
        "portable": False,
        "agent_instance_id": agent_instance_id,
    }


def _profile_crypto_launch_args(profile_crypto: dict[str, Any]) -> list[str]:
    if profile_crypto["backend"] == "mock-keychain":
        return ["--use-mock-keychain"]
    if profile_crypto["backend"] == "basic-password-store":
        return ["--password-store=basic"]
    return []


def _profile_crypto_summary(profile_crypto: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": profile_crypto["version"],
        "platform": profile_crypto["platform"],
        "backend": profile_crypto["backend"],
        "portable": profile_crypto["portable"],
    }


class AgentAPIError(RuntimeError):
    """A control-plane request failed."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CloudAgentClient:
    """Authenticated HTTP client for the Agent-only cloud API."""

    def __init__(
        self,
        cloud_url: str,
        token: str,
        *,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=cloud_url,
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        try:
            response = self._client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise AgentAPIError(f"cloud request failed: {exc}") from exc
        self._raise_for_error(response)
        if response.status_code == 204:
            return {}
        try:
            result = response.json()
        except ValueError as exc:
            raise AgentAPIError("cloud returned an invalid JSON response") from exc
        if not isinstance(result, dict):
            raise AgentAPIError("cloud returned an invalid response object")
        return result

    @staticmethod
    def _raise_for_error(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        try:
            body = response.json()
            detail = body.get("detail", response.text)
        except (AttributeError, ValueError):
            detail = response.text
        raise AgentAPIError(
            f"cloud request failed ({response.status_code}): {detail}",
            response.status_code,
        )

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/agent/heartbeat", payload)

    def list_environments(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/api/agent/environments")
        environments = response.get("environments")
        if not isinstance(environments, list) or not all(
            isinstance(environment, dict) for environment in environments
        ):
            raise AgentAPIError("cloud returned an invalid environment list")
        return environments

    def create_environment(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._request("POST", "/api/agent/environments", payload)
        environment = response.get("environment")
        if not isinstance(environment, dict):
            raise AgentAPIError("cloud returned an invalid environment")
        return environment

    def request_launch(self, environment_id: str, expected_revision: int) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/environments/{environment_id}/launch",
            {"expected_revision": expected_revision},
        )

    def request_stop(self, environment_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/environments/{environment_id}/stop",
        )

    def claim_task(self) -> dict[str, Any]:
        return self._request("POST", "/api/agent/tasks/claim")

    def heartbeat_task(self, task_id: str, task_token: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/tasks/{task_id}/heartbeat",
            {"task_token": task_token},
        )

    def complete_task(
        self,
        task_id: str,
        task_token: str,
        status: str,
        *,
        result: Optional[dict[str, Any]] = None,
        error: str = "",
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/tasks/{task_id}/complete",
            {
                "task_token": task_token,
                "status": status,
                "result": result or {},
                "error": error,
            },
        )

    def acquire_lease(self, environment_id: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/agent/leases/acquire",
            {"environment_id": environment_id},
        )

    def heartbeat_lease(
        self, environment_id: str, proof: dict[str, Any]
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/leases/{environment_id}/heartbeat",
            proof,
        )

    def release_lease(self, environment_id: str, proof: dict[str, Any]) -> None:
        self._request(
            "POST",
            f"/api/agent/leases/{environment_id}/release",
            proof,
        )

    def snapshot_manifest(
        self, environment_id: str, proof: dict[str, Any]
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/snapshots/{environment_id}",
            proof,
        )

    def runtime_assets(
        self,
        environment_id: str,
        proof: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/api/agent/environments/{environment_id}/runtime-assets",
            proof,
        )

    def download_extension(
        self,
        environment_id: str,
        extension_id: str,
        proof: dict[str, Any],
        destination: Path,
        *,
        expected_sha256: str,
        expected_size: int,
        max_extension_bytes: int,
    ) -> None:
        destination.unlink(missing_ok=True)
        digest = hashlib.sha256()
        received = 0
        try:
            with self._client.stream(
                "POST",
                f"/api/agent/environments/{environment_id}/extensions/"
                f"{extension_id}/download",
                json=proof,
            ) as response:
                if response.status_code >= 400:
                    response.read()
                    self._raise_for_error(response)
                with destination.open("xb") as output:
                    try:
                        destination.chmod(0o600)
                    except OSError:
                        pass
                    for block in response.iter_bytes():
                        received += len(block)
                        if received > max_extension_bytes:
                            raise AgentAPIError(
                                "downloaded extension exceeds its size limit"
                            )
                        digest.update(block)
                        output.write(block)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        if received != expected_size or digest.hexdigest() != expected_sha256:
            destination.unlink(missing_ok=True)
            raise AgentAPIError("downloaded extension failed integrity verification")

    def download_snapshot(
        self,
        environment_id: str,
        proof: dict[str, Any],
        destination: Path,
        *,
        expected_sha256: str,
        max_snapshot_bytes: int,
    ) -> None:
        destination.unlink(missing_ok=True)
        digest = hashlib.sha256()
        received = 0
        try:
            with self._client.stream(
                "POST",
                f"/api/agent/snapshots/{environment_id}/download",
                json=proof,
            ) as response:
                if response.status_code >= 400:
                    response.read()
                    self._raise_for_error(response)
                with destination.open("xb") as output:
                    try:
                        destination.chmod(0o600)
                    except OSError:
                        pass
                    for block in response.iter_bytes():
                        received += len(block)
                        if received > max_snapshot_bytes:
                            raise AgentAPIError("downloaded cloud snapshot exceeds its size limit")
                        digest.update(block)
                        output.write(block)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        if digest.hexdigest() != expected_sha256:
            destination.unlink(missing_ok=True)
            raise AgentAPIError("downloaded cloud snapshot failed SHA-256 verification")

    def upload_snapshot(
        self,
        environment_id: str,
        proof: dict[str, Any],
        artifact: SnapshotArtifact,
        *,
        expected_version: int,
    ) -> dict[str, Any]:
        headers = {
            "X-CB-Lease-Id": str(proof["lease_id"]),
            "X-CB-Lease-Token": str(proof["lease_token"]),
            "X-CB-Fencing-Token": str(proof["fencing_token"]),
            "X-CB-Snapshot-Expected-Version": str(expected_version),
            "X-CB-Snapshot-Plaintext-Size": str(artifact.plaintext_size),
            "X-CB-Snapshot-SHA256": str(artifact.sha256),
            "Content-Type": "application/vnd.cloakbrowser.snapshot",
            "Content-Length": str(artifact.size),
        }
        try:
            with artifact.path.open("rb") as content:
                response = self._client.put(
                    f"/api/agent/snapshots/{environment_id}/content",
                    headers=headers,
                    content=content,
                )
        except httpx.HTTPError as exc:
            raise AgentAPIError(f"cloud request failed: {exc}") from exc
        self._raise_for_error(response)
        try:
            result = response.json()
        except ValueError as exc:
            raise AgentAPIError("cloud returned an invalid snapshot response") from exc
        if not isinstance(result, dict):
            raise AgentAPIError("cloud returned an invalid snapshot response object")
        return result


@dataclass
class _TaskHeartbeat:
    api: Any
    task_id: str
    task_token: str
    interval: float = TASK_HEARTBEAT_SECONDS
    stopped: threading.Event = field(default_factory=threading.Event)
    stale: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._run,
            name=f"cloak-task-heartbeat-{self.task_id[:8]}",
            daemon=True,
        )
        self.thread.start()

    def _run(self) -> None:
        while not self.stopped.wait(self.interval):
            try:
                self.api.heartbeat_task(self.task_id, self.task_token)
            except AgentAPIError as exc:
                if exc.status_code in {401, 409}:
                    self.stale.set()
                    return
            except Exception:
                # A transient connection failure is retried on the next interval.
                continue

    def stop(self) -> None:
        self.stopped.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)


@dataclass
class _LocalBrowser:
    environment_id: str
    environment: dict[str, Any]
    browser_data_dir: Path
    snapshot_state_path: Path
    extension_cache_dir: Path
    api: Any
    launcher: Callable[..., Any]
    profile_crypto: dict[str, Any]
    state_reporter: Optional[Callable[[str, str, dict[str, Any]], None]] = None
    lease_heartbeat_interval: float = LEASE_HEARTBEAT_SECONDS
    stop_event: threading.Event = field(default_factory=threading.Event)
    ready_event: threading.Event = field(default_factory=threading.Event)
    exited_event: threading.Event = field(default_factory=threading.Event)
    lease_stop_event: threading.Event = field(default_factory=threading.Event)
    lease_stale_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None
    lease_thread: Optional[threading.Thread] = None
    lease_proof: Optional[dict[str, Any]] = None
    error: str = ""
    sync_error: str = ""
    snapshot_version: int = 0
    snapshot_result: dict[str, Any] = field(default_factory=dict)
    snapshot_key: Optional[bytes] = None
    snapshot_max_bytes: int = 0
    runtime_proxy: str = ""
    extension_paths: list[str] = field(default_factory=list)

    def _report_state(self, phase: str, **details: Any) -> None:
        if self.state_reporter is not None:
            try:
                self.state_reporter(self.environment_id, phase, details)
            except Exception:
                # A presentation-layer status callback must not affect the browser.
                pass

    def start(self, timeout: float) -> dict[str, Any]:
        self.thread = threading.Thread(
            target=self._run,
            name=f"cloak-cloud-browser-{self.environment_id[:8]}",
            daemon=True,
        )
        self.thread.start()
        if not self.ready_event.wait(timeout):
            self.stop_event.set()
            raise RuntimeError("browser launch timed out")
        if self.error:
            raise RuntimeError(self.error)
        if self.lease_proof is None:
            raise RuntimeError("browser launch did not return a lease")
        return {
            "lease_id": self.lease_proof["lease_id"],
            "fencing_token": self.lease_proof["fencing_token"],
            "snapshot_version": self.snapshot_version,
            "profile_crypto": _profile_crypto_summary(self.profile_crypto),
        }

    def matches_lease(self, lease_id: Any, fencing_token: Any) -> bool:
        return bool(
            self.lease_proof
            and self.lease_proof["lease_id"] == lease_id
            and self.lease_proof["fencing_token"] == fencing_token
        )

    def stop(self, timeout: float) -> None:
        self.stop_event.set()
        if not self.exited_event.wait(timeout):
            raise RuntimeError("browser did not stop before the timeout")

    def _start_lease_heartbeat(self) -> None:
        self.lease_thread = threading.Thread(
            target=self._lease_heartbeat_loop,
            name=f"cloak-cloud-lease-{self.environment_id[:8]}",
            daemon=True,
        )
        self.lease_thread.start()

    def _lease_heartbeat_loop(self) -> None:
        consecutive_failures = 0
        while not self.lease_stop_event.wait(self.lease_heartbeat_interval):
            if self.lease_proof is None:
                return
            try:
                self.api.heartbeat_lease(self.environment_id, self.lease_proof)
                consecutive_failures = 0
            except AgentAPIError as exc:
                consecutive_failures += 1
                if exc.status_code not in {401, 409} and consecutive_failures < 2:
                    continue
                self.error = f"environment lease was lost: {exc}"[:1000]
                self.lease_stale_event.set()
                self.stop_event.set()
                return
            except Exception as exc:
                consecutive_failures += 1
                if consecutive_failures < 2:
                    continue
                self.error = f"environment lease was lost: {exc}"[:1000]
                self.lease_stale_event.set()
                self.stop_event.set()
                return

    def _restore_cloud_snapshot(self) -> None:
        if self.lease_proof is None:
            raise RuntimeError("cloud snapshot restore requires an active lease")
        self._report_state("downloading")
        manifest = self.api.snapshot_manifest(self.environment_id, self.lease_proof)
        self.snapshot_key = decode_snapshot_key(str(manifest.get("encryption_key") or ""))
        version = manifest.get("version")
        max_snapshot_bytes = manifest.get("max_snapshot_bytes")
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version < 0
            or isinstance(max_snapshot_bytes, bool)
            or not isinstance(max_snapshot_bytes, int)
            or max_snapshot_bytes <= 0
        ):
            raise RuntimeError("cloud returned invalid snapshot metadata")
        self.snapshot_version = version
        self.snapshot_max_bytes = max_snapshot_bytes
        local_state = self._read_snapshot_state()
        if local_state is not None and local_state["dirty"]:
            if local_state["version"] != version:
                raise RuntimeError(
                    "local browser data has unsynchronized changes and the cloud "
                    "snapshot also changed; local data was preserved"
                )
            if not self.browser_data_dir.is_dir():
                raise RuntimeError("local snapshot state exists but browser data is missing")
            self._ensure_profile_crypto()
            self._upload_cloud_snapshot()
            return
        if version == 0:
            self._write_snapshot_state(version=0, dirty=False)
            return
        if (
            local_state is not None
            and not local_state["dirty"]
            and local_state["version"] == version
            and self.browser_data_dir.is_dir()
        ):
            return
        if local_state is None and self.browser_data_dir.is_dir() and any(
            self.browser_data_dir.iterdir()
        ):
            raise RuntimeError(
                "cloud snapshot exists but this Agent has untracked local browser data; "
                "local data was preserved"
            )
        expected_sha256 = manifest.get("ciphertext_sha256")
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise RuntimeError("cloud snapshot SHA-256 metadata is invalid")
        download_path = self.browser_data_dir.parent / (
            f".snapshot-download-{self.environment_id}-{uuid.uuid4().hex}.cbsnap"
        )
        try:
            self.api.download_snapshot(
                self.environment_id,
                self.lease_proof,
                download_path,
                expected_sha256=expected_sha256,
                max_snapshot_bytes=max_snapshot_bytes,
            )
            self._report_state("verifying")
            if file_sha256(download_path) != expected_sha256:
                raise RuntimeError("downloaded cloud snapshot failed local verification")
            self._report_state("restoring")
            restore_encrypted_snapshot(
                download_path,
                self.browser_data_dir,
                self.snapshot_key,
                self.environment_id,
                version,
                max_unpacked_bytes=max(512 * 1024 * 1024, max_snapshot_bytes * 8),
                validate_restored=self._validate_restored_profile_crypto,
            )
            self._write_snapshot_state(version=version, dirty=False)
        finally:
            download_path.unlink(missing_ok=True)

    def _read_snapshot_state(self) -> Optional[dict[str, Any]]:
        try:
            value = json.loads(self.snapshot_state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"local snapshot state is invalid: {exc}") from exc
        if (
            not isinstance(value, dict)
            or isinstance(value.get("version"), bool)
            or not isinstance(value.get("version"), int)
            or value["version"] < 0
            or not isinstance(value.get("dirty"), bool)
        ):
            raise RuntimeError("local snapshot state is invalid")
        return {"version": value["version"], "dirty": value["dirty"]}

    def _write_snapshot_state(self, *, version: int, dirty: bool) -> None:
        self.snapshot_state_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.snapshot_state_path.parent.chmod(0o700)
        except OSError:
            pass
        temporary = self.snapshot_state_path.with_name(
            f".{self.snapshot_state_path.name}-{uuid.uuid4().hex}.tmp"
        )
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump(
                    {"version": version, "dirty": dirty},
                    output,
                    separators=(",", ":"),
                )
                output.write("\n")
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, self.snapshot_state_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_profile_crypto(self, root: Optional[Path] = None) -> Optional[dict[str, Any]]:
        path = (root or self.browser_data_dir) / PROFILE_CRYPTO_FILENAME
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("cloud profile encryption metadata is invalid") from exc
        if (
            not isinstance(value, dict)
            or isinstance(value.get("version"), bool)
            or value.get("version") != PROFILE_CRYPTO_VERSION
            or not isinstance(value.get("platform"), str)
            or not value["platform"]
            or not isinstance(value.get("backend"), str)
            or not value["backend"]
            or not isinstance(value.get("portable"), bool)
        ):
            raise RuntimeError("cloud profile encryption metadata is invalid")
        if value["portable"]:
            if "agent_instance_id" in value:
                raise RuntimeError("cloud profile encryption metadata is invalid")
        else:
            try:
                instance_id = str(uuid.UUID(str(value.get("agent_instance_id"))))
            except (AttributeError, TypeError, ValueError) as exc:
                raise RuntimeError("cloud profile encryption metadata is invalid") from exc
            if instance_id != value.get("agent_instance_id"):
                raise RuntimeError("cloud profile encryption metadata is invalid")
        return value

    def _validate_profile_crypto(self, root: Optional[Path] = None) -> bool:
        existing = self._read_profile_crypto(root)
        if existing is None:
            return False
        if (
            existing["platform"] != self.profile_crypto["platform"]
            or existing["backend"] != self.profile_crypto["backend"]
            or existing["portable"] != self.profile_crypto["portable"]
        ):
            raise RuntimeError(
                "cloud profile login data was encrypted for "
                f"{existing['platform']}/{existing['backend']}; this Agent uses "
                f"{self.profile_crypto['platform']}/{self.profile_crypto['backend']}"
            )
        if (
            not existing["portable"]
            and existing["agent_instance_id"]
            != self.profile_crypto["agent_instance_id"]
        ):
            raise RuntimeError(
                "cloud profile login data uses a machine-bound key store and can only "
                "be restored on the Agent that created it"
            )
        return True

    def _write_profile_crypto(self) -> None:
        path = self.browser_data_dir / PROFILE_CRYPTO_FILENAME
        temporary = path.with_name(f".{path.name}-{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump(self.profile_crypto, output, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _ensure_profile_crypto(self) -> None:
        if not self._validate_profile_crypto():
            self._write_profile_crypto()

    def _validate_restored_profile_crypto(self, restore_root: Path) -> None:
        if not self._validate_profile_crypto(restore_root):
            raise RuntimeError(
                "cloud snapshot predates profile-key metadata; open and close it once "
                "on its original Agent before moving it to another device"
            )

    def _upload_cloud_snapshot(self) -> None:
        if self.lease_proof is None or self.snapshot_key is None:
            raise RuntimeError("cloud snapshot upload requires prepared encryption state")
        destination = self.browser_data_dir.parent / (
            f".snapshot-upload-{self.environment_id}-{uuid.uuid4().hex}.cbsnap"
        )
        try:
            self._ensure_profile_crypto()
            self._report_state("encrypting")
            artifact = create_encrypted_snapshot(
                self.browser_data_dir,
                destination,
                self.snapshot_key,
                self.environment_id,
                self.snapshot_version + 1,
                max_snapshot_bytes=self.snapshot_max_bytes,
            )
            self._report_state("uploading")
            response = self.api.upload_snapshot(
                self.environment_id,
                self.lease_proof,
                artifact,
                expected_version=self.snapshot_version,
            )
            snapshot = response.get("snapshot")
            if not isinstance(snapshot, dict) or snapshot.get("version") != self.snapshot_version + 1:
                raise RuntimeError("cloud returned an invalid snapshot upload result")
            self.snapshot_result = dict(snapshot)
            self.snapshot_version = int(snapshot["version"])
            self._write_snapshot_state(version=self.snapshot_version, dirty=False)
            self._report_state("synced", snapshot_version=self.snapshot_version)
        finally:
            destination.unlink(missing_ok=True)

    def _prepare_runtime_assets(self) -> None:
        if self.lease_proof is None:
            raise RuntimeError("runtime assets require an active lease")
        self._report_state("fetching_assets")
        assets = self.api.runtime_assets(self.environment_id, self.lease_proof)
        proxy = assets.get("proxy", "")
        extensions = assets.get("extensions", [])
        max_extension_bytes = assets.get("max_extension_bytes")
        max_unpacked_bytes = assets.get("max_extension_unpacked_bytes")
        if (
            not isinstance(proxy, str)
            or len(proxy) > 2048
            or any(ord(character) < 32 for character in proxy)
            or not isinstance(extensions, list)
            or isinstance(max_extension_bytes, bool)
            or not isinstance(max_extension_bytes, int)
            or max_extension_bytes <= 0
            or isinstance(max_unpacked_bytes, bool)
            or not isinstance(max_unpacked_bytes, int)
            or max_unpacked_bytes <= 0
        ):
            raise RuntimeError("cloud returned invalid runtime assets")
        self.runtime_proxy = proxy
        prepared: list[str] = []
        self.extension_cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.extension_cache_dir.chmod(0o700)
        except OSError:
            pass
        for extension in extensions:
            if not isinstance(extension, dict):
                raise RuntimeError("cloud returned invalid extension metadata")
            extension_id = extension.get("id")
            expected_sha256 = extension.get("content_sha256")
            expected_size = extension.get("content_size")
            try:
                canonical_id = str(uuid.UUID(str(extension_id)))
            except ValueError as exc:
                raise RuntimeError("cloud returned an invalid extension id") from exc
            if (
                canonical_id != extension_id
                or not isinstance(expected_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
                or isinstance(expected_size, bool)
                or not isinstance(expected_size, int)
                or expected_size <= 0
                or expected_size > max_extension_bytes
            ):
                raise RuntimeError("cloud returned invalid extension metadata")
            package_root = self.extension_cache_dir / canonical_id / expected_sha256
            marker = package_root / ".cloakbrowser-package.json"
            try:
                marker_value = json.loads(marker.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                marker_value = None
            if (
                isinstance(marker_value, dict)
                and marker_value.get("sha256") == expected_sha256
                and (package_root / "manifest.json").is_file()
            ):
                prepared.append(str(package_root))
                continue
            download_path = self.extension_cache_dir / (
                f".extension-download-{canonical_id}-{uuid.uuid4().hex}.zip"
            )
            try:
                self.api.download_extension(
                    self.environment_id,
                    canonical_id,
                    self.lease_proof,
                    download_path,
                    expected_sha256=expected_sha256,
                    expected_size=expected_size,
                    max_extension_bytes=max_extension_bytes,
                )
                install_extension_zip(
                    download_path,
                    package_root,
                    expected_sha256=expected_sha256,
                    max_unpacked_bytes=max_unpacked_bytes,
                )
            finally:
                download_path.unlink(missing_ok=True)
            prepared.append(str(package_root))
        self.extension_paths = prepared

    def _redacted_error(self, error: Exception) -> str:
        message = str(error)
        if not self.runtime_proxy:
            return message[:1000]
        message = message.replace(self.runtime_proxy, "<redacted proxy>")
        try:
            parsed = urlsplit(self.runtime_proxy)
            for credential in (parsed.username, parsed.password):
                if credential:
                    message = message.replace(credential, "<redacted>")
                    message = message.replace(unquote(credential), "<redacted>")
        except ValueError:
            pass
        return message[:1000]

    def _run(self) -> None:
        context = None
        acquired = False
        browser_started = False
        try:
            self._report_state("acquiring_lease")
            lease_response = self.api.acquire_lease(self.environment_id)
            lease = lease_response.get("lease")
            lease_token = lease_response.get("lease_token")
            if not isinstance(lease, dict) or not isinstance(lease_token, str):
                raise RuntimeError("cloud returned an invalid lease")
            lease_id = lease.get("lease_id")
            fencing_token = lease.get("fencing_token")
            if (
                not isinstance(lease_id, str)
                or isinstance(fencing_token, bool)
                or not isinstance(fencing_token, int)
            ):
                raise RuntimeError("cloud returned invalid lease fencing data")
            self.lease_proof = {
                "lease_id": lease_id,
                "lease_token": lease_token,
                "fencing_token": fencing_token,
            }
            acquired = True
            self._start_lease_heartbeat()

            config = self.environment.get("config")
            if not isinstance(config, dict):
                raise RuntimeError("environment config is invalid")
            storage_policy = str(self.environment.get("storage_policy") or "local")
            if storage_policy != "local":
                self._restore_cloud_snapshot()
            self._prepare_runtime_assets()
            self.browser_data_dir.mkdir(parents=True, exist_ok=True)
            try:
                self.browser_data_dir.chmod(0o700)
            except OSError:
                pass
            if storage_policy != "local":
                self._ensure_profile_crypto()
            locale = str(config.get("locale") or "")
            _apply_browser_locale_preferences(self.browser_data_dir, locale)
            launch_args = _fingerprint_launch_args(config)
            if storage_policy != "local":
                launch_args.extend(_profile_crypto_launch_args(self.profile_crypto))
            launch_options: dict[str, Any] = {
                "headless": bool(config.get("headless", False)),
                "args": launch_args,
                "timezone": config.get("timezone") or None,
                "locale": locale or None,
                "geoip": bool(self.runtime_proxy and config.get("geoip", False)),
                "humanize": bool(config.get("humanize", False)),
            }
            if self.runtime_proxy:
                launch_options["proxy"] = self.runtime_proxy
            if self.extension_paths:
                launch_options["extension_paths"] = list(self.extension_paths)
            geolocation = _LOCATION_PRESETS.get(str(config.get("location") or ""))
            if geolocation:
                launch_options["geolocation"] = dict(geolocation)
                launch_options["permissions"] = ["geolocation"]
            if storage_policy != "local" or self.snapshot_state_path.exists():
                self._write_snapshot_state(
                    version=self.snapshot_version,
                    dirty=True,
                )
            self._report_state("starting")
            context = self.launcher(self.browser_data_dir, **launch_options)
            browser_started = True
            if self.lease_stale_event.is_set():
                raise RuntimeError(self.error or "environment lease was lost during launch")

            startup_url = str(config.get("startup_url") or "about:blank")
            if startup_url != "about:blank":
                try:
                    pages = context.pages
                    page = pages[0] if pages else context.new_page()
                    page.goto(startup_url, wait_until="domcontentloaded", timeout=30_000)
                except Exception:
                    # Navigation failure does not invalidate an interactive browser.
                    pass
            self._report_state("running", snapshot_version=self.snapshot_version)
            self.ready_event.set()
            while not self.stop_event.wait(0.4):
                try:
                    _ = context.pages
                except Exception:
                    break
        except Exception as exc:
            if not self.error:
                self.error = self._redacted_error(exc)
            self._report_state("error", error=self.error)
        finally:
            self.ready_event.set()
            if context is not None:
                self._report_state("stopping")
                try:
                    context.close()
                except Exception:
                    pass
            if (
                browser_started
                and str(self.environment.get("storage_policy") or "local") != "local"
                and not self.lease_stale_event.is_set()
            ):
                try:
                    self._upload_cloud_snapshot()
                except Exception as exc:
                    self.sync_error = str(exc)[:1000] or exc.__class__.__name__
                    self._report_state("error", error=self.sync_error)
            self.lease_stop_event.set()
            if self.lease_thread is not None:
                self.lease_thread.join(timeout=2.0)
            if acquired and self.lease_proof is not None:
                try:
                    self.api.release_lease(self.environment_id, self.lease_proof)
                except Exception:
                    pass
            if (
                not self.error
                and not self.sync_error
                and (
                    not browser_started
                    or str(self.environment.get("storage_policy") or "local") == "local"
                )
            ):
                self._report_state("stopped")
            self.exited_event.set()


class AgentRuntime:
    """Poll remote tasks and own all browsers assigned to one Agent."""

    def __init__(
        self,
        api: Any,
        data_dir: str | os.PathLike[str],
        *,
        heartbeat_payload: dict[str, Any],
        launcher: Optional[Callable[..., Any]] = None,
        poll_interval: float = 2.0,
        heartbeat_interval: float = 20.0,
        launch_timeout: float = 120.0,
        stop_timeout: float = 600.0,
        reporter: Optional[Callable[[str], None]] = None,
        state_reporter: Optional[
            Callable[[str, str, dict[str, Any]], None]
        ] = None,
        system_name: Optional[str] = None,
    ) -> None:
        self.api = api
        self.data_dir = Path(data_dir)
        self.browser_data_dir = self.data_dir / "browser-data"
        self.snapshot_state_dir = self.data_dir / "snapshot-state"
        self.extension_cache_dir = self.data_dir / "extensions"
        self.heartbeat_payload = heartbeat_payload
        self.launcher = launcher or launch_persistent_context
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.launch_timeout = launch_timeout
        self.stop_timeout = stop_timeout
        self.reporter = reporter or (lambda _message: None)
        self.state_reporter = state_reporter
        self._shutdown = threading.Event()
        self._lock = threading.RLock()
        self._browsers: dict[str, _LocalBrowser] = {}
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.browser_data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_state_dir.mkdir(parents=True, exist_ok=True)
        self.extension_cache_dir.mkdir(parents=True, exist_ok=True)
        for directory in (
            self.data_dir,
            self.browser_data_dir,
            self.snapshot_state_dir,
            self.extension_cache_dir,
        ):
            try:
                directory.chmod(0o700)
            except OSError:
                pass
        self.agent_instance_id = _load_or_create_agent_instance_id(self.data_dir)
        self.profile_crypto = _profile_crypto_descriptor(
            self.agent_instance_id,
            system_name,
        )

    def run(self) -> None:
        next_heartbeat = 0.0
        try:
            while not self._shutdown.is_set():
                now = time.monotonic()
                if now >= next_heartbeat:
                    try:
                        response = self.api.heartbeat(self.heartbeat_payload)
                        self.reporter(f"Agent online: {response.get('agent_id', 'unknown')}")
                    except Exception as exc:
                        self.reporter(f"Agent heartbeat warning: {exc}")
                    next_heartbeat = now + self.heartbeat_interval
                try:
                    claimed = self.api.claim_task()
                    if claimed.get("task") is not None:
                        self.process_claimed_task(claimed)
                        continue
                except Exception as exc:
                    self.reporter(f"Agent task warning: {exc}")
                self._shutdown.wait(self.poll_interval)
        finally:
            self.shutdown()

    def process_claimed_task(self, claimed: dict[str, Any]) -> None:
        task = claimed.get("task")
        task_token = claimed.get("task_token")
        if not isinstance(task, dict) or not isinstance(task_token, str):
            raise RuntimeError("cloud returned an invalid claimed task")
        task_id = task.get("id")
        if not isinstance(task_id, str):
            raise RuntimeError("claimed task does not have an id")
        heartbeat = _TaskHeartbeat(self.api, task_id, task_token)
        heartbeat.start()
        status = "failed"
        result: dict[str, Any] = {}
        error = ""
        launch_worker: Optional[_LocalBrowser] = None
        try:
            kind = task.get("kind")
            if kind == "launch":
                result, launch_worker = self._launch(task)
            elif kind == "stop":
                result = self._stop(task)
            else:
                raise RuntimeError(f"unsupported remote task kind: {kind}")
            if heartbeat.stale.is_set():
                raise RuntimeError("remote task claim expired while it was executing")
            status = "succeeded"
        except Exception as exc:
            error = str(exc)[:1000] or exc.__class__.__name__
        finally:
            heartbeat.stop()

        try:
            self.api.complete_task(
                task_id,
                task_token,
                status,
                result=result,
                error=error,
            )
        except Exception:
            if launch_worker is not None:
                try:
                    launch_worker.stop(self.stop_timeout)
                except Exception:
                    pass
            raise
        if status == "failed":
            self.reporter(f"Task {task_id[:8]} failed: {error}")

    def _environment_id(self, task: dict[str, Any]) -> str:
        environment_id = task.get("environment_id")
        if not isinstance(environment_id, str):
            raise RuntimeError("remote task does not have an environment id")
        try:
            parsed = uuid.UUID(environment_id)
        except ValueError as exc:
            raise RuntimeError("remote task environment id is invalid") from exc
        if str(parsed) != environment_id.lower():
            raise RuntimeError("remote task environment id is not canonical")
        return environment_id

    def _launch(
        self, task: dict[str, Any]
    ) -> tuple[dict[str, Any], _LocalBrowser]:
        environment_id = self._environment_id(task)
        payload = task.get("payload")
        environment = payload.get("environment") if isinstance(payload, dict) else None
        if not isinstance(environment, dict) or environment.get("id") != environment_id:
            raise RuntimeError("launch task environment payload is invalid")
        if environment.get("revision") != task.get("environment_revision"):
            raise RuntimeError("launch task environment revision is inconsistent")
        with self._lock:
            existing = self._browsers.get(environment_id)
            if existing is not None and not existing.exited_event.is_set():
                raise RuntimeError("environment is already running on this Agent")
            if existing is not None:
                self._browsers.pop(environment_id, None)
            worker = _LocalBrowser(
                environment_id=environment_id,
                environment=environment,
                browser_data_dir=self.browser_data_dir / environment_id,
                snapshot_state_path=self.snapshot_state_dir / f"{environment_id}.json",
                extension_cache_dir=self.extension_cache_dir,
                api=self.api,
                launcher=self.launcher,
                profile_crypto=dict(self.profile_crypto),
                state_reporter=self.state_reporter,
            )
            self._browsers[environment_id] = worker
        try:
            return worker.start(self.launch_timeout), worker
        except Exception:
            try:
                worker.stop(self.stop_timeout)
            except Exception:
                pass
            with self._lock:
                if self._browsers.get(environment_id) is worker:
                    self._browsers.pop(environment_id, None)
            raise

    def _stop(self, task: dict[str, Any]) -> dict[str, Any]:
        environment_id = self._environment_id(task)
        payload = task.get("payload")
        if not isinstance(payload, dict):
            raise RuntimeError("stop task payload is invalid")
        with self._lock:
            worker = self._browsers.get(environment_id)
        if worker is None or worker.exited_event.is_set():
            raise RuntimeError("environment is not running on this Agent")
        if not worker.matches_lease(payload.get("lease_id"), payload.get("fencing_token")):
            raise RuntimeError("stop task lease does not match the local browser")
        worker.stop(self.stop_timeout)
        if worker.sync_error:
            raise RuntimeError(
                f"browser stopped but cloud snapshot upload failed: {worker.sync_error}"
            )
        with self._lock:
            if self._browsers.get(environment_id) is worker:
                self._browsers.pop(environment_id, None)
        return {
            "lease_id": payload["lease_id"],
            "fencing_token": payload["fencing_token"],
            "snapshot_version": worker.snapshot_version,
            "profile_crypto": _profile_crypto_summary(worker.profile_crypto),
        }

    def shutdown(self) -> None:
        self._shutdown.set()
        with self._lock:
            workers = list(self._browsers.values())
        for worker in workers:
            worker.stop_event.set()
        for worker in workers:
            worker.exited_event.wait(min(self.stop_timeout, 30.0))
        with self._lock:
            self._browsers.clear()
