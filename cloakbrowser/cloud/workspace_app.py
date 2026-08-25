"""Loopback desktop UI for a member's cloud browser environments."""

from __future__ import annotations

import json
import platform
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from .agent_cli import heartbeat_payload
from .agent_runtime import AgentAPIError, AgentRuntime, CloudAgentClient
from .workspace_cli import (
    clear_workspace_session,
    load_or_create_device_uid,
    load_workspace_session,
    login_device,
    register_client_account,
    save_workspace_session,
)


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_REQUEST_BYTES = 128 * 1024
ACCOUNT_PENDING_NOTICE = "Account created. Team access pending."


class WorkspaceError(RuntimeError):
    """A local workspace request could not be completed."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkspaceApplication:
    """Own cloud credentials and Agent runtime outside the browser UI."""

    def __init__(
        self,
        cloud_url: str,
        root: Path,
        *,
        email: str = "",
        organization_id: str = "",
        device_name: str = "",
        poll_interval: float = 1.0,
    ) -> None:
        self.cloud_url = cloud_url
        self.root = root
        self.default_email = email
        self.default_organization_id = organization_id
        self.device_name = (device_name or platform.node() or "Desktop").strip()
        self.poll_interval = poll_interval
        self.device_uid = load_or_create_device_uid(root)
        self.csrf_token = secrets.token_urlsafe(32)
        self.assets_dir = Path(__file__).with_name("workspace_ui")
        self._lock = threading.RLock()
        self._operation_lock = threading.RLock()
        self._api: Optional[CloudAgentClient] = None
        self._runtime: Optional[AgentRuntime] = None
        self._runtime_thread: Optional[threading.Thread] = None
        self._identity: dict[str, Any] = {}
        self._environments: list[dict[str, Any]] = []
        self._environment_states: dict[str, dict[str, Any]] = {}
        self._last_error = ""
        self._last_notice = ""
        self._connection_message = ""
        self._last_refresh = 0.0
        self._remember_session = False
        self._saved_session: Optional[dict[str, str]] = None
        self._restoring_session = False
        try:
            self._saved_session = load_workspace_session(root, cloud_url)
            self._restoring_session = self._saved_session is not None
        except Exception as exc:
            self._set_error(exc)

    def _set_error(self, error: Exception | str) -> None:
        message = str(error).strip()[:1000] or "request failed"
        with self._lock:
            self._last_error = message

    def clear_error(self) -> None:
        with self._lock:
            self._last_error = ""
            self._last_notice = ""

    def _report(self, message: str) -> None:
        with self._lock:
            self._connection_message = message[:300]

    def _report_environment_state(
        self,
        environment_id: str,
        phase: str,
        details: dict[str, Any],
    ) -> None:
        public_details = {
            key: value
            for key, value in details.items()
            if key in {"snapshot_version", "error"}
        }
        with self._lock:
            self._environment_states[environment_id] = {
                "phase": phase,
                "updated_at": _now_iso(),
                **public_details,
            }

    def _activate_session(
        self,
        api: CloudAgentClient,
        result: dict[str, Any],
        *,
        remember: bool,
    ) -> None:
        runtime = AgentRuntime(
            api,
            self.root,
            heartbeat_payload=heartbeat_payload(),
            poll_interval=self.poll_interval,
            heartbeat_interval=20.0,
            reporter=self._report,
            state_reporter=self._report_environment_state,
        )
        runtime_thread = threading.Thread(
            target=runtime.run,
            name="cloak-cloud-workspace",
            daemon=True,
        )
        with self._lock:
            self._api = api
            self._runtime = runtime
            self._runtime_thread = runtime_thread
            self._identity = {
                "user": dict(result.get("user") or {}),
                "organization": dict(result.get("organization") or {}),
                "agent": dict(result.get("agent") or {}),
            }
            self._environments = list(result["environments"])
            self._environment_states = {
                str(environment["id"]): {
                    "phase": "idle",
                    "updated_at": _now_iso(),
                }
                for environment in self._environments
            }
            self._last_error = ""
            self._connection_message = "Connecting"
            self._last_refresh = time.monotonic()
            self._remember_session = remember
            self._restoring_session = False
        runtime_thread.start()

    def _stop_runtime(self, *, revoke: bool) -> None:
        with self._lock:
            runtime = self._runtime
            runtime_thread = self._runtime_thread
            api = self._api
            self._runtime = None
            self._runtime_thread = None
            self._api = None
            self._identity = {}
            self._environments = []
            self._environment_states = {}
            self._connection_message = ""
            self._last_refresh = 0.0
        if runtime is not None:
            runtime.shutdown()
        if runtime_thread is not None and runtime_thread is not threading.current_thread():
            runtime_thread.join(timeout=35.0)
        if api is not None:
            if revoke:
                try:
                    api.logout_device()
                except Exception:
                    pass
            api.close()

    def restore_saved_session(self) -> None:
        with self._operation_lock:
            session = self._saved_session
            if session is None or self._api is not None:
                with self._lock:
                    self._restoring_session = False
                return
            api = CloudAgentClient(self.cloud_url, session["device_token"])
            try:
                result = api.client_session()
            except AgentAPIError as exc:
                api.close()
                if exc.status_code == HTTPStatus.UNAUTHORIZED:
                    clear_workspace_session(self.root)
                    self._saved_session = None
                    self._set_error("saved session expired; sign in again")
                else:
                    self._set_error(exc)
                with self._lock:
                    self._restoring_session = False
                return
            except Exception as exc:
                api.close()
                self._set_error(exc)
                with self._lock:
                    self._restoring_session = False
                return
            self._activate_session(api, result, remember=True)

    def login(
        self,
        email: str,
        password: str,
        organization_id: str = "",
        *,
        remember: bool = True,
    ) -> None:
        email = email.strip()
        if not email or not password:
            raise WorkspaceError("email and password are required")
        with self._operation_lock:
            with self._lock:
                self._last_notice = ""
            self._stop_runtime(revoke=True)
            clear_workspace_session(self.root)
            self._saved_session = None
            result = login_device(
                self.cloud_url,
                email=email,
                password=password,
                organization_id=(organization_id or self.default_organization_id).strip(),
                device_uid=self.device_uid,
                device_name=self.device_name,
            )
            api = CloudAgentClient(self.cloud_url, result["device_token"])
            try:
                if remember:
                    save_workspace_session(self.root, self.cloud_url, result)
                    self._saved_session = {
                        "device_token": result["device_token"],
                        "expires_at": result["session_expires_at"],
                    }
                self._activate_session(api, result, remember=remember)
            except Exception:
                try:
                    api.logout_device()
                except Exception:
                    pass
                api.close()
                clear_workspace_session(self.root)
                self._saved_session = None
                raise

    def register(
        self,
        email: str,
        password: str,
        password_confirmation: str,
        display_name: str,
    ) -> dict[str, Any]:
        email = email.strip()
        display_name = display_name.strip()
        if not email or not password or not display_name:
            raise WorkspaceError("name, email, and password are required")
        if password != password_confirmation:
            raise WorkspaceError("passwords do not match")
        with self._operation_lock:
            with self._lock:
                if self._api is not None:
                    raise WorkspaceError("sign out before creating another account")
                self._last_error = ""
                self._last_notice = ""
            result = register_client_account(
                self.cloud_url,
                email=email,
                password=password,
                display_name=display_name,
            )
            clear_workspace_session(self.root)
            self._saved_session = None
            with self._lock:
                self.default_email = email
                self._restoring_session = False
                self._last_notice = ACCOUNT_PENDING_NOTICE
            return result

    def logout(self) -> None:
        with self._operation_lock:
            self._stop_runtime(revoke=True)
            clear_workspace_session(self.root)
            self._saved_session = None
            with self._lock:
                self._remember_session = False
                self._restoring_session = False
                self._last_error = ""
                self._last_notice = ""

    def close(self) -> None:
        with self._operation_lock:
            self._stop_runtime(revoke=not self._remember_session)

    def _require_api(self) -> CloudAgentClient:
        with self._lock:
            api = self._api
        if api is None:
            raise WorkspaceError("sign in to the workspace first")
        return api

    def refresh_environments(self, *, force: bool = True) -> None:
        with self._lock:
            if self._api is None:
                return
            if not force and time.monotonic() - self._last_refresh < 2.0:
                return
            api = self._api
        try:
            environments = api.list_environments()
        except Exception as exc:
            self._set_error(exc)
            return
        with self._lock:
            if api is not self._api:
                return
            self._environments = environments
            self._last_refresh = time.monotonic()
            for environment in environments:
                self._environment_states.setdefault(
                    str(environment["id"]),
                    {"phase": "idle", "updated_at": _now_iso()},
                )

    def create_environment(self, payload: dict[str, Any]) -> dict[str, Any]:
        api = self._require_api()
        try:
            environment = api.create_environment(payload)
        except Exception as exc:
            self._set_error(exc)
            raise
        with self._lock:
            self._environments.insert(0, environment)
            self._environment_states[str(environment["id"])] = {
                "phase": "idle",
                "updated_at": _now_iso(),
            }
            self._last_error = ""
        return environment

    def launch(self, environment_id: str) -> dict[str, Any]:
        api = self._require_api()
        self.refresh_environments(force=True)
        with self._lock:
            environment = next(
                (
                    item
                    for item in self._environments
                    if item.get("id") == environment_id
                ),
                None,
            )
        if environment is None:
            raise WorkspaceError("environment not found")
        result = api.request_launch(environment_id, int(environment["revision"]))
        self._report_environment_state(environment_id, "queued", {})
        self.clear_error()
        return result

    def stop(self, environment_id: str) -> dict[str, Any]:
        api = self._require_api()
        result = api.request_stop(environment_id)
        self._report_environment_state(environment_id, "stop_queued", {})
        self.clear_error()
        return result

    def public_state(self) -> dict[str, Any]:
        self.refresh_environments(force=False)
        with self._lock:
            signed_in = self._api is not None
            return {
                "signed_in": signed_in,
                "restoring_session": self._restoring_session,
                "cloud_url": self.cloud_url,
                "default_email": self.default_email,
                "default_organization_id": self.default_organization_id,
                "user": dict(self._identity.get("user") or {}),
                "organization": dict(self._identity.get("organization") or {}),
                "agent": dict(self._identity.get("agent") or {}),
                "environments": list(self._environments),
                "environment_states": dict(self._environment_states),
                "connection_message": self._connection_message,
                "last_error": self._last_error,
                "last_notice": self._last_notice,
            }


class _WorkspaceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], app: WorkspaceApplication) -> None:
        self.app = app
        super().__init__(address, _WorkspaceRequestHandler)


class _WorkspaceRequestHandler(BaseHTTPRequestHandler):
    server: _WorkspaceHTTPServer
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> WorkspaceApplication:
        return self.server.app

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _host_allowed(self) -> bool:
        try:
            hostname = urlparse(f"http://{self.headers.get('Host', '')}").hostname
        except ValueError:
            return False
        return hostname in LOOPBACK_HOSTS

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urlparse(origin)
            host = urlparse(f"http://{self.headers.get('Host', '')}")
            origin_port = parsed.port
            host_port = host.port
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and parsed.hostname in LOOPBACK_HOSTS
            and host.hostname in LOOPBACK_HOSTS
            and origin_port == host_port
        )

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _redirect(self, location: str = "/") -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _request_allowed(self) -> bool:
        if self._host_allowed() and self._origin_allowed():
            return True
        self.close_connection = True
        self._error(HTTPStatus.FORBIDDEN, "request origin is not allowed")
        return False

    def _read_body(self, expected_content_type: str) -> bytes:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type != expected_content_type:
            raise WorkspaceError(f"Content-Type must be {expected_content_type}")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise WorkspaceError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise WorkspaceError("request body has an invalid size")
        return self.rfile.read(length)

    def _read_json(self) -> dict[str, Any]:
        try:
            value = json.loads(self._read_body("application/json"))
        except json.JSONDecodeError as exc:
            raise WorkspaceError("request body is not valid JSON") from exc
        if not isinstance(value, dict):
            raise WorkspaceError("request body must be a JSON object")
        return value

    def _read_form(self) -> dict[str, str]:
        try:
            parsed = parse_qs(
                self._read_body("application/x-www-form-urlencoded").decode("utf-8"),
                keep_blank_values=True,
                max_num_fields=80,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise WorkspaceError("form body is invalid") from exc
        return {key: values[-1] for key, values in parsed.items() if values}

    def _json_mutation_allowed(self) -> bool:
        if not self._request_allowed():
            return False
        if self.headers.get("X-Cloak-CSRF") == self.app.csrf_token:
            return True
        self.close_connection = True
        self._error(HTTPStatus.FORBIDDEN, "invalid session token")
        return False

    def _form_mutation_allowed(self, form: dict[str, str]) -> bool:
        if form.get("csrf_token") == self.app.csrf_token:
            return True
        self.close_connection = True
        self._error(HTTPStatus.FORBIDDEN, "invalid session token")
        return False

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if not self._host_allowed():
            self._error(HTTPStatus.FORBIDDEN, "request host is not allowed")
            return
        if path == "/api/session":
            self._json(
                HTTPStatus.OK,
                {"csrf_token": self.app.csrf_token, "state": self.app.public_state()},
            )
            return
        if path == "/api/state":
            self._json(HTTPStatus.OK, {"state": self.app.public_state()})
            return
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        asset = assets.get(path)
        if asset is None:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        try:
            self._send(
                HTTPStatus.OK,
                (self.app.assets_dir / asset[0]).read_bytes(),
                asset[1],
            )
        except FileNotFoundError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "workspace asset is missing")

    def _environment_action(self) -> tuple[str, str] | None:
        parts = [part for part in self.path.split("?", 1)[0].split("/") if part]
        if len(parts) == 4 and parts[:2] == ["api", "environments"]:
            return parts[2], parts[3]
        return None

    @staticmethod
    def _integer(form: dict[str, str], name: str) -> Optional[int]:
        value = form.get(name, "").strip()
        if not value:
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise WorkspaceError(f"{name} must be an integer") from exc

    def _environment_form_payload(self, form: dict[str, str]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": form.get("name", "").strip(),
            "storage_policy": form.get("storage_policy", "shared"),
            "proxy": form.get("proxy", "").strip(),
            "tags": [
                value.strip()
                for value in form.get("tags", "").split(",")
                if value.strip()
            ],
        }
        config: dict[str, Any] = {}
        for name in (
            "timezone",
            "location",
            "locale",
            "startup_url",
            "fingerprint_platform",
            "fingerprint_brand",
            "fingerprint_brand_version",
            "fingerprint_platform_version",
            "gpu_vendor",
            "gpu_renderer",
        ):
            value = form.get(name, "").strip()
            if value:
                config[name] = value
        for name in (
            "fingerprint_seed",
            "storage_quota_mb",
            "hardware_concurrency",
            "device_memory_gb",
            "screen_width",
            "screen_height",
            "taskbar_height",
        ):
            value = self._integer(form, name)
            if value is not None:
                config[name] = value
        for name in (
            "headless",
            "humanize",
            "geoip",
            "fingerprint_noise",
            "allow_third_party_cookies",
        ):
            if name in form:
                config[name] = True
        if "fingerprint_noise" not in form:
            config["fingerprint_noise"] = False
        payload["config"] = config
        return payload

    def do_POST(self) -> None:
        if not self._request_allowed():
            return
        path = self.path.split("?", 1)[0]
        try:
            if path in {"/api/login", "/api/register", "/api/environments"}:
                form = self._read_form()
                if not self._form_mutation_allowed(form):
                    return
                if path == "/api/login":
                    try:
                        self.app.login(
                            form.get("email", ""),
                            form.get("password", ""),
                            form.get("organization_id", ""),
                            remember=form.get("remember") == "1",
                        )
                    except Exception as exc:
                        self.app._set_error(exc)
                    self._redirect()
                    return
                if path == "/api/register":
                    try:
                        self.app.register(
                            form.get("email", ""),
                            form.get("password", ""),
                            form.get("password_confirmation", ""),
                            form.get("display_name", ""),
                        )
                    except Exception as exc:
                        self.app._set_error(exc)
                        self._redirect("/?mode=register")
                        return
                    self._redirect()
                    return
                try:
                    self.app.create_environment(self._environment_form_payload(form))
                except Exception:
                    pass
                self._redirect()
                return
            if not self._json_mutation_allowed():
                return
            self._read_json()
            if path == "/api/logout":
                self.app.logout()
                self._json(HTTPStatus.OK, {"signed_out": True})
                return
            if path == "/api/refresh":
                self.app.refresh_environments(force=True)
                self._json(HTTPStatus.OK, {"state": self.app.public_state()})
                return
            action = self._environment_action()
            if action is None:
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            environment_id, verb = action
            if verb == "launch":
                result = self.app.launch(environment_id)
            elif verb == "stop":
                result = self.app.stop(environment_id)
            else:
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            self._json(HTTPStatus.ACCEPTED, result)
        except WorkspaceError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            self.app._set_error(exc)
            self._error(HTTPStatus.BAD_GATEWAY, str(exc)[:1000])


def run_workspace(
    cloud_url: str,
    root: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8766,
    open_browser: bool = True,
    email: str = "",
    organization_id: str = "",
    device_name: str = "",
    poll_interval: float = 1.0,
) -> None:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("the workspace can only listen on a loopback address")
    app = WorkspaceApplication(
        cloud_url,
        root,
        email=email,
        organization_id=organization_id,
        device_name=device_name,
        poll_interval=poll_interval,
    )
    server = _WorkspaceHTTPServer((host, port), app)
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else actual_host
    if ":" in browser_host:
        browser_host = f"[{browser_host}]"
    url = f"http://{browser_host}:{actual_port}"
    print(f"CloakBrowser Workspace: {url}")
    print(f"Cloud control plane: {cloud_url}")
    print(f"Workspace data: {root}")
    restore_thread = threading.Thread(
        target=app.restore_saved_session,
        name="cloak-workspace-session-restore",
        daemon=True,
    )
    restore_thread.start()
    if open_browser:
        timer = threading.Timer(0.25, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        app.close()
