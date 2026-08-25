"""Interactive local workspace for user-assigned cloud environments."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
import platform
import stat
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

from ..config import get_cache_dir
from .agent_cli import heartbeat_payload, validate_cloud_url
from .agent_runtime import AgentRuntime, CloudAgentClient
from .security import DEVICE_TOKEN_PREFIX


DEFAULT_WORKSPACE_CLOUD_URL = "https://45-152-67-19.sslip.io:39177"
WORKSPACE_SESSION_FILENAME = "session.json"
WORKSPACE_SESSION_VERSION = 1


def add_workspace_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "workspace",
        aliases=["client"],
        help="Sign in and run cloud environments assigned to this user",
    )
    parser.add_argument(
        "--cloud-url",
        default=os.environ.get(
            "CLOAKBROWSER_CLOUD_URL", DEFAULT_WORKSPACE_CLOUD_URL
        ),
        help=f"Cloud control-plane URL (default: {DEFAULT_WORKSPACE_CLOUD_URL})",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("CLOAKBROWSER_CLOUD_EMAIL", ""),
        help="Cloud account email (entered in the local page when omitted)",
    )
    parser.add_argument(
        "--organization-id",
        default=os.environ.get("CLOAKBROWSER_CLOUD_ORGANIZATION_ID", ""),
        help="Team UUID when the account belongs to multiple teams",
    )
    parser.add_argument("--device-name", help="Device label shown in the cloud console")
    parser.add_argument(
        "--data-dir",
        help="Local workspace directory (default: CloakBrowser cache/cloud-workspace)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Cloud task polling interval in seconds (default: 1)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Sign in, list assigned environments, and exit",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Use the interactive terminal client instead of the local workspace UI",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Workspace loopback host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8766,
        help="Workspace UI port (default: 8766; use 0 for any free port)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the system browser for the workspace UI",
    )
    return parser


def _workspace_root(configured: Optional[str]) -> Path:
    return (
        Path(configured).expanduser()
        if configured
        else get_cache_dir() / "cloud-workspace"
    )


def load_or_create_device_uid(root: Path) -> str:
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    path = root / "device.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        device_uid = str(uuid.UUID(str(value.get("device_uid"))))
    except FileNotFoundError:
        device_uid = str(uuid.uuid4())
        temporary = path.with_name(f".{path.name}-{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as output:
                json.dump({"device_uid": device_uid}, output, separators=(",", ":"))
                output.write("\n")
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"workspace device identity is invalid: {path}") from exc
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(f"workspace device identity must use owner-only permissions: {path}")
    return device_uid


def save_workspace_session(
    root: Path,
    cloud_url: str,
    login: dict[str, Any],
) -> None:
    token = login.get("device_token")
    expires_at = login.get("session_expires_at")
    if (
        not isinstance(token, str)
        or not token.startswith(DEVICE_TOKEN_PREFIX)
        or len(token) > 160
        or not isinstance(expires_at, str)
    ):
        raise ValueError("cloud returned an invalid persistent device session")
    try:
        expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("cloud returned an invalid device session expiry") from exc
    if expiration.tzinfo is None or expiration <= datetime.now(timezone.utc):
        raise ValueError("cloud returned an expired device session")

    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    path = root / WORKSPACE_SESSION_FILENAME
    temporary = path.with_name(f".{path.name}-{uuid.uuid4().hex}.tmp")
    payload = {
        "version": WORKSPACE_SESSION_VERSION,
        "cloud_url": cloud_url,
        "device_token": token,
        "expires_at": expiration.astimezone(timezone.utc).isoformat(),
    }
    try:
        with temporary.open("x", encoding="utf-8") as output:
            json.dump(payload, output, separators=(",", ":"))
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


def clear_workspace_session(root: Path) -> None:
    (root / WORKSPACE_SESSION_FILENAME).unlink(missing_ok=True)


def load_workspace_session(root: Path, cloud_url: str) -> Optional[dict[str, str]]:
    path = root / WORKSPACE_SESSION_FILENAME
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"workspace session must be a regular file: {path}")
        if os.name != "nt" and metadata.st_mode & 0o077:
            raise ValueError(
                f"workspace session must use owner-only permissions: {path}"
            )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"workspace session is invalid: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict) or value.get("version") != WORKSPACE_SESSION_VERSION:
        raise ValueError(f"workspace session is invalid: {path}")
    token = value.get("device_token")
    expires_at = value.get("expires_at")
    if (
        value.get("cloud_url") != cloud_url
        or not isinstance(token, str)
        or not token.startswith(DEVICE_TOKEN_PREFIX)
        or len(token) > 160
        or not isinstance(expires_at, str)
    ):
        clear_workspace_session(root)
        return None
    try:
        expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        clear_workspace_session(root)
        return None
    if expiration.tzinfo is None or expiration <= datetime.now(timezone.utc):
        clear_workspace_session(root)
        return None
    return {"device_token": token, "expires_at": expires_at}


def _response_detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail", response.text)
    except (AttributeError, ValueError):
        return response.text
    if isinstance(detail, list):
        messages = [
            str(item.get("msg", "")).strip()
            for item in detail
            if isinstance(item, dict) and item.get("msg")
        ]
        return "; ".join(messages) or "request validation failed"
    return str(detail)


def register_client_account(
    cloud_url: str,
    *,
    email: str,
    password: str,
    display_name: str,
) -> dict[str, Any]:
    payload = {
        "email": email,
        "password": password,
        "display_name": display_name,
    }
    try:
        with httpx.Client(follow_redirects=False, timeout=15.0, trust_env=False) as client:
            response = client.post(f"{cloud_url}/api/client/register", json=payload)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"cloud registration failed: {exc}") from exc
    if response.status_code >= 400:
        raise RuntimeError(
            f"cloud registration failed ({response.status_code}): "
            f"{_response_detail(response)}"
        )
    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError("cloud registration returned an invalid response") from exc
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("user"), dict)
        or result.get("access_status") != "pending"
    ):
        raise RuntimeError("cloud registration returned an invalid account")
    return result


def login_device(
    cloud_url: str,
    *,
    email: str,
    password: str,
    organization_id: str,
    device_uid: str,
    device_name: str,
) -> dict[str, Any]:
    system_payload = heartbeat_payload()
    payload = {
        "email": email,
        "password": password,
        "organization_id": organization_id or None,
        "device_uid": device_uid,
        "device_name": device_name,
        **system_payload,
    }
    try:
        with httpx.Client(follow_redirects=False, timeout=15.0, trust_env=False) as client:
            response = client.post(f"{cloud_url}/api/client/login", json=payload)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"cloud login failed: {exc}") from exc
    if response.status_code >= 400:
        raise RuntimeError(
            f"cloud login failed ({response.status_code}): {_response_detail(response)}"
        )
    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError("cloud login returned an invalid response") from exc
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("device_token"), str)
        or not isinstance(result.get("environments"), list)
    ):
        raise RuntimeError("cloud login returned an invalid device session")
    return result


def _print_environments(environments: list[dict[str, Any]]) -> None:
    if not environments:
        print("No environments are assigned to this account.")
        return
    print("Assigned environments:")
    for index, environment in enumerate(environments, start=1):
        storage = environment.get("storage_policy", "unknown")
        print(
            f"  {index}. {environment.get('name', 'Unnamed')} "
            f"[{storage}] {environment.get('id', '')}"
        )


def _resolve_environment(
    value: str,
    environments: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        index = int(value)
    except ValueError:
        index = 0
    if 1 <= index <= len(environments):
        return environments[index - 1]
    for environment in environments:
        if environment.get("id") == value:
            return environment
    raise ValueError("environment must be a listed number or UUID")


def cmd_workspace(args: argparse.Namespace) -> None:
    cloud_url = validate_cloud_url(args.cloud_url)
    if not 0.25 <= args.poll_interval <= 30:
        raise ValueError("task polling interval must be between 0.25 and 30 seconds")
    root = _workspace_root(args.data_dir)
    if not args.cli and not args.once:
        from .workspace_app import run_workspace

        run_workspace(
            cloud_url,
            root,
            host=args.host,
            port=args.port,
            open_browser=not args.no_open,
            email=args.email.strip(),
            organization_id=args.organization_id.strip(),
            device_name=(args.device_name or platform.node() or "Desktop").strip(),
            poll_interval=args.poll_interval,
        )
        return
    device_uid = load_or_create_device_uid(root)
    email = args.email.strip() or input("Cloud email: ").strip()
    password = os.environ.get("CLOAKBROWSER_CLOUD_PASSWORD", "") or getpass.getpass(
        "Cloud password: "
    )
    if not email or not password:
        raise ValueError("email and password are required")
    device_name = (args.device_name or platform.node() or "Desktop").strip()
    login = login_device(
        cloud_url,
        email=email,
        password=password,
        organization_id=args.organization_id.strip(),
        device_uid=device_uid,
        device_name=device_name,
    )
    user = login.get("user") or {}
    organization = login.get("organization") or {}
    print(
        f"Signed in as {user.get('display_name', email)} "
        f"to {organization.get('name', 'team')}"
    )
    environments = list(login["environments"])
    _print_environments(environments)
    if args.once:
        return

    api = CloudAgentClient(cloud_url, login["device_token"])
    runtime = AgentRuntime(
        api,
        root,
        heartbeat_payload=heartbeat_payload(),
        poll_interval=args.poll_interval,
        heartbeat_interval=20.0,
        reporter=print,
    )
    runtime_thread = threading.Thread(
        target=runtime.run,
        name="cloak-cloud-workspace",
        daemon=True,
    )
    runtime_thread.start()
    print("Commands: list, launch <number|uuid>, stop <number|uuid>, quit")
    try:
        while True:
            try:
                command = input("workspace> ").strip()
            except EOFError:
                command = "quit"
            if not command:
                continue
            verb, _, argument = command.partition(" ")
            verb = verb.lower()
            if verb in {"quit", "exit"}:
                break
            if verb == "list":
                environments = api.list_environments()
                _print_environments(environments)
                continue
            if verb not in {"launch", "stop"} or not argument.strip():
                print("Commands: list, launch <number|uuid>, stop <number|uuid>, quit")
                continue
            try:
                environment = _resolve_environment(argument.strip(), environments)
                if verb == "launch":
                    api.request_launch(
                        str(environment["id"]),
                        int(environment["revision"]),
                    )
                else:
                    api.request_stop(str(environment["id"]))
                print(f"{verb.capitalize()} queued: {environment.get('name', environment['id'])}")
            except Exception as exc:
                print(f"Command failed: {exc}")
    finally:
        runtime.shutdown()
        runtime_thread.join(timeout=35.0)
        api.close()
