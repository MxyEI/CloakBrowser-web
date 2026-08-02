"""Local Agent heartbeat client for the collaborative cloud control plane."""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from .._version import __version__
from ..config import get_cache_dir
from .constants import AGENT_TOKEN_PREFIX


DEFAULT_CLOUD_URL = "http://127.0.0.1:8777"


def add_agent_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "agent", help="Run a local execution Agent for CloakBrowser Cloud"
    )
    parser.add_argument(
        "--cloud-url",
        default=os.environ.get("CLOAKBROWSER_CLOUD_URL", DEFAULT_CLOUD_URL),
        help=f"Cloud control-plane URL (default: {DEFAULT_CLOUD_URL})",
    )
    parser.add_argument(
        "--token-file",
        help="Agent token file (default: CLOAKBROWSER_AGENT_TOKEN or cloud-agent.token)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=20,
        help="Heartbeat interval in seconds (default: 20)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Remote task polling interval in seconds (default: 2)",
    )
    parser.add_argument(
        "--data-dir",
        help="Local Agent state directory (default: CloakBrowser cache/cloud-agent)",
    )
    parser.add_argument("--once", action="store_true", help="Send one heartbeat and exit")
    return parser


def _is_loopback_hostname(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_cloud_url(value: str) -> str:
    url = value.strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("cloud URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("cloud URL must not contain credentials, a query, or a fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("cloud URL must not contain a path")
    if parsed.scheme == "http" and not _is_loopback_hostname(parsed.hostname):
        raise ValueError("agent credentials require HTTPS for non-loopback cloud URLs")
    return url


def _default_token_file() -> Path:
    return get_cache_dir() / "cloud-agent.token"


def load_agent_token(token_file: Optional[str] = None) -> str:
    configured = os.environ.get("CLOAKBROWSER_AGENT_TOKEN", "").strip()
    if configured:
        token = configured
    else:
        path = Path(token_file).expanduser() if token_file else _default_token_file()
        if not path.is_file():
            raise ValueError(
                "agent token is missing; set CLOAKBROWSER_AGENT_TOKEN or create "
                f"{path} with owner-only permissions"
            )
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError(f"agent token file must use owner-only permissions: {path}")
        token = path.read_text(encoding="utf-8").strip()
    if not token.startswith(AGENT_TOKEN_PREFIX) or len(token) > 160:
        raise ValueError("agent token has an invalid format")
    return token


def heartbeat_payload() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "platform": f"{platform.system()} {platform.machine()}".strip(),
        "version": __version__,
        "capabilities": {
            "heartbeat": True,
            "leases": True,
            "browser_launch": True,
            "snapshot_sync": True,
            "secret_sync": True,
            "extension_sync": True,
        },
    }


def send_heartbeat(cloud_url: str, token: str) -> dict[str, Any]:
    with httpx.Client(follow_redirects=False, timeout=10.0) as client:
        response = client.post(
            f"{cloud_url}/api/agent/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json=heartbeat_payload(),
        )
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise RuntimeError(f"agent heartbeat failed ({response.status_code}): {detail}")
    return response.json()


def cmd_agent(args: argparse.Namespace) -> None:
    cloud_url = validate_cloud_url(args.cloud_url)
    token = load_agent_token(args.token_file)
    if not 5 <= args.interval <= 300:
        raise ValueError("heartbeat interval must be between 5 and 300 seconds")
    poll_interval = getattr(args, "poll_interval", 2.0)
    if not 0.25 <= poll_interval <= 30:
        raise ValueError("task polling interval must be between 0.25 and 30 seconds")
    print(f"CloakBrowser Agent: {cloud_url}")
    if args.once:
        try:
            result = send_heartbeat(cloud_url, token)
        except (httpx.HTTPError, RuntimeError) as exc:
            raise RuntimeError(str(exc)) from exc
        print(f"Agent online: {result['agent_id']}")
        return

    from .agent_runtime import AgentRuntime, CloudAgentClient

    configured_data_dir = getattr(args, "data_dir", None)
    data_dir = (
        Path(configured_data_dir).expanduser()
        if configured_data_dir
        else get_cache_dir() / "cloud-agent"
    )
    client = CloudAgentClient(cloud_url, token)
    runtime = AgentRuntime(
        client,
        data_dir,
        heartbeat_payload=heartbeat_payload(),
        poll_interval=poll_interval,
        heartbeat_interval=float(args.interval),
        reporter=print,
    )
    try:
        runtime.run()
    finally:
        client.close()
