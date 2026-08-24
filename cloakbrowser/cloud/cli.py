"""CLI entry point for the cloud control plane."""

from __future__ import annotations

import argparse
import os
import webbrowser
from typing import Any

from .settings import CloudSettings


def add_cloud_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "cloud", help="Run the collaborative cloud control plane"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8777, help="HTTP port (default: 8777)")
    parser.add_argument("--no-open", action="store_true", help="Do not open the system browser")
    parser.add_argument("--data-dir", help="SQLite data directory (default: ~/.cloakbrowser/cloud)")
    parser.add_argument(
        "--container-loopback",
        action="store_true",
        help=(
            "Allow local HTTP inside a container whose published host port is "
            "restricted to loopback"
        ),
    )
    return parser


def cmd_cloud(args: argparse.Namespace) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            'Cloud dependencies are not installed. Run: pip install "cloakbrowser[cloud]"'
        ) from exc

    from .app import create_app

    settings = CloudSettings.from_env(args.data_dir)
    settings.validate_bind(args.host, container_loopback=args.container_loopback)
    app = create_app(settings)
    display_host = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
    if ":" in display_host:
        display_host = f"[{display_host}]"
    url = f"http://{display_host}:{args.port}"
    label = (
        "CloakBrowser Cloud upstream"
        if settings.cookie_secure
        else "CloakBrowser Cloud"
    )
    print(f"{label}: {url}")
    print(f"Database: {settings.database_url.split('@')[-1]}")
    if settings.development_secret:
        print("Mode: local development (ephemeral application secret)")
    if settings.cookie_secure:
        print("Public access: use the HTTPS URL configured at your reverse proxy")
    if args.container_loopback:
        print("Container access: publish this port only on host loopback")
    if (
        not args.no_open
        and not settings.cookie_secure
        and args.host in {"127.0.0.1", "localhost", "::1"}
    ):
        webbrowser.open(url)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=os.environ.get("CLOAKBROWSER_CLOUD_LOG_LEVEL", "info"),
    )
