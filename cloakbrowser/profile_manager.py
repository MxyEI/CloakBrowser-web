"""Local browser-profile manager and management UI server.

The manager binds a fingerprint seed, persistent Chromium data directory, and
proxy configuration into one reusable environment. It intentionally listens on
loopback only: profile files can contain proxy credentials and browser sessions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlsplit

from .config import get_cache_dir


PROFILE_VERSION = 1
MAX_REQUEST_BYTES = 512 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_PROFILE_ID_RE = re.compile(r"^env_[a-f0-9]{12}$")
_TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+./-]{0,80}$")
_LOCALE_RE = re.compile(r"^[A-Za-z0-9-]{0,35}$")
_VERSION_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,7}){0,3}$")
_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}
PROFILE_EXPORT_FORMAT = "cloakbrowser-profile-export"
PROFILE_EXPORT_VERSION = 1
_LOCATION_PRESETS: dict[str, dict[str, float]] = {
    "new-york": {"latitude": 40.7128, "longitude": -74.0060, "accuracy": 50.0},
    "chicago": {"latitude": 41.8781, "longitude": -87.6298, "accuracy": 50.0},
    "denver": {"latitude": 39.7392, "longitude": -104.9903, "accuracy": 50.0},
    "phoenix": {"latitude": 33.4484, "longitude": -112.0740, "accuracy": 50.0},
    "los-angeles": {"latitude": 34.0522, "longitude": -118.2437, "accuracy": 50.0},
    "anchorage": {"latitude": 61.2181, "longitude": -149.9003, "accuracy": 50.0},
    "honolulu": {"latitude": 21.3099, "longitude": -157.8581, "accuracy": 50.0},
}
_EXPORT_FIELDS = (
    "name",
    "group",
    "tags",
    "fingerprint_seed",
    "proxy",
    "lock_proxy_ip",
    "geoip",
    "headless",
    "humanize",
    "timezone",
    "location",
    "locale",
    "startup_url",
    "storage_quota_mb",
    "fingerprint_platform",
    "fingerprint_brand",
    "fingerprint_brand_version",
    "fingerprint_platform_version",
    "hardware_concurrency",
    "device_memory_gb",
    "screen_width",
    "screen_height",
    "gpu_vendor",
    "gpu_renderer",
    "taskbar_height",
    "fingerprint_noise",
    "allow_third_party_cookies",
    "notes",
)
_FINGERPRINT_PLATFORMS = {"", "windows", "macos"}
_FINGERPRINT_BRANDS = {"", "Chrome", "Edge", "Opera", "Vivaldi"}
_ADVANCED_FINGERPRINT_DEFAULTS: dict[str, Any] = {
    "fingerprint_platform": "",
    "fingerprint_brand": "",
    "fingerprint_brand_version": "",
    "fingerprint_platform_version": "",
    "hardware_concurrency": 0,
    "device_memory_gb": 0,
    "screen_width": 0,
    "screen_height": 0,
    "gpu_vendor": "",
    "gpu_renderer": "",
    "taskbar_height": -1,
    "fingerprint_noise": True,
    "allow_third_party_cookies": False,
}
_FINGERPRINT_DETAILS_SCRIPT = """
async () => {
  const details = {
    user_agent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: Array.from(navigator.languages || []),
    hardware_concurrency: navigator.hardwareConcurrency ?? null,
    device_memory_gb: navigator.deviceMemory ?? null,
    max_touch_points: navigator.maxTouchPoints ?? null,
    cookie_enabled: navigator.cookieEnabled,
    do_not_track: navigator.doNotTrack,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    screen: {
      width: screen.width,
      height: screen.height,
      avail_width: screen.availWidth,
      avail_height: screen.availHeight,
      color_depth: screen.colorDepth,
      pixel_depth: screen.pixelDepth,
    },
    viewport: {
      inner_width: innerWidth,
      inner_height: innerHeight,
      outer_width: outerWidth,
      outer_height: outerHeight,
      device_pixel_ratio: devicePixelRatio,
    },
    webgl_vendor: "",
    webgl_renderer: "",
    storage_quota_mb: null,
  };
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    const extension = gl && gl.getExtension("WEBGL_debug_renderer_info");
    if (gl && extension) {
      details.webgl_vendor = gl.getParameter(extension.UNMASKED_VENDOR_WEBGL) || "";
      details.webgl_renderer = gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) || "";
    }
  } catch (_) {}
  try {
    const estimate = navigator.storage && navigator.storage.estimate
      ? await navigator.storage.estimate()
      : null;
    if (estimate && estimate.quota) details.storage_quota_mb = Math.round(estimate.quota / 1048576);
  } catch (_) {}
  return details;
}
"""


class ProfileError(ValueError):
    """A profile request failed validation."""


class ProfileNotFound(ProfileError):
    """The requested profile does not exist."""


class ProfileConflict(ProfileError):
    """The requested operation conflicts with a running environment."""


class ProxyCheckError(RuntimeError):
    """A proxy could not provide a verifiable public exit IP."""


class FingerprintPreviewError(RuntimeError):
    """A temporary browser could not produce a fingerprint preview."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _manager_dir() -> Path:
    override = os.environ.get("CLOAKBROWSER_MANAGER_DIR")
    return Path(override).expanduser() if override else get_cache_dir() / "manager"


def _make_profile_id() -> str:
    return f"env_{secrets.token_hex(6)}"


def _random_seed() -> int:
    return secrets.randbelow(90000) + 10000


def _as_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ProfileError(f"{field_name} must be true or false")


def _clean_text(value: Any, field_name: str, max_length: int, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ProfileError(f"{field_name} must be a string")
    value = value.strip()
    if required and not value:
        raise ProfileError(f"{field_name} is required")
    if len(value) > max_length:
        raise ProfileError(f"{field_name} is too long")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ProfileError(f"{field_name} contains invalid characters")
    return value


def _validate_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ProfileError("tags must be an array")
    if len(value) > 10:
        raise ProfileError("tags cannot contain more than 10 items")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        tag = _clean_text(item, "tag", 24, required=True)
        key = tag.casefold()
        if key not in seen:
            result.append(tag)
            seen.add(key)
    return result


def _validate_proxy(value: Any) -> str:
    proxy = _clean_text(value, "proxy", 2048)
    if not proxy:
        return ""
    candidate = proxy if "://" in proxy else f"http://{proxy}"
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError as exc:
        raise ProfileError("proxy is not a valid URL") from exc
    if parsed.scheme.lower() not in _PROXY_SCHEMES:
        raise ProfileError("proxy scheme must be http, https, socks5, or socks5h")
    if not parsed.hostname:
        raise ProfileError("proxy host is required")
    return proxy


def _validate_proxy_scheme(value: Any) -> str:
    scheme = _clean_text(value, "proxy_scheme", 10, required=True).lower()
    if scheme not in _PROXY_SCHEMES:
        raise ProfileError("proxy scheme must be http, https, socks5, or socks5h")
    return scheme


def _replace_proxy_scheme(proxy: str, scheme: str) -> str:
    candidate = proxy if "://" in proxy else f"http://{proxy}"
    return urlsplit(candidate)._replace(scheme=scheme).geturl()


def _validate_startup_url(value: Any) -> str:
    startup_url = _clean_text(value, "startup_url", 2048) or "about:blank"
    if startup_url == "about:blank":
        return startup_url
    parsed = urlsplit(startup_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProfileError("startup_url must be an http(s) URL or about:blank")
    return startup_url


def _mask_proxy(proxy: str) -> str:
    if not proxy:
        return ""
    candidate = proxy if "://" in proxy else f"http://{proxy}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parsed.port:
            host = f"{host}:{parsed.port}"
        auth = ""
        if parsed.username is not None:
            auth = f"{parsed.username}:****@" if parsed.password is not None else f"{parsed.username}@"
        return f"{parsed.scheme}://{auth}{host}"
    except (TypeError, ValueError):
        return "configured"


def _redact_error(message: str, proxy: str) -> str:
    """Remove proxy URL and credentials before exposing launch errors to the UI."""
    if not proxy:
        return message
    redacted = message.replace(proxy, _mask_proxy(proxy))
    try:
        parsed = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        for secret in (parsed.username, parsed.password):
            if secret:
                redacted = redacted.replace(secret, "****")
    except ValueError:
        pass
    return redacted


def _fingerprint_launch_args(profile: dict[str, Any]) -> list[str]:
    """Build deterministic binary flags shared by previews and real sessions."""
    args = [
        f"--fingerprint={profile['fingerprint_seed']}",
        f"--fingerprint-storage-quota={profile['storage_quota_mb']}",
    ]
    value_flags = (
        ("fingerprint_platform", "--fingerprint-platform"),
        ("fingerprint_brand", "--fingerprint-brand"),
        ("fingerprint_brand_version", "--fingerprint-brand-version"),
        ("fingerprint_platform_version", "--fingerprint-platform-version"),
        ("hardware_concurrency", "--fingerprint-hardware-concurrency"),
        ("device_memory_gb", "--fingerprint-device-memory"),
        ("screen_width", "--fingerprint-screen-width"),
        ("screen_height", "--fingerprint-screen-height"),
        ("gpu_vendor", "--fingerprint-gpu-vendor"),
        ("gpu_renderer", "--fingerprint-gpu-renderer"),
    )
    for field_name, flag in value_flags:
        value = profile.get(field_name, _ADVANCED_FINGERPRINT_DEFAULTS[field_name])
        if value not in (None, "", 0):
            args.append(f"{flag}={value}")

    taskbar_height = profile.get("taskbar_height", -1)
    if taskbar_height is not None and taskbar_height >= 0:
        args.append(f"--fingerprint-taskbar-height={taskbar_height}")
    if not profile.get("fingerprint_noise", True):
        args.append("--fingerprint-noise=false")
    if profile.get("allow_third_party_cookies", False):
        args.append("--fingerprint-allow-3p-cookies")
    return args


def _apply_browser_locale_preferences(browser_data_dir: Path, locale: str) -> None:
    preferences_path = browser_data_dir / "Default" / "Preferences"
    if not locale and not preferences_path.exists():
        return
    try:
        preferences = json.loads(preferences_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        preferences = {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"could not update browser locale preference: {exc}") from exc
    if not isinstance(preferences, dict):
        raise ProfileError("browser locale preference file is invalid")

    intl = preferences.get("intl")
    if not isinstance(intl, dict):
        intl = {}
    if locale:
        language = locale.split("-", 1)[0]
        languages = locale if language == locale else f"{locale},{language}"
        intl["accept_languages"] = languages
        intl["selected_languages"] = languages
        preferences["intl"] = intl
    else:
        intl.pop("accept_languages", None)
        intl.pop("selected_languages", None)
        if intl:
            preferences["intl"] = intl
        else:
            preferences.pop("intl", None)

    preferences_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = preferences_path.with_name(f".Preferences-{secrets.token_hex(4)}.tmp")
    try:
        with temporary_path.open("x", encoding="utf-8") as handle:
            json.dump(preferences, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
        os.replace(temporary_path, preferences_path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _capture_fingerprint_details(context: Any) -> dict[str, Any]:
    details: dict[str, Any] = {}
    try:
        pages = context.pages
        page = pages[0] if pages else context.new_page()
        captured = page.evaluate(_FINGERPRINT_DETAILS_SCRIPT)
        if isinstance(captured, dict):
            details = captured
    except Exception:
        return {}

    # Device Memory requires a trustworthy origin. Fulfill a loopback request
    # inside Playwright so no network request or user navigation is needed, then
    # discard the temporary page immediately.
    if details.get("device_memory_gb") is None:
        probe = None
        try:
            probe = context.new_page()
            probe.route(
                "http://127.0.0.1/__cloakbrowser_fingerprint_probe__",
                lambda route: route.fulfill(
                    status=200,
                    content_type="text/html",
                    body="<!doctype html><title>Fingerprint probe</title>",
                ),
            )
            probe.goto(
                "http://127.0.0.1/__cloakbrowser_fingerprint_probe__",
                wait_until="commit",
                timeout=5_000,
            )
            secure_details = probe.evaluate(_FINGERPRINT_DETAILS_SCRIPT)
            if isinstance(secure_details, dict):
                details = secure_details
        except Exception:
            pass
        finally:
            if probe is not None:
                try:
                    probe.close()
                except Exception:
                    pass

    details["captured_at"] = _utc_now()
    return details


class ProfileStore:
    """File-backed store for reusable browser environments."""

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root) if root is not None else _manager_dir()
        self.profiles_dir = self.root / "profiles"
        self.trash_dir = self.root / "_trash"
        self._lock = threading.RLock()
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
            self.profiles_dir.chmod(0o700)
        except OSError:
            pass

    def _profile_dir(self, profile_id: str) -> Path:
        if not _PROFILE_ID_RE.fullmatch(profile_id):
            raise ProfileNotFound("environment not found")
        return self.profiles_dir / profile_id

    def _config_path(self, profile_id: str) -> Path:
        return self._profile_dir(profile_id) / "profile.json"

    def browser_data_dir(self, profile_id: str) -> Path:
        return self._profile_dir(profile_id) / "browser-data"

    def apply_browser_locale(self, profile_id: str, locale: str) -> None:
        """Persist Chromium's accepted languages without replacing other preferences."""
        with self._lock:
            self._read(profile_id)
            _apply_browser_locale_preferences(self.browser_data_dir(profile_id), locale)

    def _read(self, profile_id: str) -> dict[str, Any]:
        path = self._config_path(profile_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProfileNotFound("environment not found") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f"could not read environment: {exc}") from exc
        if not isinstance(data, dict) or data.get("id") != profile_id:
            raise ProfileError("environment file is invalid")
        return data

    def _write(self, profile: dict[str, Any]) -> None:
        profile_dir = self._profile_dir(profile["id"])
        profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            profile_dir.chmod(0o700)
        except OSError:
            pass
        path = profile_dir / "profile.json"
        temp = profile_dir / f".profile-{secrets.token_hex(4)}.tmp"
        try:
            with temp.open("x", encoding="utf-8") as handle:
                json.dump(profile, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
            try:
                temp.chmod(0o600)
            except OSError:
                pass
            os.replace(temp, path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def _validated_fields(
        self,
        payload: dict[str, Any],
        *,
        existing: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ProfileError("request body must be a JSON object")
        old = existing or {}

        name = _clean_text(payload.get("name", old.get("name")), "name", 80, required=True)
        raw_seed = payload.get("fingerprint_seed", old.get("fingerprint_seed", _random_seed()))
        if isinstance(raw_seed, bool):
            raise ProfileError("fingerprint_seed must be an integer")
        try:
            seed = int(raw_seed)
        except (TypeError, ValueError) as exc:
            raise ProfileError("fingerprint_seed must be an integer") from exc
        if not 1 <= seed <= 2_147_483_647:
            raise ProfileError("fingerprint_seed must be between 1 and 2147483647")

        proxy_scheme = (
            _validate_proxy_scheme(payload["proxy_scheme"])
            if "proxy_scheme" in payload
            else None
        )
        if payload.get("clear_proxy") is True:
            proxy = ""
        elif "proxy" in payload and payload["proxy"] not in (None, ""):
            proxy = _validate_proxy(payload["proxy"])
        else:
            proxy = old.get("proxy", "")
            if proxy and proxy_scheme:
                proxy = _replace_proxy_scheme(proxy, proxy_scheme)

        timezone_value = _clean_text(payload.get("timezone", old.get("timezone", "")), "timezone", 80)
        location = _clean_text(payload.get("location", old.get("location", "")), "location", 40)
        locale_value = _clean_text(payload.get("locale", old.get("locale", "")), "locale", 35)
        if not _TIMEZONE_RE.fullmatch(timezone_value):
            raise ProfileError("timezone contains invalid characters")
        if location and location not in _LOCATION_PRESETS:
            raise ProfileError("location is not a supported preset")
        if not _LOCALE_RE.fullmatch(locale_value):
            raise ProfileError("locale contains invalid characters")

        raw_quota = payload.get("storage_quota_mb", old.get("storage_quota_mb", 5000))
        if isinstance(raw_quota, bool):
            raise ProfileError("storage_quota_mb must be an integer")
        try:
            storage_quota_mb = int(raw_quota)
        except (TypeError, ValueError) as exc:
            raise ProfileError("storage_quota_mb must be an integer") from exc
        if not 256 <= storage_quota_mb <= 500_000:
            raise ProfileError("storage_quota_mb must be between 256 and 500000")

        fingerprint_platform = _clean_text(
            payload.get("fingerprint_platform", old.get("fingerprint_platform", "")),
            "fingerprint_platform",
            20,
        ).lower()
        if fingerprint_platform not in _FINGERPRINT_PLATFORMS:
            raise ProfileError("fingerprint_platform must be automatic, windows, or macos")

        raw_brand = _clean_text(
            payload.get("fingerprint_brand", old.get("fingerprint_brand", "")),
            "fingerprint_brand",
            20,
        )
        brand_lookup = {brand.casefold(): brand for brand in _FINGERPRINT_BRANDS}
        fingerprint_brand = brand_lookup.get(raw_brand.casefold())
        if fingerprint_brand is None:
            raise ProfileError("fingerprint_brand must be Chrome, Edge, Opera, or Vivaldi")

        fingerprint_brand_version = _clean_text(
            payload.get(
                "fingerprint_brand_version",
                old.get("fingerprint_brand_version", ""),
            ),
            "fingerprint_brand_version",
            40,
        )
        fingerprint_platform_version = _clean_text(
            payload.get(
                "fingerprint_platform_version",
                old.get("fingerprint_platform_version", ""),
            ),
            "fingerprint_platform_version",
            40,
        )
        for field_name, value in (
            ("fingerprint_brand_version", fingerprint_brand_version),
            ("fingerprint_platform_version", fingerprint_platform_version),
        ):
            if value and not _VERSION_RE.fullmatch(value):
                raise ProfileError(f"{field_name} must be a dotted numeric version")

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            raw_value = payload.get(name, old.get(name, default))
            if isinstance(raw_value, bool):
                raise ProfileError(f"{name} must be an integer")
            try:
                value = int(raw_value)
            except (TypeError, ValueError) as exc:
                raise ProfileError(f"{name} must be an integer") from exc
            if not minimum <= value <= maximum:
                raise ProfileError(f"{name} must be between {minimum} and {maximum}")
            return value

        hardware_concurrency = integer("hardware_concurrency", 0, 0, 64)
        device_memory_gb = integer("device_memory_gb", 0, 0, 8)
        if device_memory_gb not in {0, 1, 2, 4, 8}:
            raise ProfileError("device_memory_gb must be automatic, 1, 2, 4, or 8")
        screen_width = integer("screen_width", 0, 0, 7680)
        screen_height = integer("screen_height", 0, 0, 4320)
        if bool(screen_width) != bool(screen_height):
            raise ProfileError("screen_width and screen_height must both be automatic or both be set")
        if screen_width and screen_width < 800:
            raise ProfileError("screen_width must be at least 800")
        if screen_height and screen_height < 600:
            raise ProfileError("screen_height must be at least 600")
        taskbar_height = integer("taskbar_height", -1, -1, 240)
        gpu_vendor = _clean_text(
            payload.get("gpu_vendor", old.get("gpu_vendor", "")),
            "gpu_vendor",
            160,
        )
        gpu_renderer = _clean_text(
            payload.get("gpu_renderer", old.get("gpu_renderer", "")),
            "gpu_renderer",
            240,
        )
        if bool(gpu_vendor) != bool(gpu_renderer):
            raise ProfileError("gpu_vendor and gpu_renderer must both be automatic or both be set")

        def boolean(name: str, default: bool) -> bool:
            return _as_bool(payload.get(name, old.get(name, default)), name)

        lock_proxy_ip = False if payload.get("clear_proxy") is True else boolean("lock_proxy_ip", False)
        if lock_proxy_ip and not proxy:
            raise ProfileError("lock_proxy_ip requires a configured proxy")
        geoip = boolean("geoip", bool(proxy))
        if not proxy:
            geoip = False

        return {
            "name": name,
            "group": _clean_text(payload.get("group", old.get("group", "")), "group", 50),
            "tags": _validate_tags(payload.get("tags", old.get("tags", []))),
            "fingerprint_seed": seed,
            "proxy": proxy,
            "lock_proxy_ip": lock_proxy_ip,
            "geoip": geoip,
            "headless": boolean("headless", False),
            "humanize": boolean("humanize", False),
            "timezone": timezone_value,
            "location": location,
            "locale": locale_value,
            "startup_url": _validate_startup_url(
                payload.get("startup_url", old.get("startup_url", "about:blank"))
            ),
            "storage_quota_mb": storage_quota_mb,
            "fingerprint_platform": fingerprint_platform,
            "fingerprint_brand": fingerprint_brand,
            "fingerprint_brand_version": fingerprint_brand_version,
            "fingerprint_platform_version": fingerprint_platform_version,
            "hardware_concurrency": hardware_concurrency,
            "device_memory_gb": device_memory_gb,
            "screen_width": screen_width,
            "screen_height": screen_height,
            "gpu_vendor": gpu_vendor,
            "gpu_renderer": gpu_renderer,
            "taskbar_height": taskbar_height,
            "fingerprint_noise": boolean("fingerprint_noise", True),
            "allow_third_party_cookies": boolean("allow_third_party_cookies", False),
            "notes": _clean_text(payload.get("notes", old.get("notes", "")), "notes", 500),
        }

    def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            fields = self._validated_fields(payload)
            profile_id = _make_profile_id()
            while self._profile_dir(profile_id).exists():
                profile_id = _make_profile_id()
            now = _utc_now()
            profile = {
                "version": PROFILE_VERSION,
                "id": profile_id,
                **fields,
                "proxy_exit_ip": "",
                "proxy_checked_at": None,
                "locked_proxy_ip": "",
                "created_at": now,
                "updated_at": now,
                "last_launched_at": None,
            }
            self._write(profile)
            return dict(profile)

    def get(self, profile_id: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._read(profile_id))

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            profiles: list[dict[str, Any]] = []
            for path in self.profiles_dir.glob("env_*/profile.json"):
                profile_id = path.parent.name
                if not _PROFILE_ID_RE.fullmatch(profile_id):
                    continue
                try:
                    profiles.append(self._read(profile_id))
                except ProfileError:
                    continue
            return sorted(profiles, key=lambda item: item.get("updated_at", ""), reverse=True)

    def update(self, profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            profile = self._read(profile_id)
            old_proxy = profile.get("proxy", "")
            fields = self._validated_fields(payload, existing=profile)
            profile.update(fields)
            if profile["proxy"] != old_proxy:
                profile["proxy_exit_ip"] = ""
                profile["proxy_checked_at"] = None
                profile["locked_proxy_ip"] = ""
            if not profile["lock_proxy_ip"]:
                profile["locked_proxy_ip"] = ""
            profile["updated_at"] = _utc_now()
            self._write(profile)
            return dict(profile)

    def clone(self, profile_id: str) -> dict[str, Any]:
        with self._lock:
            source = self._read(profile_id)
            payload = {
                key: source.get(key, _ADVANCED_FINGERPRINT_DEFAULTS.get(key))
                for key in (
                    "proxy",
                    "geoip",
                    "headless",
                    "humanize",
                    "timezone",
                    "locale",
                    "startup_url",
                    "storage_quota_mb",
                    "fingerprint_platform",
                    "fingerprint_brand",
                    "fingerprint_brand_version",
                    "fingerprint_platform_version",
                    "hardware_concurrency",
                    "device_memory_gb",
                    "screen_width",
                    "screen_height",
                    "gpu_vendor",
                    "gpu_renderer",
                    "taskbar_height",
                    "fingerprint_noise",
                    "allow_third_party_cookies",
                    "notes",
                )
            }
            payload["lock_proxy_ip"] = source.get("lock_proxy_ip", False)
            payload["location"] = source.get("location", "")
            payload["group"] = source.get("group", "")
            payload["tags"] = source.get("tags", [])
            payload["name"] = f"{source['name']} - copy"
            payload["fingerprint_seed"] = _random_seed()
            return self.create(payload)

    def mark_launched(self, profile_id: str) -> None:
        with self._lock:
            profile = self._read(profile_id)
            profile["last_launched_at"] = _utc_now()
            profile["updated_at"] = profile["last_launched_at"]
            self._write(profile)

    def mark_proxy_checked(self, profile_id: str, exit_ip: str) -> dict[str, Any]:
        with self._lock:
            profile = self._read(profile_id)
            profile["proxy_exit_ip"] = exit_ip
            profile["proxy_checked_at"] = _utc_now()
            profile["updated_at"] = profile["proxy_checked_at"]
            self._write(profile)
            return dict(profile)

    def verify_locked_proxy_ip(self, profile_id: str, exit_ip: str) -> dict[str, Any]:
        """Record a launch-time proxy check and establish the first lock atomically."""
        with self._lock:
            profile = self._read(profile_id)
            checked_at = _utc_now()
            profile["proxy_exit_ip"] = exit_ip
            profile["proxy_checked_at"] = checked_at
            if profile.get("lock_proxy_ip", False) and not profile.get("locked_proxy_ip", ""):
                profile["locked_proxy_ip"] = exit_ip
            profile["updated_at"] = checked_at
            self._write(profile)
            return dict(profile)

    def accept_proxy_ip(self, profile_id: str) -> dict[str, Any]:
        """Replace the lock with the most recently observed proxy exit IP."""
        with self._lock:
            profile = self._read(profile_id)
            if not profile.get("lock_proxy_ip", False):
                raise ProfileError("proxy IP locking is not enabled")
            if not profile.get("proxy", ""):
                raise ProfileError("proxy is required")
            exit_ip = profile.get("proxy_exit_ip", "")
            if not exit_ip:
                raise ProfileError("check the proxy before accepting its exit IP")
            profile["locked_proxy_ip"] = exit_ip
            profile["updated_at"] = _utc_now()
            self._write(profile)
            return dict(profile)

    def delete(self, profile_id: str) -> Path:
        """Move an environment to the manager trash directory for recovery."""
        with self._lock:
            source = self._profile_dir(profile_id)
            if not (source / "profile.json").is_file():
                raise ProfileNotFound("environment not found")
            self.trash_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            destination = self.trash_dir / f"{profile_id}-{stamp}"
            suffix = 1
            while destination.exists():
                destination = self.trash_dir / f"{profile_id}-{stamp}-{suffix}"
                suffix += 1
            shutil.move(str(source), str(destination))
            return destination

    @staticmethod
    def public(profile: dict[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in profile.items() if key != "proxy"}
        proxy = profile.get("proxy", "")
        result["proxy_configured"] = bool(proxy)
        result["proxy_masked"] = _mask_proxy(proxy)
        result["geoip"] = bool(proxy and result.get("geoip", True))
        result.setdefault("proxy_exit_ip", "")
        result.setdefault("proxy_checked_at", None)
        result.setdefault("group", "")
        result.setdefault("tags", [])
        result.setdefault("location", "")
        result.setdefault("lock_proxy_ip", False)
        result.setdefault("locked_proxy_ip", "")
        for field_name, default in _ADVANCED_FINGERPRINT_DEFAULTS.items():
            result.setdefault(field_name, default)
        result["proxy_ip_conflict"] = bool(
            result["lock_proxy_ip"]
            and result["locked_proxy_ip"]
            and result["proxy_exit_ip"]
            and result["locked_proxy_ip"] != result["proxy_exit_ip"]
        )
        return result


@dataclass
class _SessionState:
    status: str = "stopped"
    error: str = ""
    started_at: str | None = None
    fingerprint_details: dict[str, Any] = field(default_factory=dict)
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


class BrowserSessionManager:
    """Owns browser contexts while keeping Playwright work on one thread each."""

    def __init__(
        self,
        store: ProfileStore,
        launcher: Callable[..., Any] | None = None,
        proxy_resolver: Callable[[str | None], str | None] | None = None,
    ) -> None:
        self.store = store
        self._launcher = launcher
        self._proxy_resolver = proxy_resolver
        self._states: dict[str, _SessionState] = {}
        self._lock = threading.RLock()

    def _get_launcher(self) -> Callable[..., Any]:
        if self._launcher is None:
            from .browser import launch_persistent_context

            return launch_persistent_context
        return self._launcher

    def status(self, profile_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._states.get(profile_id)
            if state is None:
                return {
                    "status": "stopped",
                    "error": "",
                    "started_at": None,
                    "fingerprint_details": {},
                }
            return {
                "status": state.status,
                "error": state.error,
                "started_at": state.started_at,
                "fingerprint_details": dict(state.fingerprint_details),
            }

    def start(self, profile_id: str) -> dict[str, Any]:
        profile = self.store.get(profile_id)
        with self._lock:
            current = self._states.get(profile_id)
            if current and current.status in {"starting", "running", "stopping"}:
                raise ProfileConflict("environment is already active")
            state = _SessionState(status="starting")
            thread = threading.Thread(
                target=self._run,
                args=(profile, state),
                name=f"cloak-profile-{profile_id}",
                daemon=True,
            )
            state.thread = thread
            self._states[profile_id] = state
            self.store.mark_launched(profile_id)
            thread.start()
            return self.status(profile_id)

    def _set_state(self, profile_id: str, state: _SessionState, status: str, error: str = "") -> None:
        with self._lock:
            if self._states.get(profile_id) is state:
                state.status = status
                state.error = error
                if status == "running":
                    state.started_at = _utc_now()

    def _capture_fingerprint_details(self, context: Any) -> dict[str, Any]:
        return _capture_fingerprint_details(context)

    def _set_fingerprint_details(
        self,
        profile_id: str,
        state: _SessionState,
        details: dict[str, Any],
    ) -> None:
        with self._lock:
            if self._states.get(profile_id) is state:
                state.fingerprint_details = details

    def _run(self, profile: dict[str, Any], state: _SessionState) -> None:
        profile_id = profile["id"]
        context = None
        try:
            if profile.get("lock_proxy_ip", False):
                proxy = profile.get("proxy", "")
                if not proxy:
                    raise ProxyCheckError("proxy IP locking requires a configured proxy")
                proxy_url = proxy if "://" in proxy else f"http://{proxy}"
                resolver = self._proxy_resolver
                if resolver is None:
                    from .geoip import resolve_proxy_exit_ip

                    resolver = resolve_proxy_exit_ip
                try:
                    exit_ip = resolver(proxy_url)
                except Exception as exc:
                    message = _redact_error(str(exc), proxy)
                    raise ProxyCheckError(f"proxy check failed before launch: {message}") from exc
                if not exit_ip:
                    raise ProxyCheckError("could not resolve the proxy exit IP before launch")
                exit_ip = str(exit_ip).strip()
                if not exit_ip:
                    raise ProxyCheckError("could not resolve the proxy exit IP before launch")
                checked = self.store.verify_locked_proxy_ip(profile_id, exit_ip)
                locked_ip = checked.get("locked_proxy_ip", "")
                if checked.get("lock_proxy_ip", False) and locked_ip != exit_ip:
                    raise ProxyCheckError(
                        f"proxy exit IP mismatch: locked {locked_ip}, current {exit_ip}; "
                        "accept the current IP before launching"
                    )

            args = _fingerprint_launch_args(profile)
            self.store.apply_browser_locale(profile_id, profile["locale"])
            launch_options: dict[str, Any] = {
                "headless": profile["headless"],
                "proxy": profile["proxy"] or None,
                "args": args,
                "timezone": profile["timezone"] or None,
                "locale": profile["locale"] or None,
                "geoip": bool(profile.get("proxy", "") and profile.get("geoip", True)),
                "humanize": profile["humanize"],
            }
            geolocation = _LOCATION_PRESETS.get(profile.get("location", ""))
            if geolocation:
                launch_options["geolocation"] = dict(geolocation)
                launch_options["permissions"] = ["geolocation"]
            context = self._get_launcher()(
                self.store.browser_data_dir(profile_id),
                **launch_options,
            )
            if state.stop_event.is_set():
                self._set_state(profile_id, state, "stopping")
            else:
                self._set_fingerprint_details(
                    profile_id,
                    state,
                    self._capture_fingerprint_details(context),
                )
                self._set_state(profile_id, state, "running")
                startup_url = profile["startup_url"]
                if startup_url != "about:blank":
                    try:
                        pages = context.pages
                        page = pages[0] if pages else context.new_page()
                        page.goto(startup_url, wait_until="domcontentloaded", timeout=30_000)
                    except Exception:
                        # A startup navigation failure should not close an otherwise
                        # healthy interactive browser environment.
                        pass

            while not state.stop_event.wait(0.4):
                try:
                    # This also pumps Playwright events, allowing a manually closed
                    # browser window to be observed by the worker.
                    _ = context.pages
                except Exception:
                    break
        except Exception as exc:
            error = _redact_error(str(exc), profile.get("proxy", ""))
            self._set_state(profile_id, state, "error", error[:1000])
            return
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass
        self._set_state(profile_id, state, "stopped")

    def stop(self, profile_id: str) -> dict[str, Any]:
        self.store.get(profile_id)
        with self._lock:
            state = self._states.get(profile_id)
            if state is None or state.status in {"stopped", "error"}:
                return self.status(profile_id)
            state.status = "stopping"
            state.stop_event.set()
            return self.status(profile_id)

    def is_active(self, profile_id: str) -> bool:
        return self.status(profile_id)["status"] in {"starting", "running", "stopping"}

    def stop_all(self, timeout: float = 10.0) -> None:
        with self._lock:
            states = list(self._states.values())
            for state in states:
                if state.status in {"starting", "running", "stopping"}:
                    state.status = "stopping"
                    state.stop_event.set()
        deadline = time.monotonic() + timeout
        for state in states:
            if state.thread and state.thread.is_alive():
                state.thread.join(max(0.0, deadline - time.monotonic()))


class _ManagerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], app: "ManagerApplication") -> None:
        self.app = app
        super().__init__(address, _ManagerRequestHandler)


class ManagerApplication:
    """HTTP API and static asset owner for the local management interface."""

    def __init__(
        self,
        store: ProfileStore | None = None,
        proxy_resolver: Callable[[str | None], str | None] | None = None,
        preview_launcher: Callable[..., Any] | None = None,
        proxy_geo_resolver: Callable[[str], tuple[str | None, str | None]] | None = None,
    ) -> None:
        self.store = store or ProfileStore()
        self.sessions = BrowserSessionManager(self.store, proxy_resolver=proxy_resolver)
        self.csrf_token = secrets.token_urlsafe(32)
        self.assets_dir = Path(__file__).with_name("manager_ui")
        self._proxy_resolver = proxy_resolver
        self._proxy_geo_resolver = proxy_geo_resolver
        self._preview_launcher = preview_launcher
        self._preview_lock = threading.Lock()

    def profiles(self) -> list[dict[str, Any]]:
        result = []
        for profile in self.store.list():
            public = self.store.public(profile)
            public.update(self.sessions.status(profile["id"]))
            result.append(public)
        return result

    def preview_fingerprint(self, payload: dict[str, Any]) -> dict[str, Any]:
        preview_payload = {
            "name": "Fingerprint preview",
            "fingerprint_seed": payload.get("fingerprint_seed"),
            "proxy": "",
            "lock_proxy_ip": False,
            "geoip": False,
            "headless": True,
            "humanize": False,
            "timezone": payload.get("timezone", ""),
            "location": payload.get("location", ""),
            "locale": payload.get("locale", ""),
            "startup_url": "about:blank",
            "storage_quota_mb": payload.get("storage_quota_mb", 5000),
            "notes": "",
        }
        for field_name in _ADVANCED_FINGERPRINT_DEFAULTS:
            if field_name in payload:
                preview_payload[field_name] = payload[field_name]
        fields = self.store._validated_fields(preview_payload)
        if not self._preview_lock.acquire(blocking=False):
            raise ProfileConflict("another fingerprint preview is still running")
        try:
            launcher = self._preview_launcher
            if launcher is None:
                from .browser import launch_persistent_context

                launcher = launch_persistent_context
            try:
                with tempfile.TemporaryDirectory(prefix="cloakbrowser-fingerprint-preview-") as temp_dir:
                    browser_data_dir = Path(temp_dir)
                    _apply_browser_locale_preferences(browser_data_dir, fields["locale"])
                    launch_options: dict[str, Any] = {
                        "headless": True,
                        "proxy": None,
                        "args": _fingerprint_launch_args(fields),
                        "timezone": fields["timezone"] or None,
                        "locale": fields["locale"] or None,
                        "geoip": False,
                        "humanize": False,
                    }
                    geolocation = _LOCATION_PRESETS.get(fields["location"])
                    if geolocation:
                        launch_options["geolocation"] = dict(geolocation)
                        launch_options["permissions"] = ["geolocation"]
                    context = launcher(browser_data_dir, **launch_options)
                    try:
                        details = _capture_fingerprint_details(context)
                    finally:
                        context.close()
                if not details:
                    raise FingerprintPreviewError("browser returned no fingerprint details")
                return {"fingerprint_seed": fields["fingerprint_seed"], "details": details}
            except (ProfileError, FingerprintPreviewError):
                raise
            except Exception as exc:
                raise FingerprintPreviewError(f"fingerprint preview failed: {exc}") from exc
        finally:
            self._preview_lock.release()

    def export_profiles(self, payload: dict[str, Any]) -> dict[str, Any]:
        profile_ids = payload.get("profile_ids")
        if not isinstance(profile_ids, list) or not profile_ids or len(profile_ids) > 100:
            raise ProfileError("profile_ids must contain between 1 and 100 environments")
        if any(not isinstance(profile_id, str) for profile_id in profile_ids):
            raise ProfileError("profile_ids must contain strings")
        include_proxy_credentials = _as_bool(
            payload.get("include_proxy_credentials", False),
            "include_proxy_credentials",
        )

        profiles = []
        for profile_id in dict.fromkeys(profile_ids):
            source = self.store.get(profile_id)
            exported = {
                field: source.get(field, _ADVANCED_FINGERPRINT_DEFAULTS.get(field))
                for field in _EXPORT_FIELDS
            }
            exported["group"] = source.get("group", "")
            exported["tags"] = source.get("tags", [])
            exported["lock_proxy_ip"] = source.get("lock_proxy_ip", False)
            if not include_proxy_credentials:
                exported["proxy"] = ""
                exported["lock_proxy_ip"] = False
            if not exported["proxy"]:
                exported["geoip"] = False
            profiles.append(exported)
        return {
            "format": PROFILE_EXPORT_FORMAT,
            "version": PROFILE_EXPORT_VERSION,
            "exported_at": _utc_now(),
            "includes_proxy_credentials": include_proxy_credentials,
            "profiles": profiles,
        }

    def import_profiles(self, payload: dict[str, Any]) -> dict[str, Any]:
        export_format = payload.get("format")
        if export_format not in (None, PROFILE_EXPORT_FORMAT):
            raise ProfileError("unsupported profile export format")
        version = payload.get("version")
        if version not in (None, PROFILE_EXPORT_VERSION):
            raise ProfileError("unsupported profile export version")
        imported_profiles = payload.get("profiles")
        if not isinstance(imported_profiles, list) or not imported_profiles or len(imported_profiles) > 100:
            raise ProfileError("profiles must contain between 1 and 100 environments")

        created = []
        errors: dict[str, str] = {}
        for index, item in enumerate(imported_profiles, start=1):
            try:
                if not isinstance(item, dict):
                    raise ProfileError("profile must be a JSON object")
                fields = {field: item[field] for field in _EXPORT_FIELDS if field in item}
                if not fields.get("proxy"):
                    fields["lock_proxy_ip"] = False
                profile = self.store.create(fields)
                created.append(self.store.public(profile))
            except ProfileError as exc:
                errors[str(index)] = str(exc)
        return {"created": created, "errors": errors}

    def check_proxy(self, payload: dict[str, Any]) -> dict[str, Any]:
        profile_id = payload.get("profile_id")
        profile: dict[str, Any] | None = None
        if profile_id is not None:
            if not isinstance(profile_id, str):
                raise ProfileError("profile_id must be a string")
            profile = self.store.get(profile_id)

        provided_proxy = payload.get("proxy")
        proxy_scheme = (
            _validate_proxy_scheme(payload["proxy_scheme"])
            if "proxy_scheme" in payload
            else None
        )
        if provided_proxy not in (None, ""):
            proxy = _validate_proxy(provided_proxy)
        else:
            proxy = profile.get("proxy", "") if profile else ""
            if proxy and proxy_scheme:
                proxy = _replace_proxy_scheme(proxy, proxy_scheme)
        if not proxy:
            raise ProfileError("proxy is required")

        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        resolver = self._proxy_resolver
        if resolver is None:
            from .geoip import resolve_proxy_exit_ip

            resolver = resolve_proxy_exit_ip
        try:
            exit_ip = resolver(proxy_url)
        except Exception as exc:
            message = _redact_error(str(exc), proxy)
            raise ProxyCheckError(f"proxy check failed: {message}") from exc
        if not exit_ip:
            raise ProxyCheckError("could not resolve a public exit IP through this proxy")
        exit_ip = str(exit_ip).strip()

        timezone_name = None
        locale = None
        geo_resolver = self._proxy_geo_resolver
        if geo_resolver is None and self._proxy_resolver is None:
            from .geoip import resolve_ip_geo

            geo_resolver = resolve_ip_geo
        if geo_resolver is not None:
            try:
                timezone_name, locale = geo_resolver(exit_ip)
            except (ImportError, OSError, ValueError):
                pass

        previous_ip = profile.get("proxy_exit_ip", "") if profile else ""
        checked_at = _utc_now()
        uses_saved_proxy = bool(profile and proxy == profile.get("proxy", ""))
        if uses_saved_proxy:
            profile = self.store.mark_proxy_checked(profile["id"], exit_ip)
            checked_at = profile["proxy_checked_at"]
        locked_ip = profile.get("locked_proxy_ip", "") if uses_saved_proxy and profile else ""
        return {
            "exit_ip": exit_ip,
            "timezone": timezone_name,
            "locale": locale,
            "webrtc_ip": exit_ip,
            "geoip_ready": bool(timezone_name and locale),
            "checked_at": checked_at,
            "changed": bool(previous_ip and previous_ip != exit_ip),
            "previous_ip": previous_ip,
            "locked_ip": locked_ip,
            "lock_conflict": bool(
                uses_saved_proxy
                and profile
                and profile.get("lock_proxy_ip", False)
                and locked_ip
                and locked_ip != exit_ip
            ),
        }

    def batch_sessions(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = payload.get("action")
        profile_ids = payload.get("profile_ids")
        if action not in {"launch", "stop"}:
            raise ProfileError("action must be launch or stop")
        if not isinstance(profile_ids, list) or not profile_ids or len(profile_ids) > 100:
            raise ProfileError("profile_ids must contain between 1 and 100 environments")
        if any(not isinstance(profile_id, str) for profile_id in profile_ids):
            raise ProfileError("profile_ids must contain strings")

        operation = self.sessions.start if action == "launch" else self.sessions.stop
        results: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for profile_id in dict.fromkeys(profile_ids):
            try:
                results[profile_id] = operation(profile_id)
            except (ProfileError, ProfileConflict) as exc:
                errors[profile_id] = str(exc)
        return {"action": action, "results": results, "errors": errors}


class _ManagerRequestHandler(BaseHTTPRequestHandler):
    server: _ManagerHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid logging URLs or bodies that may contain environment identifiers.
        return

    @property
    def app(self) -> ManagerApplication:
        return self.server.app

    def _host_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            hostname = urlparse(f"http://{host}").hostname
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
        except ValueError:
            return False
        return parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS and parsed.netloc == host.netloc

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ProfileError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ProfileError("invalid Content-Length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ProfileError("request body has an invalid size")
        try:
            data = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ProfileError("request body is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ProfileError("request body must be a JSON object")
        return data

    def _authorize_mutation(self) -> bool:
        if not self._host_allowed() or not self._origin_allowed():
            self.close_connection = True
            self._error(HTTPStatus.FORBIDDEN, "request origin is not allowed")
            return False
        if self.headers.get("X-Cloak-CSRF") != self.app.csrf_token:
            # The body is intentionally not parsed for an unauthorized request.
            # Close this keep-alive connection so unread bytes cannot become the
            # request line of the next request on the same socket.
            self.close_connection = True
            self._error(HTTPStatus.FORBIDDEN, "invalid session token")
            return False
        return True

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if not self._host_allowed():
            self._error(HTTPStatus.FORBIDDEN, "request host is not allowed")
            return
        if path == "/api/session":
            self._json(HTTPStatus.OK, {"csrf_token": self.app.csrf_token})
            return
        if path == "/api/profiles":
            profiles = self.app.profiles()
            self._json(
                HTTPStatus.OK,
                {
                    "profiles": profiles,
                    "summary": {
                        "total": len(profiles),
                        "running": sum(item["status"] == "running" for item in profiles),
                        "with_proxy": sum(item["proxy_configured"] for item in profiles),
                    },
                },
            )
            return
        route = self._profile_route()
        if route is not None and route[1] == "proxy":
            try:
                profile = self.app.store.get(route[0])
                self._json(HTTPStatus.OK, {"proxy": profile.get("proxy", "")})
            except ProfileNotFound as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
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
        file_path = self.app.assets_dir / asset[0]
        try:
            self._send(HTTPStatus.OK, file_path.read_bytes(), asset[1])
        except FileNotFoundError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "manager asset is missing")

    def _profile_route(self) -> tuple[str, str] | None:
        parts = [part for part in self.path.split("?", 1)[0].split("/") if part]
        if len(parts) >= 3 and parts[:2] == ["api", "profiles"]:
            action = parts[3] if len(parts) == 4 else ""
            if len(parts) in {3, 4}:
                return parts[2], action
        return None

    def do_POST(self) -> None:
        if not self._authorize_mutation():
            return
        try:
            path = self.path.split("?", 1)[0]
            if path == "/api/profiles":
                profile = self.app.store.create(self._read_json())
                self._json(HTTPStatus.CREATED, {"profile": self.app.store.public(profile)})
                return
            if path == "/api/proxy/check":
                result = self.app.check_proxy(self._read_json())
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/fingerprint/preview":
                result = self.app.preview_fingerprint(self._read_json())
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/profiles/batch":
                result = self.app.batch_sessions(self._read_json())
                self._json(HTTPStatus.ACCEPTED, result)
                return
            if path == "/api/profiles/export":
                result = self.app.export_profiles(self._read_json())
                self._json(HTTPStatus.OK, result)
                return
            if path == "/api/profiles/import":
                result = self.app.import_profiles(self._read_json())
                self._json(HTTPStatus.CREATED, result)
                return
            route = self._profile_route()
            if route is None:
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            profile_id, action = route
            # Consume and validate an empty JSON object for every mutation. This
            # keeps all POSTs non-simple requests and therefore CSRF-resistant.
            self._read_json()
            if action == "launch":
                runtime = self.app.sessions.start(profile_id)
                self._json(HTTPStatus.ACCEPTED, {"runtime": runtime})
            elif action == "stop":
                runtime = self.app.sessions.stop(profile_id)
                self._json(HTTPStatus.ACCEPTED, {"runtime": runtime})
            elif action == "clone":
                profile = self.app.store.clone(profile_id)
                self._json(HTTPStatus.CREATED, {"profile": self.app.store.public(profile)})
            elif action == "accept-proxy-ip":
                if self.app.sessions.is_active(profile_id):
                    raise ProfileConflict("stop the environment before accepting a new proxy IP")
                profile = self.app.store.accept_proxy_ip(profile_id)
                self._json(HTTPStatus.OK, {"profile": self.app.store.public(profile)})
            else:
                self._error(HTTPStatus.NOT_FOUND, "not found")
        except (ProxyCheckError, FingerprintPreviewError) as exc:
            self._error(HTTPStatus.BAD_GATEWAY, str(exc))
        except ProfileNotFound as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
        except ProfileConflict as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
        except ProfileError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_PUT(self) -> None:
        if not self._authorize_mutation():
            return
        route = self._profile_route()
        if route is None or route[1]:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        profile_id, _ = route
        try:
            if self.app.sessions.is_active(profile_id):
                raise ProfileConflict("stop the environment before editing it")
            profile = self.app.store.update(profile_id, self._read_json())
            self._json(HTTPStatus.OK, {"profile": self.app.store.public(profile)})
        except ProfileNotFound as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
        except ProfileConflict as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
        except ProfileError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_DELETE(self) -> None:
        if not self._authorize_mutation():
            return
        route = self._profile_route()
        if route is None or route[1]:
            self._error(HTTPStatus.NOT_FOUND, "not found")
            return
        profile_id, _ = route
        try:
            self._read_json()
            if self.app.sessions.is_active(profile_id):
                raise ProfileConflict("stop the environment before deleting it")
            self.app.store.delete(profile_id)
            self._json(HTTPStatus.OK, {"deleted": True})
        except ProfileNotFound as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
        except ProfileConflict as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
        except ProfileError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))


def run_manager(
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    open_browser: bool = True,
    data_dir: str | os.PathLike[str] | None = None,
) -> None:
    """Run the local profile-management interface until interrupted."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError("the profile manager can only listen on a loopback address")
    app = ManagerApplication(ProfileStore(data_dir) if data_dir else None)
    server = _ManagerHTTPServer((host, port), app)
    actual_host, actual_port = server.server_address[:2]
    browser_host = "127.0.0.1" if actual_host in {"0.0.0.0", "::"} else actual_host
    if ":" in browser_host:
        browser_host = f"[{browser_host}]"
    url = f"http://{browser_host}:{actual_port}"
    print(f"CloakBrowser Manager: {url}")
    print(f"Profile data: {app.store.root}")
    if open_browser:
        timer = threading.Timer(0.25, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        app.sessions.stop_all()


def add_manager_parser(subparsers: Any) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("manager", help="Open the local browser environment manager")
    parser.add_argument("--host", default="127.0.0.1", help="Loopback host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765; use 0 for any free port)")
    parser.add_argument("--no-open", action="store_true", help="Do not open the system browser automatically")
    parser.add_argument("--data-dir", help="Manager data directory (default: ~/.cloakbrowser/manager)")
    return parser


def cmd_manager(args: argparse.Namespace) -> None:
    run_manager(
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
        data_dir=args.data_dir,
    )
