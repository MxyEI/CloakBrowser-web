"""Tests for the local browser environment manager."""

from __future__ import annotations

import json
import threading
import time
from argparse import Namespace
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import pytest

from cloakbrowser.profile_manager import (
    BrowserSessionManager,
    ManagerApplication,
    ProfileConflict,
    ProfileError,
    ProfileStore,
    ProxyCheckError,
    _ManagerHTTPServer,
    cmd_manager,
    run_manager,
)


def _profile_payload(**overrides):
    payload = {
        "name": "Customer A",
        "group": "Client accounts",
        "tags": ["primary", "commerce"],
        "fingerprint_seed": 48327,
        "proxy": "http://proxy-user:proxy-password@proxy.example:8080",
        "lock_proxy_ip": False,
        "geoip": True,
        "headless": False,
        "humanize": False,
        "timezone": "",
        "location": "",
        "locale": "",
        "startup_url": "about:blank",
        "storage_quota_mb": 5000,
        "notes": "primary account",
    }
    payload.update(overrides)
    return payload


def test_profile_create_and_public_shape_masks_proxy(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())

    assert profile["fingerprint_seed"] == 48327
    assert store.browser_data_dir(profile["id"]).name == "browser-data"

    public = store.public(profile)
    assert "proxy" not in public
    assert public["proxy_configured"] is True
    assert public["proxy_masked"] == "http://proxy-user:****@proxy.example:8080"
    assert public["proxy_exit_ip"] == ""
    assert public["proxy_checked_at"] is None
    assert public["lock_proxy_ip"] is False
    assert public["locked_proxy_ip"] == ""
    assert public["proxy_ip_conflict"] is False
    assert public["group"] == "Client accounts"
    assert public["tags"] == ["primary", "commerce"]
    assert "proxy-password" not in json.dumps(public)


def test_profile_config_file_is_private(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())
    config = tmp_path / "profiles" / profile["id"] / "profile.json"

    assert config.stat().st_mode & 0o777 == 0o600


def test_browser_locale_preferences_merge_and_clear(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(proxy=""))
    preferences_path = store.browser_data_dir(profile["id"]) / "Default" / "Preferences"
    preferences_path.parent.mkdir(parents=True)
    preferences_path.write_text(
        json.dumps({"browser": {"show_home_button": True}, "intl": {"charset_default": "UTF-8"}}),
        encoding="utf-8",
    )

    store.apply_browser_locale(profile["id"], "en-US")
    preferences = json.loads(preferences_path.read_text(encoding="utf-8"))
    assert preferences["browser"]["show_home_button"] is True
    assert preferences["intl"] == {
        "charset_default": "UTF-8",
        "accept_languages": "en-US,en",
    }

    store.apply_browser_locale(profile["id"], "")
    preferences = json.loads(preferences_path.read_text(encoding="utf-8"))
    assert preferences["browser"]["show_home_button"] is True
    assert preferences["intl"] == {"charset_default": "UTF-8"}


def test_update_keeps_proxy_when_field_is_blank_and_can_clear_it(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())

    updated = store.update(profile["id"], {"name": "Renamed", "proxy": ""})
    assert updated["proxy"] == profile["proxy"]

    cleared = store.update(profile["id"], {"clear_proxy": True})
    assert cleared["proxy"] == ""
    assert cleared["geoip"] is False


def test_geoip_is_disabled_without_proxy(tmp_path):
    store = ProfileStore(tmp_path)

    profile = store.create(_profile_payload(proxy="", geoip=True))

    assert profile["geoip"] is False
    assert store.public(profile)["geoip"] is False


def test_group_and_tags_are_normalized_and_updated(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(
        _profile_payload(group=" Operations ", tags=["Priority", "priority", " US "])
    )

    assert profile["group"] == "Operations"
    assert profile["tags"] == ["Priority", "US"]

    updated = store.update(profile["id"], {"group": "Archive", "tags": []})
    assert updated["group"] == "Archive"
    assert updated["tags"] == []


def test_public_shape_defaults_group_and_tags_for_older_profiles():
    public = ProfileStore.public({"id": "env_000000000000", "proxy": "", "geoip": True})

    assert public["group"] == ""
    assert public["tags"] == []
    assert public["location"] == ""
    assert public["geoip"] is False


def test_changing_proxy_clears_previous_exit_ip(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    store.verify_locked_proxy_ip(profile["id"], "1.2.3.4")

    updated = store.update(profile["id"], {"proxy": "http://new.example:9000"})

    assert updated["proxy_exit_ip"] == ""
    assert updated["proxy_checked_at"] is None
    assert updated["locked_proxy_ip"] == ""
    assert updated["lock_proxy_ip"] is True


def test_clearing_proxy_disables_ip_lock(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    store.verify_locked_proxy_ip(profile["id"], "1.2.3.4")

    updated = store.update(profile["id"], {"clear_proxy": True})

    assert updated["proxy"] == ""
    assert updated["lock_proxy_ip"] is False
    assert updated["locked_proxy_ip"] == ""


def test_clone_gets_new_seed_and_empty_browser_data(tmp_path):
    store = ProfileStore(tmp_path)
    source = store.create(
        _profile_payload(
            location="new-york",
            fingerprint_platform="windows",
            hardware_concurrency=12,
            device_memory_gb=8,
            screen_width=1920,
            screen_height=1080,
        )
    )
    data_dir = store.browser_data_dir(source["id"])
    data_dir.mkdir()
    (data_dir / "cookie-store").write_text("state")

    clone = store.clone(source["id"])

    assert clone["id"] != source["id"]
    assert clone["fingerprint_seed"] != source["fingerprint_seed"]
    assert clone["proxy"] == source["proxy"]
    assert clone["group"] == source["group"]
    assert clone["tags"] == source["tags"]
    assert clone["location"] == "new-york"
    assert clone["fingerprint_platform"] == "windows"
    assert clone["hardware_concurrency"] == 12
    assert clone["device_memory_gb"] == 8
    assert clone["screen_width"] == 1920
    assert clone["screen_height"] == 1080
    assert not store.browser_data_dir(clone["id"]).exists()


def test_delete_moves_environment_to_trash(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())

    destination = store.delete(profile["id"])

    assert destination.parent == tmp_path / "_trash"
    assert (destination / "profile.json").is_file()
    assert not (tmp_path / "profiles" / profile["id"]).exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"proxy": "ftp://proxy.example:21"},
        {"proxy": "http://proxy.example:bad"},
        {"startup_url": "file:///etc/passwd"},
        {"timezone": "Asia/Shanghai\n--bad"},
        {"location": "unsupported-city"},
        {"storage_quota_mb": 1},
        {"proxy": "", "lock_proxy_ip": True},
        {"group": "x" * 51},
        {"tags": "not-an-array"},
        {"tags": ["tag"] * 11},
        {"tags": ["x" * 25]},
        {"fingerprint_platform": "android"},
        {"fingerprint_brand": "Firefox"},
        {"fingerprint_brand_version": "150.beta"},
        {"hardware_concurrency": 65},
        {"device_memory_gb": 3},
        {"screen_width": 1920, "screen_height": 0},
        {"screen_width": 640, "screen_height": 600},
        {"gpu_vendor": "Apple Inc.", "gpu_renderer": ""},
        {"taskbar_height": 241},
        {"fingerprint_noise": "yes"},
    ],
)
def test_profile_validation_rejects_invalid_values(tmp_path, overrides):
    store = ProfileStore(tmp_path)
    with pytest.raises(ProfileError):
        store.create(_profile_payload(**overrides))


class _FakeContext:
    def __init__(self):
        self.closed = threading.Event()

    @property
    def pages(self):
        return []

    def close(self):
        self.closed.set()


class _FingerprintPage:
    def __init__(self, *, secure=False):
        self.secure = secure
        self.closed = False

    def evaluate(self, script):
        assert "navigator.userAgent" in script
        return {
            "user_agent": "CloakBrowser QA",
            "platform": "MacIntel",
            "timezone": "America/New_York",
            "hardware_concurrency": 8,
            "device_memory_gb": 4 if self.secure else None,
        }

    def route(self, url, handler):
        assert url.startswith("http://127.0.0.1/")

    def goto(self, url, **kwargs):
        assert url.startswith("http://127.0.0.1/")

    def close(self):
        self.closed = True


class _FingerprintContext(_FakeContext):
    def __init__(self):
        super().__init__()
        self.probe_page = None

    @property
    def pages(self):
        return [_FingerprintPage()]

    def new_page(self):
        self.probe_page = _FingerprintPage(secure=True)
        return self.probe_page


def _wait_for_status(manager, profile_id, expected, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = manager.status(profile_id)["status"]
        if status == expected:
            return
        time.sleep(0.01)
    raise AssertionError(f"status never became {expected}: {manager.status(profile_id)}")


def test_session_uses_saved_identity_and_stops_on_worker_thread(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(timezone="Asia/Shanghai", locale="zh-CN"))
    calls = []
    context = _FakeContext()

    def launcher(user_data_dir, **kwargs):
        calls.append((user_data_dir, kwargs, threading.current_thread().name))
        return context

    manager = BrowserSessionManager(store, launcher=launcher)
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    user_data_dir, kwargs, thread_name = calls[0]
    assert user_data_dir == store.browser_data_dir(profile["id"])
    assert "--fingerprint=48327" in kwargs["args"]
    assert "--fingerprint-storage-quota=5000" in kwargs["args"]
    assert kwargs["proxy"] == profile["proxy"]
    assert kwargs["timezone"] == "Asia/Shanghai"
    assert kwargs["locale"] == "zh-CN"
    assert thread_name.startswith("cloak-profile-")

    manager.stop(profile["id"])
    _wait_for_status(manager, profile["id"], "stopped")
    assert context.closed.is_set()


def test_session_disables_geoip_for_legacy_profile_without_proxy(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())
    profile["proxy"] = ""
    profile["geoip"] = True
    store._write(profile)
    calls = []

    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: calls.append(kwargs) or _FakeContext(),
    )
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    assert calls[0]["proxy"] is None
    assert calls[0]["geoip"] is False
    manager.stop_all()


def test_session_supports_socks5_and_us_timezone(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(
        _profile_payload(
            proxy="socks5://proxy-user:proxy-password@proxy.example:1080",
            timezone="America/Los_Angeles",
        )
    )
    calls = []
    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: calls.append(kwargs) or _FakeContext(),
    )

    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    assert calls[0]["proxy"] == "socks5://proxy-user:proxy-password@proxy.example:1080"
    assert calls[0]["timezone"] == "America/Los_Angeles"
    manager.stop_all()


def test_session_applies_advanced_fingerprint_overrides(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(
        _profile_payload(
            geoip=False,
            fingerprint_platform="windows",
            fingerprint_brand="Edge",
            fingerprint_brand_version="150.0.1.2",
            fingerprint_platform_version="15.0.0",
            hardware_concurrency=12,
            device_memory_gb=8,
            screen_width=1920,
            screen_height=1080,
            gpu_vendor="Google Inc. (NVIDIA)",
            gpu_renderer="ANGLE (NVIDIA GeForce RTX 3060)",
            taskbar_height=48,
            fingerprint_noise=False,
            allow_third_party_cookies=True,
        )
    )
    calls = []
    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: calls.append(kwargs) or _FakeContext(),
    )

    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    args = calls[0]["args"]
    assert "--fingerprint-platform=windows" in args
    assert "--fingerprint-brand=Edge" in args
    assert "--fingerprint-brand-version=150.0.1.2" in args
    assert "--fingerprint-platform-version=15.0.0" in args
    assert "--fingerprint-hardware-concurrency=12" in args
    assert "--fingerprint-device-memory=8" in args
    assert "--fingerprint-screen-width=1920" in args
    assert "--fingerprint-screen-height=1080" in args
    assert "--fingerprint-gpu-vendor=Google Inc. (NVIDIA)" in args
    assert "--fingerprint-gpu-renderer=ANGLE (NVIDIA GeForce RTX 3060)" in args
    assert "--fingerprint-taskbar-height=48" in args
    assert "--fingerprint-noise=false" in args
    assert "--fingerprint-allow-3p-cookies" in args
    manager.stop_all()


def test_session_supports_manual_timezone_and_location_without_proxy(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(
        _profile_payload(
            proxy="",
            geoip=True,
            timezone="America/New_York",
            location="new-york",
            locale="en-US",
        )
    )
    calls = []
    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: calls.append(kwargs) or _FakeContext(),
    )

    assert profile["geoip"] is False
    assert profile["location"] == "new-york"
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    assert calls[0]["proxy"] is None
    assert calls[0]["geoip"] is False
    assert calls[0]["timezone"] == "America/New_York"
    assert calls[0]["locale"] == "en-US"
    assert calls[0]["geolocation"] == {
        "latitude": 40.7128,
        "longitude": -74.0060,
        "accuracy": 50.0,
    }
    assert calls[0]["permissions"] == ["geolocation"]
    preferences_path = store.browser_data_dir(profile["id"]) / "Default" / "Preferences"
    preferences = json.loads(preferences_path.read_text(encoding="utf-8"))
    assert preferences["intl"]["accept_languages"] == "en-US,en"
    manager.stop_all()


def test_session_captures_runtime_fingerprint_details(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(geoip=False))
    context = _FingerprintContext()
    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: context,
    )

    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")
    details = manager.status(profile["id"])["fingerprint_details"]

    assert details["user_agent"] == "CloakBrowser QA"
    assert details["platform"] == "MacIntel"
    assert details["timezone"] == "America/New_York"
    assert details["device_memory_gb"] == 4
    assert details["captured_at"].endswith("Z")
    assert context.probe_page.closed is True
    manager.stop_all()


def test_running_environment_cannot_start_twice(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())
    manager = BrowserSessionManager(store, launcher=lambda *args, **kwargs: _FakeContext())
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")

    with pytest.raises(ProfileConflict):
        manager.start(profile["id"])
    manager.stop_all()


def test_first_locked_launch_saves_ip_and_same_ip_can_be_reused(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    calls = []

    def launcher(*args, **kwargs):
        calls.append((args, kwargs))
        return _FakeContext()

    manager = BrowserSessionManager(
        store,
        launcher=launcher,
        proxy_resolver=lambda _proxy: "1.2.3.4",
    )
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")
    manager.stop(profile["id"])
    _wait_for_status(manager, profile["id"], "stopped")

    saved = store.get(profile["id"])
    assert saved["locked_proxy_ip"] == "1.2.3.4"
    assert saved["proxy_exit_ip"] == "1.2.3.4"

    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")
    manager.stop_all()
    assert len(calls) == 2


def test_changed_locked_ip_blocks_browser_launch(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    resolved_ips = iter(["1.2.3.4", "5.6.7.8"])
    calls = []
    manager = BrowserSessionManager(
        store,
        launcher=lambda *args, **kwargs: calls.append((args, kwargs)) or _FakeContext(),
        proxy_resolver=lambda _proxy: next(resolved_ips),
    )

    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "running")
    manager.stop(profile["id"])
    _wait_for_status(manager, profile["id"], "stopped")
    manager.start(profile["id"])
    _wait_for_status(manager, profile["id"], "error")

    status = manager.status(profile["id"])
    saved = store.get(profile["id"])
    assert "locked 1.2.3.4, current 5.6.7.8" in status["error"]
    assert saved["locked_proxy_ip"] == "1.2.3.4"
    assert saved["proxy_exit_ip"] == "5.6.7.8"
    assert store.public(saved)["proxy_ip_conflict"] is True
    assert len(calls) == 1


def test_proxy_check_persists_exit_ip_and_detects_change(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload())
    resolved_ips = iter(["1.2.3.4", "5.6.7.8"])
    app = ManagerApplication(store, proxy_resolver=lambda _proxy: next(resolved_ips))

    first = app.check_proxy({"profile_id": profile["id"]})
    second = app.check_proxy({"profile_id": profile["id"]})

    assert first["exit_ip"] == "1.2.3.4"
    assert first["changed"] is False
    assert second == {
        "exit_ip": "5.6.7.8",
        "checked_at": store.get(profile["id"])["proxy_checked_at"],
        "changed": True,
        "previous_ip": "1.2.3.4",
        "locked_ip": "",
        "lock_conflict": False,
    }
    assert store.get(profile["id"])["proxy_exit_ip"] == "5.6.7.8"


def test_manual_proxy_check_does_not_replace_locked_ip(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    store.verify_locked_proxy_ip(profile["id"], "1.2.3.4")
    app = ManagerApplication(store, proxy_resolver=lambda _proxy: "5.6.7.8")

    result = app.check_proxy({"profile_id": profile["id"]})

    assert result["lock_conflict"] is True
    assert result["locked_ip"] == "1.2.3.4"
    assert store.get(profile["id"])["locked_proxy_ip"] == "1.2.3.4"
    assert store.get(profile["id"])["proxy_exit_ip"] == "5.6.7.8"


def test_accept_proxy_ip_uses_latest_observation(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    store.verify_locked_proxy_ip(profile["id"], "1.2.3.4")
    store.mark_proxy_checked(profile["id"], "5.6.7.8")

    accepted = store.accept_proxy_ip(profile["id"])

    assert accepted["locked_proxy_ip"] == "5.6.7.8"
    assert store.public(accepted)["proxy_ip_conflict"] is False


def test_profile_export_is_safe_by_default_and_full_export_can_be_imported(tmp_path):
    source_store = ProfileStore(tmp_path / "source")
    profile = source_store.create(
        _profile_payload(
            lock_proxy_ip=True,
            location="new-york",
            fingerprint_brand="Edge",
            hardware_concurrency=12,
            fingerprint_noise=False,
        )
    )
    app = ManagerApplication(source_store)

    safe = app.export_profiles({"profile_ids": [profile["id"]]})
    full = app.export_profiles(
        {"profile_ids": [profile["id"], profile["id"]], "include_proxy_credentials": True}
    )

    assert safe["includes_proxy_credentials"] is False
    assert safe["profiles"][0]["proxy"] == ""
    assert safe["profiles"][0]["lock_proxy_ip"] is False
    assert safe["profiles"][0]["geoip"] is False
    assert "proxy-password" not in json.dumps(safe)
    assert len(full["profiles"]) == 1
    assert full["profiles"][0]["proxy"] == profile["proxy"]
    assert full["profiles"][0]["fingerprint_seed"] == profile["fingerprint_seed"]
    assert "id" not in full["profiles"][0]
    assert "created_at" not in full["profiles"][0]

    target_store = ProfileStore(tmp_path / "target")
    imported = ManagerApplication(target_store).import_profiles(full)
    restored = target_store.list()[0]
    assert imported["errors"] == {}
    assert len(imported["created"]) == 1
    assert restored["fingerprint_seed"] == profile["fingerprint_seed"]
    assert restored["proxy"] == profile["proxy"]
    assert restored["group"] == profile["group"]
    assert restored["tags"] == profile["tags"]
    assert restored["location"] == profile["location"]
    assert restored["fingerprint_brand"] == "Edge"
    assert restored["hardware_concurrency"] == 12
    assert restored["fingerprint_noise"] is False
    assert restored["locked_proxy_ip"] == ""


def test_profile_import_reports_invalid_rows_without_losing_valid_rows(tmp_path):
    store = ProfileStore(tmp_path)
    app = ManagerApplication(store)
    valid = _profile_payload(name="Imported", proxy="", lock_proxy_ip=False)

    result = app.import_profiles(
        {
            "profiles": [valid, {**valid, "name": ""}, "not-an-object"],
        }
    )

    assert len(result["created"]) == 1
    assert result["errors"] == {
        "2": "name is required",
        "3": "profile must be a JSON object",
    }
    assert [profile["name"] for profile in store.list()] == ["Imported"]


def test_legacy_profile_advanced_defaults_survive_export_and_import(tmp_path):
    source_store = ProfileStore(tmp_path / "source")
    profile = source_store.create(_profile_payload(proxy="", geoip=False))
    legacy = source_store.get(profile["id"])
    for field_name in (
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
    ):
        legacy.pop(field_name)
    source_store._write(legacy)

    exported = ManagerApplication(source_store).export_profiles(
        {"profile_ids": [profile["id"]]}
    )
    target_store = ProfileStore(tmp_path / "target")
    imported = ManagerApplication(target_store).import_profiles(exported)
    restored = target_store.list()[0]

    assert imported["errors"] == {}
    assert restored["fingerprint_platform"] == ""
    assert restored["hardware_concurrency"] == 0
    assert restored["screen_width"] == 0
    assert restored["taskbar_height"] == -1
    assert restored["fingerprint_noise"] is True
    assert restored["allow_third_party_cookies"] is False


def test_proxy_check_can_test_unsaved_proxy_without_persisting(tmp_path):
    store = ProfileStore(tmp_path)
    seen = []
    app = ManagerApplication(
        store,
        proxy_resolver=lambda proxy: seen.append(proxy) or "9.8.7.6",
    )

    result = app.check_proxy({"proxy": "user:pass@proxy.example:8080"})

    assert result["exit_ip"] == "9.8.7.6"
    assert result["locked_ip"] == ""
    assert result["lock_conflict"] is False
    assert seen == ["http://user:pass@proxy.example:8080"]
    assert store.list() == []


def test_proxy_check_preserves_socks5_scheme(tmp_path):
    store = ProfileStore(tmp_path)
    seen = []
    app = ManagerApplication(store, proxy_resolver=lambda proxy: seen.append(proxy) or "4.3.2.1")

    result = app.check_proxy({"proxy": "socks5://user:pass@proxy.example:1080"})

    assert result["exit_ip"] == "4.3.2.1"
    assert seen == ["socks5://user:pass@proxy.example:1080"]


def test_proxy_check_failure_redacts_credentials(tmp_path):
    store = ProfileStore(tmp_path)

    def fail(proxy):
        raise RuntimeError(f"connection failed for {proxy}")

    app = ManagerApplication(store, proxy_resolver=fail)
    with pytest.raises(ProxyCheckError) as error:
        app.check_proxy({"proxy": "http://private-user:private-pass@proxy.example:8080"})
    assert "private-pass" not in str(error.value)
    assert "private-user" not in str(error.value)


def test_batch_start_and_stop(tmp_path):
    store = ProfileStore(tmp_path)
    first = store.create(_profile_payload(name="First"))
    second = store.create(_profile_payload(name="Second", fingerprint_seed=58328))
    contexts = []

    def launcher(*args, **kwargs):
        context = _FakeContext()
        contexts.append(context)
        return context

    app = ManagerApplication(store)
    app.sessions = BrowserSessionManager(store, launcher=launcher)
    profile_ids = [first["id"], second["id"]]

    started = app.batch_sessions({"action": "launch", "profile_ids": profile_ids})
    _wait_for_status(app.sessions, first["id"], "running")
    _wait_for_status(app.sessions, second["id"], "running")
    stopped = app.batch_sessions({"action": "stop", "profile_ids": profile_ids})
    _wait_for_status(app.sessions, first["id"], "stopped")
    _wait_for_status(app.sessions, second["id"], "stopped")

    assert started["errors"] == {}
    assert stopped["errors"] == {}
    assert len(contexts) == 2
    assert all(context.closed.is_set() for context in contexts)


def test_fingerprint_preview_uses_temporary_seeded_browser(tmp_path):
    store = ProfileStore(tmp_path)
    calls = []
    context = _FingerprintContext()

    def preview_launcher(user_data_dir, **kwargs):
        preferences = json.loads((user_data_dir / "Default" / "Preferences").read_text(encoding="utf-8"))
        calls.append((Path(user_data_dir), kwargs, preferences))
        return context

    app = ManagerApplication(store, preview_launcher=preview_launcher)
    result = app.preview_fingerprint(
        {
            "fingerprint_seed": 98765,
            "timezone": "America/New_York",
            "location": "new-york",
            "locale": "en-US",
            "storage_quota_mb": 7000,
            "fingerprint_platform": "windows",
            "fingerprint_brand": "Edge",
            "hardware_concurrency": 12,
            "device_memory_gb": 8,
            "screen_width": 1920,
            "screen_height": 1080,
            "fingerprint_noise": False,
            "allow_third_party_cookies": True,
        }
    )

    preview_dir, kwargs, preferences = calls[0]
    assert result["fingerprint_seed"] == 98765
    assert result["details"]["user_agent"] == "CloakBrowser QA"
    assert result["details"]["captured_at"].endswith("Z")
    assert "--fingerprint=98765" in kwargs["args"]
    assert "--fingerprint-storage-quota=7000" in kwargs["args"]
    assert "--fingerprint-platform=windows" in kwargs["args"]
    assert "--fingerprint-brand=Edge" in kwargs["args"]
    assert "--fingerprint-hardware-concurrency=12" in kwargs["args"]
    assert "--fingerprint-device-memory=8" in kwargs["args"]
    assert "--fingerprint-screen-width=1920" in kwargs["args"]
    assert "--fingerprint-screen-height=1080" in kwargs["args"]
    assert "--fingerprint-noise=false" in kwargs["args"]
    assert "--fingerprint-allow-3p-cookies" in kwargs["args"]
    assert kwargs["timezone"] == "America/New_York"
    assert kwargs["locale"] == "en-US"
    assert kwargs["geolocation"]["latitude"] == 40.7128
    assert preferences["intl"]["accept_languages"] == "en-US,en"
    assert context.closed.is_set()
    assert not preview_dir.exists()

    with pytest.raises(ProfileError):
        app.preview_fingerprint({"fingerprint_seed": 0})


def test_manager_http_api_masks_proxy_and_requires_csrf(tmp_path):
    store = ProfileStore(tmp_path)
    profile = store.create(_profile_payload(lock_proxy_ip=True))
    app = ManagerApplication(store, proxy_resolver=lambda _proxy: "1.1.1.1")
    server = _ManagerHTTPServer(("127.0.0.1", 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        connection = HTTPConnection(host, port, timeout=2)
        connection.request("GET", "/api/profiles", headers={"Host": f"127.0.0.1:{port}"})
        response = connection.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert "proxy-password" not in body
        assert "proxy-user:****@proxy.example:8080" in body

        connection.request(
            "POST",
            "/api/profiles",
            body=json.dumps(_profile_payload(name="No token")),
            headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        assert response.status == 403

        connection.request(
            "POST",
            "/api/proxy/check",
            body=json.dumps({"profile_id": profile["id"]}),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Cloak-CSRF": app.csrf_token,
            },
        )
        response = connection.getresponse()
        checked = json.loads(response.read())
        assert response.status == 200
        assert checked["exit_ip"] == "1.1.1.1"
        assert store.get(profile["id"])["proxy_exit_ip"] == "1.1.1.1"
        assert store.get(profile["id"])["locked_proxy_ip"] == ""

        connection.request(
            "POST",
            f"/api/profiles/{profile['id']}/accept-proxy-ip",
            body="{}",
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Cloak-CSRF": app.csrf_token,
            },
        )
        response = connection.getresponse()
        accepted = json.loads(response.read())
        assert response.status == 200
        assert accepted["profile"]["locked_proxy_ip"] == "1.1.1.1"

        connection.request(
            "POST",
            "/api/profiles/export",
            body=json.dumps({"profile_ids": [profile["id"]]}),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Cloak-CSRF": app.csrf_token,
            },
        )
        response = connection.getresponse()
        exported = json.loads(response.read())
        assert response.status == 200
        assert exported["profiles"][0]["proxy"] == ""
        assert "proxy-password" not in json.dumps(exported)

        connection.request(
            "POST",
            "/api/profiles/import",
            body=json.dumps(exported),
            headers={
                "Host": f"127.0.0.1:{port}",
                "Content-Type": "application/json",
                "X-Cloak-CSRF": app.csrf_token,
            },
        )
        response = connection.getresponse()
        imported = json.loads(response.read())
        assert response.status == 201
        assert len(imported["created"]) == 1
        assert imported["created"][0]["proxy_configured"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_cmd_manager_forwards_cli_options(tmp_path):
    args = Namespace(host="localhost", port=9000, no_open=True, data_dir=str(tmp_path))
    with patch("cloakbrowser.profile_manager.run_manager") as manager:
        cmd_manager(args)
    manager.assert_called_once_with(
        host="localhost",
        port=9000,
        open_browser=False,
        data_dir=str(tmp_path),
    )


def test_manager_rejects_non_loopback_bind():
    with pytest.raises(ValueError, match="loopback"):
        run_manager(host="0.0.0.0", open_browser=False)


def test_manager_ui_exposes_profile_management_controls():
    ui_dir = Path(__file__).parents[1] / "cloakbrowser" / "manager_ui"
    html = (ui_dir / "index.html").read_text(encoding="utf-8")
    javascript = (ui_dir / "app.js").read_text(encoding="utf-8")

    assert 'id="lockProxyIpInput"' in html
    assert 'id="acceptProxyIpButton"' in html
    assert "profile.proxy_ip_conflict" in javascript
    assert "status-error-line" in javascript
    assert "/accept-proxy-ip" in javascript
    assert 'id="groupFilter"' in html
    assert 'id="selectVisibleInput"' in html
    assert 'id="groupInput"' in html
    assert "state.selected" in javascript
    assert "dataset.profileSelect" in javascript
    assert 'id="importFileInput"' in html
    assert 'id="exportMenu"' in html
    assert 'data-export-proxy="false"' in html
    assert "/api/profiles/export" in javascript
    assert "/api/profiles/import" in javascript
    assert 'id="geoipInput" name="geoip" type="checkbox">' in html
    assert "syncGeoipAvailability" in javascript
    assert 'option value="socks5"' in html
    assert 'option value="America/New_York"' in html
    assert 'id="locationInput"' in html
    assert 'option value="new-york"' in html
    assert '<option value="en-US">English (United States)</option>' in html
    assert '<option value="en-GB">English (United Kingdom)</option>' in html
    assert "setLocaleValue" in javascript
    assert 'id="seedPreviewRows"' in html
    assert 'id="previewSeedButton"' in html
    assert "/api/fingerprint/preview" in javascript
    assert 'id="fingerprintModal"' in html
    assert 'id="advancedFingerprintPanel"' in html
    assert 'id="fingerprintPlatformInput"' in html
    assert 'id="fingerprintBrandInput"' in html
    assert 'id="hardwareConcurrencyInput"' in html
    assert 'id="deviceMemoryInput"' in html
    assert 'id="screenSizeInput"' in html
    assert 'id="gpuVendorInput"' in html
    assert 'id="fingerprintNoiseInput"' in html
    assert "advancedFingerprintPayload" in javascript
    assert "renderFingerprintDetails" in javascript
    assert "profilesSignature" in javascript
    assert "hasOpenProfileMenu" in javascript
    assert "if (profilesChanged) requestProfilesRender();" in javascript
    assert "flushPendingProfilesRender();" in javascript
