"""Security and collaboration tests for the cloud control plane."""

from __future__ import annotations

from argparse import Namespace
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import stat
from threading import Barrier
import uuid
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cloakbrowser.cloud.app import create_app
from cloakbrowser.cloud import agent_cli
from cloakbrowser.cloud.agent_runtime import AgentRuntime
from cloakbrowser.cloud.cli import add_cloud_parser
from cloakbrowser.cloud.models import EnvironmentSecret, RemoteTask, utc_now
from cloakbrowser.cloud.settings import CloudSettings
from cloakbrowser.cloud.snapshot_crypto import (
    SnapshotError,
    create_encrypted_snapshot,
    decode_snapshot_key,
    encode_snapshot_key,
    restore_encrypted_snapshot,
)


@pytest.fixture()
def cloud_app(tmp_path):
    settings = CloudSettings(
        database_url=f"sqlite:///{tmp_path / 'cloud.db'}",
        secret_key="test-secret-key-with-at-least-thirty-two-bytes",
        cookie_secure=False,
        assets_dir=Path(__file__).parents[1] / "cloakbrowser" / "cloud" / "ui",
    )
    app = create_app(settings)
    yield app
    app.state.engine.dispose()


@pytest.fixture()
def client(cloud_app):
    with TestClient(cloud_app) as test_client:
        yield test_client


def register(client, email="owner@example.com", name="Owner", team="Acme"):
    response = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "correct-horse-battery-staple",
            "display_name": name,
            "organization_name": team,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def csrf_headers(auth):
    return {"X-CSRF-Token": auth["csrf_token"]}


def current_session(client):
    response = client.get("/api/session")
    assert response.status_code == 200, response.text
    return response.json()


def test_registration_session_csrf_and_security_headers(client):
    auth = register(client)

    session = current_session(client)
    assert session["user"]["email"] == "owner@example.com"
    assert session["organization"]["role"] == "owner"
    assert "members.manage" in session["permissions"]

    blocked = client.post("/api/groups", json={"name": "Customers", "description": ""})
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "invalid CSRF token"

    created = client.post(
        "/api/groups",
        headers=csrf_headers(auth),
        json={"name": "Customers", "description": "Managed accounts"},
    )
    assert created.status_code == 201

    index = client.get("/")
    assert index.status_code == 200
    assert 'id="authShell"' in index.text
    assert index.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in index.headers["content-security-policy"]


def test_duplicate_registration_and_invalid_login_are_rejected(client):
    register(client)
    duplicate = client.post(
        "/api/auth/register",
        json={
            "email": "OWNER@example.com",
            "password": "another-secure-password",
            "display_name": "Duplicate",
            "organization_name": "Other",
        },
    )
    assert duplicate.status_code == 409

    invalid = client.post(
        "/api/auth/login",
        json={"email": "owner@example.com", "password": "wrong-password"},
    )
    assert invalid.status_code == 401
    assert invalid.json()["detail"] == "invalid email or password"


def test_environment_revision_validation_and_audit(client):
    auth = register(client)
    headers = csrf_headers(auth)
    group = client.post(
        "/api/groups",
        headers=headers,
        json={"name": "Priority", "description": ""},
    ).json()["group"]
    created = client.post(
        "/api/environments",
        headers=headers,
        json={
            "name": "Account A",
            "group_id": group["id"],
            "tags": ["Primary", "primary"],
            "storage_policy": "backup",
            "config": {
                "fingerprint_seed": 48327,
                "timezone": "America/New_York",
                "location": "new-york",
                "locale": "en-US",
                "storage_quota_mb": 4096,
                "fingerprint_platform": "windows",
                "fingerprint_brand": "Edge",
                "fingerprint_brand_version": "150.0.1.2",
                "fingerprint_platform_version": "10.0.0",
                "hardware_concurrency": 8,
                "device_memory_gb": 4,
                "screen_width": 1920,
                "screen_height": 1080,
                "gpu_vendor": "Google Inc. (NVIDIA)",
                "gpu_renderer": "ANGLE (NVIDIA GeForce RTX 3060)",
                "taskbar_height": 40,
                "fingerprint_noise": False,
                "allow_third_party_cookies": True,
            },
        },
    )
    assert created.status_code == 201, created.text
    environment = created.json()["environment"]
    assert environment["revision"] == 1
    assert environment["tags"] == ["Primary"]
    assert environment["config"] == {
        "fingerprint_seed": 48327,
        "headless": False,
        "humanize": False,
        "geoip": False,
        "timezone": "America/New_York",
        "location": "new-york",
        "locale": "en-US",
        "startup_url": "about:blank",
        "storage_quota_mb": 4096,
        "fingerprint_platform": "windows",
        "fingerprint_brand": "Edge",
        "fingerprint_brand_version": "150.0.1.2",
        "fingerprint_platform_version": "10.0.0",
        "hardware_concurrency": 8,
        "device_memory_gb": 4,
        "screen_width": 1920,
        "screen_height": 1080,
        "gpu_vendor": "Google Inc. (NVIDIA)",
        "gpu_renderer": "ANGLE (NVIDIA GeForce RTX 3060)",
        "taskbar_height": 40,
        "fingerprint_noise": False,
        "allow_third_party_cookies": True,
    }

    updated = client.patch(
        f"/api/environments/{environment['id']}",
        headers=headers,
        json={
            "expected_revision": 1,
            "name": "Account A - updated",
            "storage_policy": "shared",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["environment"]["revision"] == 2

    stale = client.patch(
        f"/api/environments/{environment['id']}",
        headers=headers,
        json={"expected_revision": 1, "name": "Stale overwrite"},
    )
    assert stale.status_code == 409
    assert "another team member" in stale.json()["detail"]

    invalid_gpu = client.post(
        "/api/environments",
        headers=headers,
        json={
            "name": "Broken",
            "config": {"gpu_vendor": "Apple Inc.", "gpu_renderer": ""},
        },
    )
    assert invalid_gpu.status_code == 422

    audit = client.get("/api/audit")
    assert audit.status_code == 200
    actions = {entry["action"] for entry in audit.json()["entries"]}
    assert {"environment.created", "environment.updated", "group.created"} <= actions


def test_team_roles_and_tenant_isolation(cloud_app):
    with TestClient(cloud_app) as owner_client, TestClient(cloud_app) as operator_client:
        owner_auth = register(owner_client, "owner@example.com", "Owner", "Owner Team")
        operator_auth = register(operator_client, "operator@example.com", "Operator", "Personal")
        operator_personal_org = operator_auth["organization"]["id"]

        added = owner_client.post(
            "/api/members",
            headers=csrf_headers(owner_auth),
            json={"email": "operator@example.com", "role": "operator"},
        )
        assert added.status_code == 201, added.text
        membership = added.json()["member"]

        operator_session = current_session(operator_client)
        shared_org = next(
            org for org in operator_session["organizations"] if org["name"] == "Owner Team"
        )
        switched = operator_client.post(
            "/api/session/organization",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"organization_id": shared_org["id"]},
        )
        assert switched.status_code == 200
        operator_session = current_session(operator_client)
        assert operator_session["organization"]["role"] == "operator"

        created = operator_client.post(
            "/api/environments",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"name": "Operator Environment", "config": {"fingerprint_seed": 12345}},
        )
        assert created.status_code == 201, created.text
        environment_id = created.json()["environment"]["id"]

        cannot_delete = operator_client.delete(
            f"/api/environments/{environment_id}",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
        )
        assert cannot_delete.status_code == 403
        cannot_manage_groups = operator_client.post(
            "/api/groups",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"name": "Forbidden", "description": ""},
        )
        assert cannot_manage_groups.status_code == 403
        assert operator_client.get("/api/agents").status_code == 200
        cannot_manage_agents = operator_client.post(
            "/api/agents",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"name": "Forbidden Runner"},
        )
        assert cannot_manage_agents.status_code == 403
        assert operator_client.get("/api/audit").status_code == 403

        switched_back = operator_client.post(
            "/api/session/organization",
            headers={"X-CSRF-Token": operator_session["csrf_token"]},
            json={"organization_id": operator_personal_org},
        )
        assert switched_back.status_code == 200
        isolated = operator_client.get("/api/environments").json()["environments"]
        assert isolated == []

        promoted = owner_client.patch(
            f"/api/members/{membership['id']}",
            headers=csrf_headers(owner_auth),
            json={"role": "viewer"},
        )
        assert promoted.status_code == 200


def test_last_owner_cannot_be_demoted_or_removed(client):
    auth = register(client)
    member = client.get("/api/members").json()["members"][0]

    demote = client.patch(
        f"/api/members/{member['id']}",
        headers=csrf_headers(auth),
        json={"role": "admin"},
    )
    assert demote.status_code == 409

    remove = client.delete(
        f"/api/members/{member['id']}",
        headers=csrf_headers(auth),
    )
    assert remove.status_code == 409


def test_group_delete_unassigns_environments(client):
    auth = register(client)
    headers = csrf_headers(auth)
    group = client.post(
        "/api/groups", headers=headers, json={"name": "Temporary", "description": ""}
    ).json()["group"]
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={"name": "Grouped", "group_id": group["id"], "config": {}},
    ).json()["environment"]

    deleted = client.delete(f"/api/groups/{group['id']}", headers=headers)
    assert deleted.status_code == 204
    environments = client.get("/api/environments").json()["environments"]
    restored = next(item for item in environments if item["id"] == environment["id"])
    assert restored["group_id"] is None
    assert restored["revision"] == environment["revision"] + 1

    stale = client.patch(
        f"/api/environments/{environment['id']}",
        headers=headers,
        json={"expected_revision": environment["revision"], "name": "Stale group view"},
    )
    assert stale.status_code == 409

    audit = client.get("/api/audit").json()["entries"]
    deleted = next(entry for entry in audit if entry["action"] == "group.deleted")
    assert deleted["details"]["environments_unassigned"] == 1


def test_cloud_settings_refuse_insecure_public_bind(tmp_path):
    settings = CloudSettings(
        database_url=f"sqlite:///{tmp_path / 'cloud.db'}",
        secret_key="temporary",
        cookie_secure=False,
        development_secret=True,
    )
    with pytest.raises(ValueError, match="CLOAKBROWSER_CLOUD_SECRET"):
        settings.validate_bind("0.0.0.0")

    weak = CloudSettings(
        database_url=settings.database_url,
        secret_key="too-short",
        cookie_secure=True,
        development_secret=False,
    )
    with pytest.raises(ValueError, match="at least 32"):
        weak.validate_bind("0.0.0.0")


def test_cloud_snapshot_master_key_is_private_and_strictly_decoded(tmp_path, monkeypatch):
    monkeypatch.delenv("CLOAKBROWSER_CLOUD_SNAPSHOT_KEY", raising=False)
    settings = CloudSettings.from_env(str(tmp_path / "cloud-settings"))
    assert len(settings.snapshot_master_key or b"") == 32
    if os.name != "nt":
        key_path = tmp_path / "cloud-settings" / "snapshot-master.key"
        assert key_path.stat().st_mode & 0o077 == 0

    invalid_root = tmp_path / "invalid-key"
    monkeypatch.setenv(
        "CLOAKBROWSER_CLOUD_SNAPSHOT_KEY",
        base64.urlsafe_b64encode(os.urandom(32)).decode("ascii") + "$",
    )
    with pytest.raises(ValueError, match="URL-safe base64"):
        CloudSettings.from_env(str(invalid_root))


def test_cloud_cli_parser_defaults():
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    add_cloud_parser(sub)
    args = parser.parse_args(["cloud", "--no-open"])
    assert isinstance(args, Namespace)
    assert args.host == "127.0.0.1"
    assert args.port == 8777
    assert args.no_open is True


def create_agent(client, auth, name="Runner One"):
    response = client.post(
        "/api/agents",
        headers=csrf_headers(auth),
        json={"name": name},
    )
    assert response.status_code == 201, response.text
    return response.json()


def agent_headers(token):
    return {"Authorization": f"Bearer {token}"}


def build_extension_zip(path, *, version="1.0.0", unsafe_name=None):
    manifest = {
        "manifest_version": 3,
        "name": "Cloud QA Extension",
        "version": version,
        "action": {"default_title": "QA"},
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("worker.js", "globalThis.cloudExtensionLoaded = true;\n")
        if unsafe_name:
            archive.writestr(unsafe_name, "unsafe")
    return path.read_bytes()


def bring_agent_online(client, created):
    response = client.post(
        "/api/agent/heartbeat",
        headers=agent_headers(created["agent_token"]),
        json={
            "hostname": "runner-01",
            "platform": "Test",
            "version": "0.5.2",
            "capabilities": {"leases": True, "browser_launch": True},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_agent_credentials_heartbeat_rotation_and_revocation(client):
    auth = register(client)
    created = create_agent(client, auth)
    agent = created["agent"]
    token = created["agent_token"]
    assert token.startswith("cb_agent_")
    assert agent["status"] == "offline"
    assert token not in client.get("/api/agents").text

    heartbeat = client.post(
        "/api/agent/heartbeat",
        headers=agent_headers(token),
        json={
            "hostname": "runner-01",
            "platform": "Linux x86_64",
            "version": "0.5.2",
            "capabilities": {"leases": True},
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    listed = client.get("/api/agents").json()["agents"][0]
    assert listed["status"] == "online"
    assert listed["hostname"] == "runner-01"

    rotated = client.post(
        f"/api/agents/{agent['id']}/rotate-token",
        headers=csrf_headers(auth),
    )
    assert rotated.status_code == 200
    replacement = rotated.json()["agent_token"]
    assert replacement != token
    assert client.post(
        "/api/agent/heartbeat", headers=agent_headers(token), json={}
    ).status_code == 401
    assert client.post(
        "/api/agent/heartbeat", headers=agent_headers(replacement), json={}
    ).status_code == 200

    revoked = client.delete(
        f"/api/agents/{agent['id']}", headers=csrf_headers(auth)
    )
    assert revoked.status_code == 204
    assert client.post(
        "/api/agent/heartbeat", headers=agent_headers(replacement), json={}
    ).status_code == 401
    assert client.get("/api/agents").json()["agents"][0]["status"] == "revoked"


def test_agent_lease_is_exclusive_and_fencing_token_increases(client):
    auth = register(client)
    environment = client.post(
        "/api/environments",
        headers=csrf_headers(auth),
        json={"name": "Lease Target", "config": {"fingerprint_seed": 44221}},
    ).json()["environment"]
    first = create_agent(client, auth, "Runner One")
    second = create_agent(client, auth, "Runner Two")

    acquired = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(first["agent_token"]),
        json={"environment_id": environment["id"]},
    )
    assert acquired.status_code == 201, acquired.text
    first_lease = acquired.json()
    assert first_lease["lease"]["fencing_token"] == 1
    assert first_lease["lease_token"].startswith("cb_lease_")

    conflict = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(second["agent_token"]),
        json={"environment_id": environment["id"]},
    )
    assert conflict.status_code == 409
    active = client.get("/api/leases").json()["leases"]
    assert len(active) == 1
    assert active[0]["agent_id"] == first["agent"]["id"]

    proof = {
        "lease_id": first_lease["lease"]["lease_id"],
        "lease_token": first_lease["lease_token"],
        "fencing_token": 1,
    }
    bad_proof = {**proof, "lease_token": f"{proof['lease_token']}x"}
    assert client.post(
        f"/api/agent/leases/{environment['id']}/heartbeat",
        headers=agent_headers(first["agent_token"]),
        json=bad_proof,
    ).status_code == 409
    assert client.post(
        f"/api/agent/leases/{environment['id']}/heartbeat",
        headers=agent_headers(first["agent_token"]),
        json=proof,
    ).status_code == 200
    assert client.post(
        f"/api/agent/leases/{environment['id']}/release",
        headers=agent_headers(first["agent_token"]),
        json=proof,
    ).status_code == 204

    reacquired = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(second["agent_token"]),
        json={"environment_id": environment["id"]},
    )
    assert reacquired.status_code == 201, reacquired.text
    assert reacquired.json()["lease"]["fencing_token"] == 2
    assert client.post(
        f"/api/agent/leases/{environment['id']}/heartbeat",
        headers=agent_headers(first["agent_token"]),
        json=proof,
    ).status_code == 409

    revoked = client.delete(
        f"/api/agents/{second['agent']['id']}", headers=csrf_headers(auth)
    )
    assert revoked.status_code == 204
    assert client.get("/api/leases").json()["leases"] == []
    third = create_agent(client, auth, "Runner Three")
    after_revoke = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(third["agent_token"]),
        json={"environment_id": environment["id"]},
    )
    assert after_revoke.status_code == 201
    assert after_revoke.json()["lease"]["fencing_token"] == 3


def test_agent_tenant_isolation(cloud_app):
    with TestClient(cloud_app) as first_client, TestClient(cloud_app) as other_client:
        first_auth = register(first_client, "first@example.com", "First", "First Team")
        environment = first_client.post(
            "/api/environments",
            headers=csrf_headers(first_auth),
            json={"name": "Private", "config": {}},
        ).json()["environment"]
        other_auth = register(other_client, "other@example.com", "Other", "Other Team")
        other_agent = create_agent(other_client, other_auth, "Other Runner")

        assert other_client.post(
            "/api/agent/leases/acquire",
            headers=agent_headers(other_agent["agent_token"]),
            json={"environment_id": environment["id"]},
        ).status_code == 404
        assert other_client.get(
            "/api/agent/environments",
            headers=agent_headers(other_agent["agent_token"]),
        ).json()["environments"] == []


def test_concurrent_agent_claims_have_one_winner(cloud_app):
    with ExitStack() as stack:
        owner_client = stack.enter_context(TestClient(cloud_app))
        first_agent_client = stack.enter_context(TestClient(cloud_app))
        second_agent_client = stack.enter_context(TestClient(cloud_app))
        auth = register(owner_client)
        environment = owner_client.post(
            "/api/environments",
            headers=csrf_headers(auth),
            json={"name": "Concurrent Target", "config": {}},
        ).json()["environment"]
        first = create_agent(owner_client, auth, "Concurrent One")
        second = create_agent(owner_client, auth, "Concurrent Two")
        barrier = Barrier(2)

        def claim(test_client, token):
            barrier.wait()
            return test_client.post(
                "/api/agent/leases/acquire",
                headers=agent_headers(token),
                json={"environment_id": environment["id"]},
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = [
                executor.submit(claim, first_agent_client, first["agent_token"]),
                executor.submit(claim, second_agent_client, second["agent_token"]),
            ]
        results = [future.result() for future in responses]
        assert sorted(response.status_code for response in results) == [201, 409]
        winner = next(response for response in results if response.status_code == 201)
        assert winner.json()["lease"]["fencing_token"] == 1


def test_agent_cli_rejects_insecure_remote_url_and_runs_once(monkeypatch, capsys):
    assert agent_cli.validate_cloud_url("http://127.0.0.1:8777/") == (
        "http://127.0.0.1:8777"
    )
    with pytest.raises(ValueError, match="require HTTPS"):
        agent_cli.validate_cloud_url("http://cloud.example.com")

    monkeypatch.setenv("CLOAKBROWSER_AGENT_TOKEN", "cb_agent_test-token")
    monkeypatch.setattr(
        agent_cli,
        "send_heartbeat",
        lambda _url, _token: {"agent_id": "agent-123"},
    )
    agent_cli.cmd_agent(
        Namespace(
            cloud_url="http://127.0.0.1:8777",
            token_file=None,
            interval=20,
            once=True,
        )
    )
    assert "Agent online: agent-123" in capsys.readouterr().out


@pytest.mark.skipif(os.name == "nt", reason="POSIX token-file permissions")
def test_agent_cli_requires_private_token_file(tmp_path, monkeypatch):
    monkeypatch.delenv("CLOAKBROWSER_AGENT_TOKEN", raising=False)
    token_file = tmp_path / "agent.token"
    token = "cb_agent_test-token-with-enough-characters-for-a-local-fixture"
    token_file.write_text(token, encoding="utf-8")
    token_file.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only permissions"):
        agent_cli.load_agent_token(str(token_file))
    token_file.chmod(0o600)
    assert agent_cli.load_agent_token(str(token_file)) == token


def test_remote_launch_and_stop_task_lifecycle(client):
    auth = register(client)
    headers = csrf_headers(auth)
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={"name": "Remote Target", "config": {"fingerprint_seed": 73124}},
    ).json()["environment"]
    created_agent = create_agent(client, auth)
    bring_agent_online(client, created_agent)

    launch = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={
            "agent_id": created_agent["agent"]["id"],
            "expected_revision": environment["revision"],
        },
    )
    assert launch.status_code == 202, launch.text
    launch_task = launch.json()["task"]
    assert launch_task["status"] == "pending"
    duplicate = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={
            "agent_id": created_agent["agent"]["id"],
            "expected_revision": environment["revision"],
        },
    )
    assert duplicate.status_code == 409

    claimed = client.post(
        "/api/agent/tasks/claim",
        headers=agent_headers(created_agent["agent_token"]),
    )
    assert claimed.status_code == 200, claimed.text
    claim = claimed.json()
    assert claim["task"]["id"] == launch_task["id"]
    assert claim["task"]["payload"]["environment"]["config"]["fingerprint_seed"] == 73124
    task_token = claim["task_token"]

    wrong_token = "cb_task_" + "x" * 48
    stale = client.post(
        f"/api/agent/tasks/{launch_task['id']}/heartbeat",
        headers=agent_headers(created_agent["agent_token"]),
        json={"task_token": wrong_token},
    )
    assert stale.status_code == 409
    missing_lease = client.post(
        f"/api/agent/tasks/{launch_task['id']}/complete",
        headers=agent_headers(created_agent["agent_token"]),
        json={"task_token": task_token, "status": "succeeded", "result": {}},
    )
    assert missing_lease.status_code == 409

    acquired = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(created_agent["agent_token"]),
        json={"environment_id": environment["id"]},
    )
    assert acquired.status_code == 201, acquired.text
    lease = acquired.json()["lease"]
    completed = client.post(
        f"/api/agent/tasks/{launch_task['id']}/complete",
        headers=agent_headers(created_agent["agent_token"]),
        json={
            "task_token": task_token,
            "status": "succeeded",
            "result": {
                "lease_id": lease["lease_id"],
                "fencing_token": lease["fencing_token"],
            },
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["task"]["status"] == "succeeded"

    stop = client.post(
        f"/api/environments/{environment['id']}/stop",
        headers=headers,
    )
    assert stop.status_code == 202, stop.text
    stop_task = stop.json()["task"]
    stop_claim = client.post(
        "/api/agent/tasks/claim",
        headers=agent_headers(created_agent["agent_token"]),
    ).json()
    assert stop_claim["task"]["id"] == stop_task["id"]
    stopped = client.post(
        f"/api/agent/tasks/{stop_task['id']}/complete",
        headers=agent_headers(created_agent["agent_token"]),
        json={
            "task_token": stop_claim["task_token"],
            "status": "succeeded",
            "result": {},
        },
    )
    assert stopped.status_code == 200, stopped.text
    assert client.get("/api/leases").json()["leases"] == []
    tasks = client.get("/api/tasks").json()["tasks"]
    assert [task["kind"] for task in tasks[:2]] == ["stop", "launch"]


def test_remote_task_claim_timeout_rejects_old_worker(client, cloud_app):
    auth = register(client)
    headers = csrf_headers(auth)
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={"name": "Claim Timeout", "config": {}},
    ).json()["environment"]
    created_agent = create_agent(client, auth)
    bring_agent_online(client, created_agent)
    queued = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={"agent_id": created_agent["agent"]["id"], "expected_revision": 1},
    ).json()["task"]
    first = client.post(
        "/api/agent/tasks/claim",
        headers=agent_headers(created_agent["agent_token"]),
    ).json()

    with cloud_app.state.session_factory() as db:
        task = db.scalar(select(RemoteTask).where(RemoteTask.id == queued["id"]))
        task.claimed_at = utc_now() - timedelta(minutes=3)
        db.commit()

    second = client.post(
        "/api/agent/tasks/claim",
        headers=agent_headers(created_agent["agent_token"]),
    ).json()
    assert second["task"]["id"] == queued["id"]
    assert second["task_token"] != first["task_token"]
    late = client.post(
        f"/api/agent/tasks/{queued['id']}/complete",
        headers=agent_headers(created_agent["agent_token"]),
        json={"task_token": first["task_token"], "status": "failed", "error": "late"},
    )
    assert late.status_code == 409


def test_agent_revocation_cancels_tasks_and_delete_rejects_active_state(client):
    auth = register(client)
    headers = csrf_headers(auth)
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={"name": "Protected Delete", "config": {}},
    ).json()["environment"]
    created_agent = create_agent(client, auth)
    bring_agent_online(client, created_agent)
    task = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={"agent_id": created_agent["agent"]["id"], "expected_revision": 1},
    ).json()["task"]

    blocked = client.delete(f"/api/environments/{environment['id']}", headers=headers)
    assert blocked.status_code == 409
    revoked = client.delete(
        f"/api/agents/{created_agent['agent']['id']}", headers=headers
    )
    assert revoked.status_code == 204
    tasks = client.get("/api/tasks").json()["tasks"]
    cancelled = next(item for item in tasks if item["id"] == task["id"])
    assert cancelled["status"] == "failed"
    assert "revoked" in cancelled["error"]
    replacement = create_agent(client, auth, "Replacement Runner")
    acquired = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(replacement["agent_token"]),
        json={"environment_id": environment["id"]},
    ).json()
    assert client.delete(
        f"/api/environments/{environment['id']}", headers=headers
    ).status_code == 409
    proof = {
        "lease_id": acquired["lease"]["lease_id"],
        "lease_token": acquired["lease_token"],
        "fencing_token": acquired["lease"]["fencing_token"],
    }
    assert client.post(
        f"/api/agent/leases/{environment['id']}/release",
        headers=agent_headers(replacement["agent_token"]),
        json=proof,
    ).status_code == 204
    assert client.delete(
        f"/api/environments/{environment['id']}", headers=headers
    ).status_code == 204


def test_task_queue_is_tenant_isolated(cloud_app):
    with TestClient(cloud_app) as first_client, TestClient(cloud_app) as second_client:
        first_auth = register(first_client, "first@example.com", "First", "First Team")
        environment = first_client.post(
            "/api/environments",
            headers=csrf_headers(first_auth),
            json={"name": "First Remote", "config": {}},
        ).json()["environment"]
        first_agent = create_agent(first_client, first_auth, "First Runner")
        bring_agent_online(first_client, first_agent)
        queued = first_client.post(
            f"/api/environments/{environment['id']}/launch",
            headers=csrf_headers(first_auth),
            json={"agent_id": first_agent["agent"]["id"], "expected_revision": 1},
        )
        assert queued.status_code == 202

        second_auth = register(second_client, "second@example.com", "Second", "Second Team")
        second_agent = create_agent(second_client, second_auth, "Second Runner")
        bring_agent_online(second_client, second_agent)
        assert second_client.get("/api/tasks").json()["tasks"] == []
        claim = second_client.post(
            "/api/agent/tasks/claim",
            headers=agent_headers(second_agent["agent_token"]),
        )
        assert claim.status_code == 200
        assert claim.json()["task"] is None


def test_concurrent_task_claims_have_one_winner(cloud_app):
    with ExitStack() as stack:
        owner_client = stack.enter_context(TestClient(cloud_app))
        first_worker = stack.enter_context(TestClient(cloud_app))
        second_worker = stack.enter_context(TestClient(cloud_app))
        auth = register(owner_client)
        environment = owner_client.post(
            "/api/environments",
            headers=csrf_headers(auth),
            json={"name": "Concurrent Task", "config": {}},
        ).json()["environment"]
        created_agent = create_agent(owner_client, auth)
        bring_agent_online(owner_client, created_agent)
        queued = owner_client.post(
            f"/api/environments/{environment['id']}/launch",
            headers=csrf_headers(auth),
            json={"agent_id": created_agent["agent"]["id"], "expected_revision": 1},
        ).json()["task"]
        barrier = Barrier(2)

        def claim(test_client):
            barrier.wait()
            return test_client.post(
                "/api/agent/tasks/claim",
                headers=agent_headers(created_agent["agent_token"]),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = [
                executor.submit(claim, first_worker),
                executor.submit(claim, second_worker),
            ]
        payloads = [future.result().json() for future in responses]
        winners = [payload for payload in payloads if payload["task"] is not None]
        assert len(winners) == 1
        assert winners[0]["task"]["id"] == queued["id"]


def test_encrypted_snapshot_upload_download_versioning_and_delete(client, tmp_path):
    auth = register(client)
    headers = csrf_headers(auth)
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={
            "name": "Cloud Snapshot",
            "storage_policy": "backup",
            "config": {},
        },
    ).json()["environment"]
    created_agent = create_agent(client, auth)
    lease_response = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(created_agent["agent_token"]),
        json={"environment_id": environment["id"]},
    ).json()
    proof = {
        "lease_id": lease_response["lease"]["lease_id"],
        "lease_token": lease_response["lease_token"],
        "fencing_token": lease_response["lease"]["fencing_token"],
    }

    without_lease = client.post(
        f"/api/agent/snapshots/{environment['id']}",
        headers=agent_headers(created_agent["agent_token"]),
        json={**proof, "lease_token": proof["lease_token"] + "x"},
    )
    assert without_lease.status_code == 409
    prepared = client.post(
        f"/api/agent/snapshots/{environment['id']}",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    )
    assert prepared.status_code == 200, prepared.text
    manifest = prepared.json()
    assert manifest["version"] == 0
    assert len(manifest["encryption_key"]) >= 40

    browser_data = tmp_path / "browser-data"
    (browser_data / "Default").mkdir(parents=True)
    (browser_data / "Default" / "Cookies").write_bytes(b"private-cookie-state")
    encrypted_path = tmp_path / "snapshot.cbsnap"
    key = base64.urlsafe_b64decode(
        manifest["encryption_key"] + "=" * (-len(manifest["encryption_key"]) % 4)
    )
    artifact = create_encrypted_snapshot(
        browser_data,
        encrypted_path,
        key,
        environment["id"],
        1,
        max_snapshot_bytes=manifest["max_snapshot_bytes"],
    )
    upload_headers = {
        **agent_headers(created_agent["agent_token"]),
        "X-CB-Lease-Id": proof["lease_id"],
        "X-CB-Lease-Token": proof["lease_token"],
        "X-CB-Fencing-Token": str(proof["fencing_token"]),
        "X-CB-Snapshot-Expected-Version": "0",
        "X-CB-Snapshot-Plaintext-Size": str(artifact.plaintext_size),
        "X-CB-Snapshot-SHA256": "0" * 64,
        "Content-Type": "application/vnd.cloakbrowser.snapshot",
    }
    bad_hash = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers=upload_headers,
        content=encrypted_path.read_bytes(),
    )
    assert bad_hash.status_code == 422

    upload_headers["X-CB-Snapshot-SHA256"] = artifact.sha256
    wrong_content_type = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers={**upload_headers, "Content-Type": "application/octet-stream"},
        content=encrypted_path.read_bytes(),
    )
    assert wrong_content_type.status_code == 415

    invalid_content = b"X" * artifact.size
    invalid_format = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers={
            **upload_headers,
            "X-CB-Snapshot-SHA256": hashlib.sha256(invalid_content).hexdigest(),
        },
        content=invalid_content,
    )
    assert invalid_format.status_code == 422
    assert invalid_format.json()["detail"] == "snapshot format is invalid"

    invalid_plaintext_size = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers={
            **upload_headers,
            "X-CB-Snapshot-Plaintext-Size": str(artifact.plaintext_size + 1),
        },
        content=encrypted_path.read_bytes(),
    )
    assert invalid_plaintext_size.status_code == 422
    assert "plaintext size" in invalid_plaintext_size.json()["detail"]

    uploaded = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers=upload_headers,
        content=encrypted_path.read_bytes(),
    )
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["snapshot"]["version"] == 1
    listed = client.get("/api/snapshots").json()["snapshots"]
    assert listed[0]["environment_id"] == environment["id"]
    assert listed[0]["ciphertext_sha256"] == artifact.sha256
    assert "encryption_key" not in listed[0]

    stale = client.put(
        f"/api/agent/snapshots/{environment['id']}/content",
        headers=upload_headers,
        content=encrypted_path.read_bytes(),
    )
    assert stale.status_code == 409
    downloaded = client.post(
        f"/api/agent/snapshots/{environment['id']}/download",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    )
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == encrypted_path.read_bytes()

    blocked_delete = client.delete(
        f"/api/environments/{environment['id']}/snapshot", headers=headers
    )
    assert blocked_delete.status_code == 409
    assert client.post(
        f"/api/agent/leases/{environment['id']}/release",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    ).status_code == 204
    deleted = client.delete(
        f"/api/environments/{environment['id']}/snapshot", headers=headers
    )
    assert deleted.status_code == 204
    assert client.get("/api/snapshots").json()["snapshots"] == []


def test_organization_snapshot_quota_blocks_another_environment(tmp_path):
    limit = 16 * 1024 * 1024
    settings = CloudSettings(
        database_url=f"sqlite:///{tmp_path / 'quota.db'}",
        secret_key="quota-test-secret-with-at-least-thirty-two-bytes",
        assets_dir=Path(__file__).parents[1] / "cloakbrowser" / "cloud" / "ui",
        snapshot_dir=tmp_path / "quota-snapshots",
        snapshot_master_key=os.urandom(32),
        max_snapshot_bytes=limit,
        max_organization_snapshot_bytes=limit,
    )
    app = create_app(settings)
    try:
        with TestClient(app) as quota_client:
            auth = register(
                quota_client,
                email="quota@example.com",
                team="Quota Team",
            )
            mutation_headers = csrf_headers(auth)
            created_agent = create_agent(quota_client, auth)
            agent_auth = agent_headers(created_agent["agent_token"])

            upload_statuses = []
            for index in range(2):
                environment = quota_client.post(
                    "/api/environments",
                    headers=mutation_headers,
                    json={
                        "name": f"Quota Snapshot {index}",
                        "storage_policy": "backup",
                        "config": {},
                    },
                ).json()["environment"]
                lease_response = quota_client.post(
                    "/api/agent/leases/acquire",
                    headers=agent_auth,
                    json={"environment_id": environment["id"]},
                ).json()
                proof = {
                    "lease_id": lease_response["lease"]["lease_id"],
                    "lease_token": lease_response["lease_token"],
                    "fencing_token": lease_response["lease"]["fencing_token"],
                }
                manifest = quota_client.post(
                    f"/api/agent/snapshots/{environment['id']}",
                    headers=agent_auth,
                    json=proof,
                ).json()
                browser_data = tmp_path / f"quota-browser-{index}"
                browser_data.mkdir()
                (browser_data / "state.bin").write_bytes(os.urandom(9 * 1024 * 1024))
                encrypted_path = tmp_path / f"quota-{index}.cbsnap"
                artifact = create_encrypted_snapshot(
                    browser_data,
                    encrypted_path,
                    decode_snapshot_key(manifest["encryption_key"]),
                    environment["id"],
                    1,
                    max_snapshot_bytes=limit,
                )
                response = quota_client.put(
                    f"/api/agent/snapshots/{environment['id']}/content",
                    headers={
                        **agent_auth,
                        "X-CB-Lease-Id": proof["lease_id"],
                        "X-CB-Lease-Token": proof["lease_token"],
                        "X-CB-Fencing-Token": str(proof["fencing_token"]),
                        "X-CB-Snapshot-Expected-Version": "0",
                        "X-CB-Snapshot-Plaintext-Size": str(artifact.plaintext_size),
                        "X-CB-Snapshot-SHA256": artifact.sha256,
                        "Content-Type": "application/vnd.cloakbrowser.snapshot",
                    },
                    content=encrypted_path.read_bytes(),
                )
                upload_statuses.append(response.status_code)

            assert upload_statuses == [200, 413]
            snapshots = quota_client.get("/api/snapshots").json()["snapshots"]
            assert len(snapshots) == 1
            assert snapshots[0]["version"] == 1
    finally:
        app.state.engine.dispose()


def test_proxy_secret_and_extension_distribution_are_lease_scoped(client, tmp_path):
    auth = register(client)
    mutation_headers = csrf_headers(auth)
    package_path = tmp_path / "qa-extension.zip"
    package_content = build_extension_zip(package_path, version="1.2.3")
    package_sha256 = hashlib.sha256(package_content).hexdigest()
    created_package = client.post(
        "/api/extensions",
        headers=mutation_headers,
        json={
            "name": "Cloud QA Extension",
            "version": "1.2.3",
            "content_sha256": package_sha256,
            "content_size": len(package_content),
        },
    )
    assert created_package.status_code == 201, created_package.text
    package = created_package.json()["extension"]
    assert package["status"] == "pending"

    wrong_type = client.put(
        f"/api/extensions/{package['id']}/content",
        headers={**mutation_headers, "Content-Type": "application/octet-stream"},
        content=package_content,
    )
    assert wrong_type.status_code == 415
    uploaded = client.put(
        f"/api/extensions/{package['id']}/content",
        headers={**mutation_headers, "Content-Type": "application/zip"},
        content=package_content,
    )
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["extension"]["status"] == "ready"

    proxy = "http://runtime-user:runtime-password@proxy.example:8080"
    created_environment = client.post(
        "/api/environments",
        headers=mutation_headers,
        json={
            "name": "Secret and Extension Runtime",
            "proxy": proxy,
            "extension_ids": [package["id"]],
            "config": {"fingerprint_seed": 13579, "geoip": True},
        },
    )
    assert created_environment.status_code == 201, created_environment.text
    environment = created_environment.json()["environment"]
    assert environment["proxy_configured"] is True
    assert environment["proxy_masked"] == "http://***@proxy.example:8080"
    assert environment["extension_ids"] == [package["id"]]
    assert "proxy" not in environment["config"]
    assert "runtime-user" not in created_environment.text
    assert "runtime-password" not in created_environment.text

    with client.app.state.session_factory() as db:
        stored_secret = db.get(EnvironmentSecret, environment["id"])
        assert stored_secret is not None
        assert stored_secret.proxy_envelope.startswith("v1.")
        assert "runtime-user" not in stored_secret.proxy_envelope
        assert "runtime-password" not in stored_secret.proxy_envelope

    created_agent = create_agent(client, auth)
    heartbeat = client.post(
        "/api/agent/heartbeat",
        headers=agent_headers(created_agent["agent_token"]),
        json={
            "hostname": "secret-runner",
            "platform": "Test",
            "version": "qa",
            "capabilities": {
                "browser_launch": True,
                "secret_sync": True,
                "extension_sync": True,
            },
        },
    )
    assert heartbeat.status_code == 200
    queued = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=mutation_headers,
        json={
            "agent_id": created_agent["agent"]["id"],
            "expected_revision": environment["revision"],
        },
    )
    assert queued.status_code == 202, queued.text
    claimed = client.post(
        "/api/agent/tasks/claim",
        headers=agent_headers(created_agent["agent_token"]),
    ).json()
    serialized_task = json.dumps(claimed["task"])
    assert "runtime-user" not in serialized_task
    assert "runtime-password" not in serialized_task
    failed_completion = client.post(
        f"/api/agent/tasks/{claimed['task']['id']}/complete",
        headers=agent_headers(created_agent["agent_token"]),
        json={
            "task_token": claimed["task_token"],
            "status": "failed",
            "error": "QA claim cleanup",
            "result": {},
        },
    )
    assert failed_completion.status_code == 200

    lease_response = client.post(
        "/api/agent/leases/acquire",
        headers=agent_headers(created_agent["agent_token"]),
        json={"environment_id": environment["id"]},
    ).json()
    proof = {
        "lease_id": lease_response["lease"]["lease_id"],
        "lease_token": lease_response["lease_token"],
        "fencing_token": lease_response["lease"]["fencing_token"],
    }
    wrong_lease = client.post(
        f"/api/agent/environments/{environment['id']}/runtime-assets",
        headers=agent_headers(created_agent["agent_token"]),
        json={**proof, "lease_token": proof["lease_token"] + "x"},
    )
    assert wrong_lease.status_code == 409
    runtime_assets = client.post(
        f"/api/agent/environments/{environment['id']}/runtime-assets",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    )
    assert runtime_assets.status_code == 200, runtime_assets.text
    assets = runtime_assets.json()
    assert assets["proxy"] == proxy
    assert assets["extensions"][0]["id"] == package["id"]
    downloaded = client.post(
        f"/api/agent/environments/{environment['id']}/extensions/{package['id']}/download",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    )
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == package_content

    blocked_delete = client.delete(
        f"/api/extensions/{package['id']}",
        headers=mutation_headers,
    )
    assert blocked_delete.status_code == 409
    blocked_update = client.patch(
        f"/api/environments/{environment['id']}",
        headers=mutation_headers,
        json={"expected_revision": 1, "proxy": "http://new.example:9000"},
    )
    assert blocked_update.status_code == 409
    released = client.post(
        f"/api/agent/leases/{environment['id']}/release",
        headers=agent_headers(created_agent["agent_token"]),
        json=proof,
    )
    assert released.status_code == 204
    cleared = client.patch(
        f"/api/environments/{environment['id']}",
        headers=mutation_headers,
        json={
            "expected_revision": 1,
            "clear_proxy": True,
            "extension_ids": [],
        },
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["environment"]["proxy_configured"] is False
    assert cleared.json()["environment"]["extension_ids"] == []
    assert client.delete(
        f"/api/extensions/{package['id']}",
        headers=mutation_headers,
    ).status_code == 204

    actions = {entry["action"] for entry in client.get("/api/audit").json()["entries"]}
    assert {"extension.created", "extension.uploaded", "extension.deleted"} <= actions


def test_extension_upload_rejects_unsafe_archive_paths(client, tmp_path):
    auth = register(client)
    headers = csrf_headers(auth)
    package_path = tmp_path / "unsafe-extension.zip"
    content = build_extension_zip(package_path, unsafe_name="../escaped.txt")
    created = client.post(
        "/api/extensions",
        headers=headers,
        json={
            "name": "Unsafe Extension",
            "version": "1.0.0",
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "content_size": len(content),
        },
    ).json()["extension"]
    upload = client.put(
        f"/api/extensions/{created['id']}/content",
        headers={**headers, "Content-Type": "application/zip"},
        content=content,
    )
    assert upload.status_code == 422
    assert "unsafe path" in upload.json()["detail"]
    assert not (tmp_path / "escaped.txt").exists()


def test_extension_management_rbac_and_tenant_isolation(cloud_app, tmp_path):
    with TestClient(cloud_app) as owner_client, TestClient(cloud_app) as viewer_client:
        owner_auth = register(owner_client, "owner@example.com", "Owner", "Owner Team")
        package_path = tmp_path / "private-extension.zip"
        content = build_extension_zip(package_path)
        package = owner_client.post(
            "/api/extensions",
            headers=csrf_headers(owner_auth),
            json={
                "name": "Private Extension",
                "version": "1.0.0",
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "content_size": len(content),
            },
        ).json()["extension"]

        viewer_auth = register(
            viewer_client,
            "viewer@example.com",
            "Viewer",
            "Viewer Personal",
        )
        personal_org_id = viewer_auth["organization"]["id"]
        added = owner_client.post(
            "/api/members",
            headers=csrf_headers(owner_auth),
            json={"email": "viewer@example.com", "role": "viewer"},
        )
        assert added.status_code == 201, added.text
        viewer_session = current_session(viewer_client)
        shared_org_id = next(
            organization["id"]
            for organization in viewer_session["organizations"]
            if organization["name"] == "Owner Team"
        )
        switched = viewer_client.post(
            "/api/session/organization",
            headers={"X-CSRF-Token": viewer_session["csrf_token"]},
            json={"organization_id": shared_org_id},
        )
        assert switched.status_code == 200
        viewer_session = current_session(viewer_client)
        assert [item["id"] for item in viewer_client.get("/api/extensions").json()["extensions"]] == [package["id"]]
        viewer_headers = {"X-CSRF-Token": viewer_session["csrf_token"]}
        assert viewer_client.post(
            "/api/extensions",
            headers=viewer_headers,
            json={
                "name": "Forbidden",
                "version": "1.0.0",
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "content_size": len(content),
            },
        ).status_code == 403
        assert viewer_client.put(
            f"/api/extensions/{package['id']}/content",
            headers={**viewer_headers, "Content-Type": "application/zip"},
            content=content,
        ).status_code == 403
        assert viewer_client.delete(
            f"/api/extensions/{package['id']}",
            headers=viewer_headers,
        ).status_code == 403

        switched_back = viewer_client.post(
            "/api/session/organization",
            headers=viewer_headers,
            json={"organization_id": personal_org_id},
        )
        assert switched_back.status_code == 200
        personal_session = current_session(viewer_client)
        assert viewer_client.get("/api/extensions").json()["extensions"] == []
        assert viewer_client.put(
            f"/api/extensions/{package['id']}/content",
            headers={
                "X-CSRF-Token": personal_session["csrf_token"],
                "Content-Type": "application/zip",
            },
            content=content,
        ).status_code == 404


def test_extension_upload_rejects_symbolic_links(client, tmp_path):
    auth = register(client)
    headers = csrf_headers(auth)
    package_path = tmp_path / "symlink-extension.zip"
    manifest = {
        "manifest_version": 3,
        "name": "Symlink Extension",
        "version": "1.0.0",
    }
    link = zipfile.ZipInfo("linked-worker.js")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(package_path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(link, "../../outside.js")
    content = package_path.read_bytes()
    package = client.post(
        "/api/extensions",
        headers=headers,
        json={
            "name": "Symlink Extension",
            "version": "1.0.0",
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "content_size": len(content),
        },
    ).json()["extension"]
    upload = client.put(
        f"/api/extensions/{package['id']}/content",
        headers={**headers, "Content-Type": "application/zip"},
        content=content,
    )
    assert upload.status_code == 422
    assert "unsupported entry" in upload.json()["detail"]


def test_snapshot_crypto_round_trip_and_authentication(tmp_path):
    source = tmp_path / "source"
    (source / "Default" / "IndexedDB").mkdir(parents=True)
    (source / "Default" / "Cookies").write_bytes(b"cookie-secret" * 100)
    (source / "Default" / "IndexedDB" / "state.db").write_bytes(b"index-db")
    (source / "SingletonLock").write_text("ignored", encoding="utf-8")
    environment_id = str(uuid.uuid4())
    key = os.urandom(32)
    with pytest.raises(SnapshotError, match="encoding is invalid"):
        decode_snapshot_key(encode_snapshot_key(key) + "$")
    encrypted = tmp_path / "profile.cbsnap"
    artifact = create_encrypted_snapshot(
        source,
        encrypted,
        key,
        environment_id,
        1,
        max_snapshot_bytes=16 * 1024 * 1024,
    )
    assert artifact.sha256 == hashlib.sha256(encrypted.read_bytes()).hexdigest()
    assert b"cookie-secret" not in encrypted.read_bytes()

    restored = tmp_path / "restored"
    restore_encrypted_snapshot(
        encrypted,
        restored,
        key,
        environment_id,
        1,
        max_unpacked_bytes=16 * 1024 * 1024,
    )
    assert (restored / "Default" / "Cookies").read_bytes() == b"cookie-secret" * 100
    assert (restored / "Default" / "IndexedDB" / "state.db").read_bytes() == b"index-db"
    assert not (restored / "SingletonLock").exists()

    tampered = bytearray(encrypted.read_bytes())
    tampered[-1] ^= 1
    encrypted.write_bytes(tampered)
    with pytest.raises(SnapshotError, match="authentication"):
        restore_encrypted_snapshot(
            encrypted,
            tmp_path / "tampered",
            key,
            environment_id,
            1,
            max_unpacked_bytes=16 * 1024 * 1024,
        )


def test_cloud_snapshot_launch_requires_capable_agent_and_blocks_live_edits(client):
    auth = register(client)
    headers = csrf_headers(auth)
    environment = client.post(
        "/api/environments",
        headers=headers,
        json={"name": "Snapshot Capability", "storage_policy": "shared", "config": {}},
    ).json()["environment"]
    created_agent = create_agent(client, auth)
    client.post(
        "/api/agent/heartbeat",
        headers=agent_headers(created_agent["agent_token"]),
        json={"capabilities": {"browser_launch": True, "snapshot_sync": False}},
    )
    rejected = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={"agent_id": created_agent["agent"]["id"], "expected_revision": 1},
    )
    assert rejected.status_code == 409
    assert "cannot synchronize" in rejected.json()["detail"]

    client.post(
        "/api/agent/heartbeat",
        headers=agent_headers(created_agent["agent_token"]),
        json={"capabilities": {"browser_launch": True, "snapshot_sync": True}},
    )
    queued = client.post(
        f"/api/environments/{environment['id']}/launch",
        headers=headers,
        json={"agent_id": created_agent["agent"]["id"], "expected_revision": 1},
    )
    assert queued.status_code == 202, queued.text
    blocked = client.patch(
        f"/api/environments/{environment['id']}",
        headers=headers,
        json={"expected_revision": 1, "storage_policy": "local"},
    )
    assert blocked.status_code == 409
    assert "remote task" in blocked.json()["detail"]


class FakeAgentAPI:
    def __init__(self):
        self.completed = []
        self.released = []
        self.lease_heartbeats = []

    def acquire_lease(self, environment_id):
        return {
            "lease": {
                "lease_id": str(uuid.uuid4()),
                "fencing_token": 7,
            },
            "lease_token": "cb_lease_" + "x" * 48,
        }

    def heartbeat_lease(self, environment_id, proof):
        self.lease_heartbeats.append((environment_id, proof))
        return {"lease": {}}

    def release_lease(self, environment_id, proof):
        self.released.append((environment_id, dict(proof)))

    def runtime_assets(self, _environment_id, _proof):
        return {
            "proxy": "",
            "proxy_version": 0,
            "extensions": [],
            "max_extension_bytes": 100 * 1024 * 1024,
            "max_extension_unpacked_bytes": 512 * 1024 * 1024,
        }

    def heartbeat_task(self, task_id, task_token):
        return {"status": "ok"}

    def complete_task(self, task_id, task_token, status, *, result=None, error=""):
        self.completed.append(
            {
                "task_id": task_id,
                "task_token": task_token,
                "status": status,
                "result": result or {},
                "error": error,
            }
        )
        return {"task": {"id": task_id, "status": status}}


class FakeBrowserContext:
    def __init__(self):
        self.pages = []
        self.closed = False

    def new_page(self):
        raise AssertionError("about:blank should not create a page")

    def close(self):
        self.closed = True


class FakeSnapshotAgentAPI(FakeAgentAPI):
    def __init__(self):
        super().__init__()
        self.snapshot_key = os.urandom(32)
        self.snapshot_version = 0
        self.snapshot_content = b""
        self.snapshot_sha256 = None
        self.upload_attempts = 0
        self.upload_failures_remaining = 0

    def snapshot_manifest(self, _environment_id, _proof):
        return {
            "version": self.snapshot_version,
            "ciphertext_sha256": self.snapshot_sha256,
            "encryption_key": encode_snapshot_key(self.snapshot_key),
            "max_snapshot_bytes": 16 * 1024 * 1024,
        }

    def download_snapshot(
        self,
        _environment_id,
        _proof,
        destination,
        *,
        expected_sha256,
        max_snapshot_bytes,
    ):
        assert len(self.snapshot_content) <= max_snapshot_bytes
        assert hashlib.sha256(self.snapshot_content).hexdigest() == expected_sha256
        destination.write_bytes(self.snapshot_content)

    def upload_snapshot(
        self,
        environment_id,
        _proof,
        artifact,
        *,
        expected_version,
    ):
        self.upload_attempts += 1
        if self.upload_failures_remaining:
            self.upload_failures_remaining -= 1
            raise RuntimeError("simulated snapshot upload outage")
        assert expected_version == self.snapshot_version
        self.snapshot_content = artifact.path.read_bytes()
        self.snapshot_sha256 = hashlib.sha256(self.snapshot_content).hexdigest()
        assert self.snapshot_sha256 == artifact.sha256
        self.snapshot_version += 1
        return {
            "snapshot": {
                "environment_id": environment_id,
                "version": self.snapshot_version,
                "ciphertext_sha256": self.snapshot_sha256,
            }
        }


class FakeRuntimeAssetAPI(FakeAgentAPI):
    def __init__(self, extension_content, extension_id, proxy):
        super().__init__()
        self.extension_content = extension_content
        self.extension_id = extension_id
        self.proxy = proxy
        self.extension_sha256 = hashlib.sha256(extension_content).hexdigest()
        self.extension_downloads = 0

    def runtime_assets(self, _environment_id, _proof):
        return {
            "proxy": self.proxy,
            "proxy_version": 1,
            "extensions": [
                {
                    "id": self.extension_id,
                    "name": "Runtime QA Extension",
                    "version": "1.0.0",
                    "content_sha256": self.extension_sha256,
                    "content_size": len(self.extension_content),
                }
            ],
            "max_extension_bytes": 10 * 1024 * 1024,
            "max_extension_unpacked_bytes": 50 * 1024 * 1024,
        }

    def download_extension(
        self,
        _environment_id,
        extension_id,
        _proof,
        destination,
        *,
        expected_sha256,
        expected_size,
        max_extension_bytes,
    ):
        assert extension_id == self.extension_id
        assert expected_sha256 == self.extension_sha256
        assert expected_size == len(self.extension_content)
        assert expected_size <= max_extension_bytes
        self.extension_downloads += 1
        destination.write_bytes(self.extension_content)


def test_agent_runtime_launches_and_stops_persistent_browser(tmp_path):
    api = FakeAgentAPI()
    launched = []

    def launcher(data_dir, **options):
        context = FakeBrowserContext()
        launched.append((Path(data_dir), options, context))
        return context

    runtime = AgentRuntime(
        api,
        tmp_path / "agent",
        heartbeat_payload={},
        launcher=launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    environment_id = str(uuid.uuid4())
    task_token = "cb_task_" + "t" * 48
    environment = {
        "id": environment_id,
        "name": "Runtime Target",
        "revision": 3,
        "storage_policy": "local",
        "config": {
            "fingerprint_seed": 45678,
            "storage_quota_mb": 4096,
            "headless": True,
            "humanize": False,
            "timezone": "Asia/Shanghai",
            "locale": "zh-CN",
            "location": "new-york",
            "startup_url": "about:blank",
            "fingerprint_platform": "windows",
            "fingerprint_brand": "Edge",
            "fingerprint_brand_version": "150.0.1.2",
            "fingerprint_platform_version": "10.0.0",
            "hardware_concurrency": 8,
            "device_memory_gb": 4,
            "screen_width": 1920,
            "screen_height": 1080,
            "gpu_vendor": "Google Inc. (NVIDIA)",
            "gpu_renderer": "ANGLE (NVIDIA GeForce RTX 3060)",
            "taskbar_height": 40,
            "fingerprint_noise": False,
            "allow_third_party_cookies": True,
        },
    }
    runtime.process_claimed_task(
        {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": "launch",
                "environment_id": environment_id,
                "environment_revision": 3,
                "payload": {"environment": environment},
            },
            "task_token": task_token,
        }
    )
    assert api.completed[-1]["status"] == "succeeded"
    assert api.completed[-1]["result"]["fencing_token"] == 7
    assert launched[0][0] == tmp_path / "agent" / "browser-data" / environment_id
    assert launched[0][1]["headless"] is True
    assert "--fingerprint=45678" in launched[0][1]["args"]
    assert "--fingerprint-storage-quota=4096" in launched[0][1]["args"]
    assert "--fingerprint-platform=windows" in launched[0][1]["args"]
    assert "--fingerprint-brand=Edge" in launched[0][1]["args"]
    assert "--fingerprint-brand-version=150.0.1.2" in launched[0][1]["args"]
    assert "--fingerprint-platform-version=10.0.0" in launched[0][1]["args"]
    assert "--fingerprint-hardware-concurrency=8" in launched[0][1]["args"]
    assert "--fingerprint-device-memory=4" in launched[0][1]["args"]
    assert "--fingerprint-screen-width=1920" in launched[0][1]["args"]
    assert "--fingerprint-screen-height=1080" in launched[0][1]["args"]
    assert "--fingerprint-gpu-vendor=Google Inc. (NVIDIA)" in launched[0][1]["args"]
    assert "--fingerprint-gpu-renderer=ANGLE (NVIDIA GeForce RTX 3060)" in launched[0][1]["args"]
    assert "--fingerprint-taskbar-height=40" in launched[0][1]["args"]
    assert "--fingerprint-noise=false" in launched[0][1]["args"]
    assert "--fingerprint-allow-3p-cookies" in launched[0][1]["args"]
    assert launched[0][1]["locale"] == "zh-CN"
    assert launched[0][1]["geolocation"] == {
        "latitude": 40.7128,
        "longitude": -74.006,
        "accuracy": 50.0,
    }
    assert launched[0][1]["permissions"] == ["geolocation"]

    lease_id = api.completed[-1]["result"]["lease_id"]
    runtime.process_claimed_task(
        {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": "stop",
                "environment_id": environment_id,
                "environment_revision": 3,
                "payload": {"lease_id": lease_id, "fencing_token": 7},
            },
            "task_token": task_token,
        }
    )
    assert api.completed[-1]["status"] == "succeeded"
    assert launched[0][2].closed is True
    assert api.released[-1][0] == environment_id
    runtime.shutdown()


def test_agent_runtime_syncs_snapshot_between_agent_data_directories(tmp_path):
    api = FakeSnapshotAgentAPI()
    environment_id = str(uuid.uuid4())
    environment = {
        "id": environment_id,
        "name": "Shared Runtime Target",
        "revision": 1,
        "storage_policy": "shared",
        "config": {
            "fingerprint_seed": 56789,
            "storage_quota_mb": 5000,
            "headless": True,
            "humanize": False,
            "timezone": "",
            "locale": "",
            "location": "",
            "startup_url": "about:blank",
        },
    }

    def task(kind, payload):
        return {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": payload,
            },
            "task_token": "cb_task_" + "s" * 48,
        }

    def first_launcher(data_dir, **_options):
        default_dir = Path(data_dir) / "Default"
        default_dir.mkdir(parents=True, exist_ok=True)
        (default_dir / "Cookies").write_bytes(b"state-from-agent-a")
        return FakeBrowserContext()

    first = AgentRuntime(
        api,
        tmp_path / "agent-a",
        heartbeat_payload={},
        launcher=first_launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    first.process_claimed_task(task("launch", {"environment": environment}))
    first_lease = api.completed[-1]["result"]
    first.process_claimed_task(
        task(
            "stop",
            {
                "lease_id": first_lease["lease_id"],
                "fencing_token": first_lease["fencing_token"],
            },
        )
    )
    assert api.completed[-1]["status"] == "succeeded"
    assert api.completed[-1]["result"]["snapshot_version"] == 1
    assert api.snapshot_version == 1
    first.shutdown()

    restored_values = []

    def second_launcher(data_dir, **_options):
        cookie_path = Path(data_dir) / "Default" / "Cookies"
        restored_values.append(cookie_path.read_bytes())
        cookie_path.write_bytes(b"state-from-agent-b")
        return FakeBrowserContext()

    second = AgentRuntime(
        api,
        tmp_path / "agent-b",
        heartbeat_payload={},
        launcher=second_launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    second.process_claimed_task(task("launch", {"environment": environment}))
    assert restored_values == [b"state-from-agent-a"]
    assert api.completed[-1]["result"]["snapshot_version"] == 1
    second_lease = api.completed[-1]["result"]
    second.process_claimed_task(
        task(
            "stop",
            {
                "lease_id": second_lease["lease_id"],
                "fencing_token": second_lease["fencing_token"],
            },
        )
    )
    assert api.completed[-1]["result"]["snapshot_version"] == 2
    assert api.snapshot_version == 2
    second.shutdown()


def test_agent_runtime_loads_proxy_and_caches_extension_package(tmp_path):
    extension_path = tmp_path / "runtime-extension.zip"
    extension_content = build_extension_zip(extension_path)
    extension_id = str(uuid.uuid4())
    proxy = "http://runtime-user:runtime-password@proxy.example:8080"
    api = FakeRuntimeAssetAPI(extension_content, extension_id, proxy)
    environment_id = str(uuid.uuid4())
    environment = {
        "id": environment_id,
        "name": "Runtime Assets",
        "revision": 1,
        "storage_policy": "local",
        "config": {
            "fingerprint_seed": 97531,
            "storage_quota_mb": 5000,
            "geoip": True,
            "startup_url": "about:blank",
        },
    }

    def task(kind, payload):
        return {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": payload,
            },
            "task_token": "cb_task_" + "a" * 48,
        }

    launched = []

    def launcher(_data_dir, **options):
        extension_directory = Path(options["extension_paths"][0])
        assert json.loads(
            (extension_directory / "manifest.json").read_text(encoding="utf-8")
        )["version"] == "1.0.0"
        launched.append(options)
        return FakeBrowserContext()

    runtime = AgentRuntime(
        api,
        tmp_path / "asset-agent",
        heartbeat_payload={},
        launcher=launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    for _ in range(2):
        runtime.process_claimed_task(task("launch", {"environment": environment}))
        assert api.completed[-1]["status"] == "succeeded"
        lease = api.completed[-1]["result"]
        runtime.process_claimed_task(
            task(
                "stop",
                {
                    "lease_id": lease["lease_id"],
                    "fencing_token": lease["fencing_token"],
                },
            )
        )
        assert api.completed[-1]["status"] == "succeeded"
    assert api.extension_downloads == 1
    assert len(launched) == 2
    assert launched[0]["proxy"] == proxy
    assert launched[0]["geoip"] is True
    assert launched[0]["extension_paths"] == launched[1]["extension_paths"]
    runtime.shutdown()


def test_agent_runtime_redacts_proxy_credentials_from_launch_errors(tmp_path):
    extension_path = tmp_path / "redaction-extension.zip"
    content = build_extension_zip(extension_path)
    proxy = "http://private-user:private-password@proxy.example:8080"
    api = FakeRuntimeAssetAPI(content, str(uuid.uuid4()), proxy)
    environment_id = str(uuid.uuid4())

    def failed_launcher(_data_dir, **options):
        raise RuntimeError(f"could not connect through {options['proxy']}")

    runtime = AgentRuntime(
        api,
        tmp_path / "redaction-agent",
        heartbeat_payload={},
        launcher=failed_launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    runtime.process_claimed_task(
        {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": "launch",
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": {
                    "environment": {
                        "id": environment_id,
                        "revision": 1,
                        "storage_policy": "local",
                        "config": {
                            "fingerprint_seed": 86420,
                            "storage_quota_mb": 5000,
                        },
                    }
                },
            },
            "task_token": "cb_task_" + "e" * 48,
        }
    )
    error = api.completed[-1]["error"]
    assert api.completed[-1]["status"] == "failed"
    assert "private-user" not in error
    assert "private-password" not in error
    assert "<redacted proxy>" in error
    runtime.shutdown()


def test_agent_runtime_retries_dirty_snapshot_before_next_launch(tmp_path):
    api = FakeSnapshotAgentAPI()
    api.upload_failures_remaining = 1
    environment_id = str(uuid.uuid4())
    environment = {
        "id": environment_id,
        "name": "Retry Snapshot",
        "revision": 1,
        "storage_policy": "backup",
        "config": {"fingerprint_seed": 67890, "storage_quota_mb": 5000},
    }

    def task(kind, payload):
        return {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": payload,
            },
            "task_token": "cb_task_" + "r" * 48,
        }

    launches = []

    def launcher(data_dir, **_options):
        cookie_path = Path(data_dir) / "Default" / "Cookies"
        cookie_path.parent.mkdir(parents=True, exist_ok=True)
        if cookie_path.exists():
            launches.append(cookie_path.read_bytes())
        else:
            cookie_path.write_bytes(b"unsynchronized-local-state")
        return FakeBrowserContext()

    agent_dir = tmp_path / "retry-agent"
    runtime = AgentRuntime(
        api,
        agent_dir,
        heartbeat_payload={},
        launcher=launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    runtime.process_claimed_task(task("launch", {"environment": environment}))
    first_lease = api.completed[-1]["result"]
    runtime.process_claimed_task(
        task(
            "stop",
            {
                "lease_id": first_lease["lease_id"],
                "fencing_token": first_lease["fencing_token"],
            },
        )
    )
    assert api.completed[-1]["status"] == "failed"
    assert "snapshot upload failed" in api.completed[-1]["error"]
    state_path = agent_dir / "snapshot-state" / f"{environment_id}.json"
    assert state_path.read_text(encoding="utf-8") == '{"version":0,"dirty":true}\n'
    assert api.snapshot_version == 0

    runtime.process_claimed_task(task("launch", {"environment": environment}))
    assert api.completed[-1]["status"] == "succeeded"
    assert api.completed[-1]["result"]["snapshot_version"] == 1
    assert api.snapshot_version == 1
    assert api.upload_attempts == 2
    assert launches == [b"unsynchronized-local-state"]
    runtime.shutdown()


def test_agent_runtime_preserves_dirty_data_when_cloud_also_changed(tmp_path):
    api = FakeSnapshotAgentAPI()
    api.upload_failures_remaining = 1
    environment_id = str(uuid.uuid4())
    environment = {
        "id": environment_id,
        "name": "Conflicting Snapshot",
        "revision": 1,
        "storage_policy": "shared",
        "config": {"fingerprint_seed": 78901, "storage_quota_mb": 5000},
    }

    def task(kind, payload):
        return {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": payload,
            },
            "task_token": "cb_task_" + "c" * 48,
        }

    launches = 0

    def launcher(data_dir, **_options):
        nonlocal launches
        launches += 1
        cookie_path = Path(data_dir) / "Default" / "Cookies"
        cookie_path.parent.mkdir(parents=True, exist_ok=True)
        cookie_path.write_bytes(b"local-data-that-must-survive")
        return FakeBrowserContext()

    agent_dir = tmp_path / "conflict-agent"
    runtime = AgentRuntime(
        api,
        agent_dir,
        heartbeat_payload={},
        launcher=launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    runtime.process_claimed_task(task("launch", {"environment": environment}))
    first_lease = api.completed[-1]["result"]
    runtime.process_claimed_task(
        task(
            "stop",
            {
                "lease_id": first_lease["lease_id"],
                "fencing_token": first_lease["fencing_token"],
            },
        )
    )
    assert api.completed[-1]["status"] == "failed"

    api.snapshot_version = 1
    runtime.process_claimed_task(task("launch", {"environment": environment}))
    assert api.completed[-1]["status"] == "failed"
    assert "local data was preserved" in api.completed[-1]["error"]
    assert launches == 1
    local_cookie = agent_dir / "browser-data" / environment_id / "Default" / "Cookies"
    assert local_cookie.read_bytes() == b"local-data-that-must-survive"
    runtime.shutdown()


def test_agent_runtime_reports_launch_failure_and_releases_lease(tmp_path):
    api = FakeAgentAPI()

    def failed_launcher(_data_dir, **_options):
        raise RuntimeError("launcher failed")

    runtime = AgentRuntime(
        api,
        tmp_path / "agent",
        heartbeat_payload={},
        launcher=failed_launcher,
        launch_timeout=2,
        stop_timeout=2,
    )
    environment_id = str(uuid.uuid4())
    runtime.process_claimed_task(
        {
            "task": {
                "id": str(uuid.uuid4()),
                "kind": "launch",
                "environment_id": environment_id,
                "environment_revision": 1,
                "payload": {
                    "environment": {
                        "id": environment_id,
                        "revision": 1,
                        "config": {
                            "fingerprint_seed": 12345,
                            "storage_quota_mb": 5000,
                        },
                    }
                },
            },
            "task_token": "cb_task_" + "t" * 48,
        }
    )
    assert api.completed[-1]["status"] == "failed"
    assert "launcher failed" in api.completed[-1]["error"]
    assert api.released[-1][0] == environment_id
    runtime.shutdown()


def test_cloud_ui_exposes_agent_management():
    root = Path(__file__).parents[1] / "cloakbrowser" / "cloud" / "ui"
    html = (root / "index.html").read_text(encoding="utf-8")
    javascript = (root / "app.js").read_text(encoding="utf-8")
    assert 'id="agentsView"' in html
    assert 'id="tasksView"' in html
    assert 'id="launchDialog"' in html
    assert 'id="storagePolicyNotice"' in html
    assert 'id="environmentLocation"' in html
    assert 'id="environmentAdvancedFingerprint"' in html
    assert 'id="environmentFingerprintPlatform"' in html
    assert 'id="environmentFingerprintBrand"' in html
    assert 'id="environmentHardwareConcurrency"' in html
    assert 'id="environmentDeviceMemory"' in html
    assert 'id="environmentScreenSize"' in html
    assert 'id="environmentGpuVendor"' in html
    assert 'id="environmentStorageQuota"' in html
    assert 'id="environmentConsistencyWarning"' in html
    assert 'id="agentTokenDialog"' in html
    assert "renderAgents" in javascript
    assert "renderTasks" in javascript
    assert "requestEnvironmentLaunch" in javascript
    assert "updateStoragePolicyNotice" in javascript
    assert "environmentAdvancedPayload" in javascript
    assert "updateEnvironmentConsistencyWarnings" in javascript
    assert "confirmSnapshotDelete" in javascript
    assert 'api("/api/snapshots")' in javascript
    assert "confirmEnvironmentStop" in javascript
    assert "confirmAgentTokenRotation" in javascript
    assert "fencing_token" in javascript
