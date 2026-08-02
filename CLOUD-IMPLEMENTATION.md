# Cloud Team Console Implementation Record

Date: 2026-08-02

Status: preview implementation complete through encrypted profile sync, runtime
secret delivery, and managed extension distribution.

## Scope

This work adds a team-oriented cloud control plane beside the existing local
Browser Environment Manager. The local manager remains a single-machine tool on
`127.0.0.1:8765`; the cloud console is a separate FastAPI application, normally
on `127.0.0.1:8777` for development.

The cloud layer coordinates users, teams, environment configuration, execution
Agents, encrypted browser-profile transfer, proxy secrets, and extension
packages. It does not replace the CloakBrowser binary or add a separate
anti-detection mechanism. Browser fingerprint behavior still comes from the
CloakBrowser binary and the selected environment configuration.

## Delivered Changes

### Commands and packaging

- Added the optional `cloakbrowser[cloud]` dependency set.
- Added `cloakbrowser cloud` for the control plane and web console.
- Added `cloakbrowser agent` for execution nodes.
- Kept cloud data and local Manager data in separate directories.
- SQLite is the development default; PostgreSQL URLs are accepted for
  deployment.

### Accounts, teams, and permissions

- Added registration, login, logout, opaque server-side sessions, and team
  switching.
- Passwords use Argon2id; raw session tokens are not stored.
- Added organizations and memberships with Owner, Admin, Operator, and Viewer
  roles.
- API permissions are enforced server-side, including tenant isolation.
- Added team-member role changes, removal rules, and last-owner protection.
- Added organization-scoped audit logs.

### Environment and group management

- Added organization-scoped environment groups and tags.
- Added `local`, `backup`, and `shared` storage policies.
- Added optimistic Revision compare-and-swap checks to prevent silent overwrite
  by another team member.
- Added UI reminders for stale revisions, active remote tasks, live environments,
  duplicate names, GeoIP without a proxy, and incompatible Agent capabilities.
- Runtime, proxy, extension, and storage settings cannot change while the
  environment has an active lease.
- Local Manager fingerprint configuration continues to report incomplete GPU
  pairs and obvious host/platform conflicts before save or launch.

### Remote execution

- Added one-time-displayed Agent tokens; only token digests are stored.
- Added Agent heartbeat, capability reporting, token rotation, and revocation.
- Added remote launch/stop task queues with separate expiring task credentials.
- Added exclusive environment leases, lease secrets, renewal, expiry, and
  monotonically increasing fencing tokens.
- Added task history and failure reporting.
- Launch selection checks `browser_launch`, `snapshot_sync`, `secret_sync`, and
  `extension_sync` against the selected environment.

### Browser data storage and synchronization

- `local` keeps Chromium user-data only on the selected Agent.
- `backup` and `shared` archive the complete closed Chromium user-data directory.
  This includes cookies, LocalStorage, IndexedDB, HTTP cache, service workers,
  extension state, preferences, and history.
- Each environment snapshot uses its own AES-256-GCM data key.
- Environment data keys are wrapped by the cloud master key; snapshot objects
  remain ciphertext on the server.
- Snapshot download, key access, and upload require the current Agent lease.
- Version checks and fencing prevent expired Agents from overwriting newer data.
- Failed uploads preserve a local dirty marker and retry before the next launch.
- If local dirty data and the cloud snapshot both changed, launch stops with a
  conflict instead of choosing one copy automatically.
- Added safe archive creation/extraction and snapshot size/organization quotas.

### Proxy secrets

- Added `EnvironmentSecret` as a separate storage boundary from normal
  environment configuration.
- Proxy URLs are encrypted with AES-256-GCM. Authenticated data binds the
  organization, environment, secret type, and secret version.
- Environment APIs return only `proxy_configured`, `proxy_masked`, and
  `secret_revision`.
- Proxy plaintext is not included in remote-task payloads or audit details.
- The Agent can fetch plaintext only while holding the current environment lease.
- Proxy plaintext stays in Agent runtime memory and is passed directly to the
  launcher.
- Agent launch errors redact the complete proxy URL, username, and password.
- The editor supports replacing or explicitly clearing a stored proxy without
  returning the existing credential to the browser UI.

### Managed extension packages

- Added immutable organization-scoped extension packages.
- Owner and Admin roles can create, upload, and delete packages; all roles can
  read them.
- Upload is a two-stage operation: metadata plus expected SHA-256/size, followed
  by raw ZIP content.
- Server validation covers media type, compressed size, organization quota,
  SHA-256, ZIP CRC, member count, unpacked size, safe paths, entry types,
  root `manifest.json`, manifest version, and package version.
- Path traversal, absolute paths, backslash paths, encrypted members, symbolic
  links, devices, and other unsupported entries are rejected.
- Environments store ordered package associations; assigned packages cannot be
  deleted.
- Package metadata/download requires tenant authorization and the current
  environment lease.
- Agents download by package ID and digest, validate and safely unpack again,
  and reuse a SHA-256-addressed local cache on later launches.

### Cloud web console

- Added workspaces for environments, groups, team members, extensions, Agents,
  tasks, and audit logs.
- Added extension ZIP upload, status, assignment count, and confirmed deletion.
- Added proxy replacement/clear controls, masked current status, GeoIP control,
  and extension selection to the environment editor.
- Matched the local Manager's effective environment settings for region,
  storage quota, platform and browser identity, versions, CPU, device memory,
  screen size, taskbar height, GPU, fingerprint noise, third-party cookies,
  headless mode, and humanization. These values round-trip through the cloud API
  and use the same Chromium launch-argument builder as local environments.
- Added local-style consistency warnings while creating or editing an
  environment, covering location/timezone, GeoIP/manual region overrides,
  incomplete GPU identity, platform/taskbar combinations, low storage quota,
  disabled fingerprint noise, and the Chromium 148+ cookie requirement.
- Added Chinese conflict messages for Revision and runtime-state `409` responses.
- Added desktop and mobile layouts; wide tables remain horizontally scrollable
  inside their own containers.
- Raw `Blob`, `FormData`, and `ArrayBuffer` API bodies are no longer JSON encoded,
  allowing streamed ZIP upload while retaining CSRF protection.

## Main Data Models

- `User`, `Organization`, `Membership`, `CloudSession`
- `Group`, `Environment`, `EnvironmentSecret`
- `ExtensionPackage`, `EnvironmentExtension`
- `AgentNode`, `EnvironmentLease`, `RemoteTask`
- `EnvironmentSnapshot`, `AuditLog`

## Security Invariants

- Every user-facing resource lookup is organization-scoped.
- Browser mutations require a matching CSRF token.
- Public binds require a configured application secret, secure cookies, and an
  HTTPS reverse proxy.
- Agent tokens, task tokens, and lease tokens have separate purposes and
  lifetimes.
- A lease from one organization or environment cannot read another environment's
  snapshots, secrets, or extensions.
- A task payload is safe to persist and inspect; runtime secrets are fetched only
  after lease acquisition.
- Only one Agent can own an environment lease at a time.
- Revision conflicts and snapshot conflicts fail closed.
- Extension and snapshot archives are validated before extraction, and extraction
  never trusts archive paths.
- The master key must be backed up separately. Losing it makes wrapped snapshot
  keys and proxy secrets unrecoverable.

## Configuration

- `CLOAKBROWSER_CLOUD_DATABASE_URL`
- `CLOAKBROWSER_CLOUD_SECRET`
- `CLOAKBROWSER_CLOUD_COOKIE_SECURE`
- `CLOAKBROWSER_CLOUD_SNAPSHOT_KEY`
- `CLOAKBROWSER_CLOUD_MAX_SNAPSHOT_MB` (default 1024 MiB)
- `CLOAKBROWSER_CLOUD_ORG_SNAPSHOT_QUOTA_MB` (default 102400 MiB)
- `CLOAKBROWSER_CLOUD_MAX_EXTENSION_MB` (default 100 MiB)
- `CLOAKBROWSER_CLOUD_ORG_EXTENSION_QUOTA_MB` (default 5120 MiB)
- `CLOAKBROWSER_CLOUD_LOG_LEVEL`
- `CLOAKBROWSER_CLOUD_URL` and `CLOAKBROWSER_AGENT_TOKEN` for Agents

## Key Files

- `cloakbrowser/cloud/app.py`: API routes, authorization, audit, and workflows
- `cloakbrowser/cloud/models.py`: SQLAlchemy models
- `cloakbrowser/cloud/schemas.py`: request validation and normalization
- `cloakbrowser/cloud/permissions.py`: role permission matrix
- `cloakbrowser/cloud/security.py`: sessions, CSRF, and credential helpers
- `cloakbrowser/cloud/snapshot_crypto.py`: encrypted profile archives
- `cloakbrowser/cloud/secrets_crypto.py`: environment-secret envelopes
- `cloakbrowser/cloud/extension_packages.py`: extension validation/extraction
- `cloakbrowser/cloud/agent_runtime.py`: task, lease, snapshot, secret, and
  extension execution logic
- `cloakbrowser/cloud/ui/`: team console frontend
- `tests/test_cloud.py`: security, concurrency, storage, runtime, and UI coverage

## Verification Record

- Cloud-focused suite: 36 passed.
- Full non-slow repository suite: 751 passed, 1 skipped, 40 deselected.
- Python compile, JavaScript syntax, and `git diff --check` passed.
- Desktop and 390 px Playwright checks passed without page errors or body
  overflow.
- Real HTTP QA covered login, extension upload, proxy/extension environment
  creation, deliberate Revision conflict, Agent heartbeat, task claim, lease
  acquisition, runtime-asset fetch, safe extension unpack, launcher options,
  stop, and cleanup.
- QA scans found no proxy username or password in the cloud database, snapshot,
  or object directories.

## Production Work Still Open

- Add versioned database migrations before upgrading persistent production
  databases; preview currently initializes schema directly.
- Replace local snapshot/extension object directories with durable shared object
  storage before running multiple control-plane instances.
- Add production deployment manifests, backup/restore drills, metrics, alerts,
  and key-rotation procedures.
- Add email verification/invitations, password recovery, MFA or SSO, and session
  management for an Internet-facing product.
- Define whether `backup` and `shared` need different retention, ownership, or
  multi-user launch semantics; both currently use the same encrypted snapshot
  transport and exclusive runtime lease.
- Add quota visibility and usage reporting to the console.
- Add explicit Agent tasks/endpoints for proxy connectivity testing, proxy
  exit-IP locking, temporary browser fingerprint previews, and runtime
  fingerprint details. The control plane cannot report these accurately without
  executing them on the selected Agent.
- Add pagination/filtering before organizations accumulate large task and audit
  histories.
- Decide whether revoked Agent records need an administrative archive/purge
  workflow. They are retained now for auditability.
