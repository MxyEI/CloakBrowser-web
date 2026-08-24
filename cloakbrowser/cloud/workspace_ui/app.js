"use strict";

const dom = {
  loginShell: document.querySelector("#loginShell"),
  appShell: document.querySelector("#appShell"),
  loginEmail: document.querySelector("#loginEmail"),
  loginOrganization: document.querySelector("#loginOrganization"),
  loginButton: document.querySelector("#loginButton"),
  loginStatus: document.querySelector("#loginStatus"),
  loginCloud: document.querySelector("#loginCloud"),
  loginError: document.querySelector("#loginError"),
  organizationName: document.querySelector("#organizationName"),
  userName: document.querySelector("#userName"),
  connectionState: document.querySelector("#connectionState"),
  environmentSummary: document.querySelector("#environmentSummary"),
  environmentRows: document.querySelector("#environmentRows"),
  emptyState: document.querySelector("#emptyState"),
  appError: document.querySelector("#appError"),
  createDialog: document.querySelector("#createDialog"),
  createButton: document.querySelector("#createButton"),
  closeCreateButton: document.querySelector("#closeCreateButton"),
  cancelCreateButton: document.querySelector("#cancelCreateButton"),
  refreshButton: document.querySelector("#refreshButton"),
  logoutButton: document.querySelector("#logoutButton"),
};

const phaseLabels = {
  idle: "Ready",
  queued: "Queued",
  acquiring_lease: "Acquiring lease",
  downloading: "Downloading profile",
  verifying: "Verifying profile",
  restoring: "Restoring profile",
  fetching_assets: "Loading proxy and extensions",
  starting: "Starting browser",
  running: "Running",
  stop_queued: "Stop queued",
  stopping: "Closing browser",
  encrypting: "Encrypting profile",
  uploading: "Uploading profile",
  synced: "Synced",
  stopped: "Stopped",
  error: "Sync error",
};

let csrfToken = "";
let currentState = null;
let pollTimer = null;

function text(value) {
  return value == null ? "" : String(value);
}

function setHidden(element, hidden) {
  element.hidden = hidden;
}

function phaseClass(phase) {
  if (phase === "running") return "running";
  if (phase === "error") return "failed";
  if (["idle", "stopped", "synced"].includes(phase)) return "ready";
  return "working";
}

function buildCell(value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value;
  return cell;
}

function actionButton(label, action, environmentId, className = "quiet") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.environmentId = environmentId;
  return button;
}

function renderEnvironment(environment, states) {
  const row = document.createElement("tr");
  const config = environment.config || {};
  const runtime = states[environment.id] || {phase: "idle"};
  const phase = runtime.phase || "idle";

  const identity = document.createElement("td");
  const name = document.createElement("strong");
  name.textContent = text(environment.name);
  const meta = document.createElement("span");
  const tags = Array.isArray(environment.tags) ? environment.tags.join(", ") : "";
  meta.textContent = tags || (environment.storage_policy === "shared" ? "Shared" : "Backup");
  identity.append(name, meta);
  row.append(identity);

  const platform = config.fingerprint_platform || "Automatic";
  const brand = config.fingerprint_brand || "Browser";
  row.append(buildCell(`${platform} / ${brand} / ${text(config.fingerprint_seed)}`));
  row.append(buildCell(environment.proxy_configured ? environment.proxy_masked : "Direct"));

  const stateCell = document.createElement("td");
  const status = document.createElement("span");
  status.className = `status ${phaseClass(phase)}`;
  status.textContent = phaseLabels[phase] || phase;
  stateCell.append(status);
  if (runtime.snapshot_version != null) {
    const version = document.createElement("small");
    version.textContent = `Snapshot v${runtime.snapshot_version}`;
    stateCell.append(version);
  }
  if (runtime.error) {
    stateCell.title = text(runtime.error);
  }
  row.append(stateCell);

  const actions = document.createElement("td");
  actions.className = "row-actions";
  const active = ["queued", "acquiring_lease", "downloading", "verifying", "restoring", "fetching_assets", "starting", "running", "stop_queued", "stopping", "encrypting", "uploading"].includes(phase);
  if (active) {
    const stop = actionButton("Stop", "stop", environment.id, "danger-quiet");
    stop.disabled = !["running", "stop_queued"].includes(phase);
    actions.append(stop);
  } else {
    actions.append(actionButton("Start", "launch", environment.id, "primary compact"));
  }
  row.append(actions);
  return row;
}

function render(state) {
  currentState = state;
  setHidden(dom.loginShell, state.signed_in);
  setHidden(dom.appShell, !state.signed_in);
  document.querySelectorAll(".csrf-field").forEach((field) => {
    field.value = csrfToken;
  });

  if (!state.signed_in) {
    dom.loginEmail.value = dom.loginEmail.value || state.default_email || "";
    dom.loginOrganization.value = dom.loginOrganization.value || state.default_organization_id || "";
    dom.loginCloud.textContent = state.cloud_url || "";
    dom.loginButton.disabled = Boolean(state.restoring_session);
    setHidden(dom.loginStatus, !state.restoring_session);
    dom.loginError.textContent = state.last_error || "";
    setHidden(dom.loginError, !state.last_error);
    return;
  }

  dom.organizationName.textContent = text(state.organization && state.organization.name);
  dom.userName.textContent = text((state.user && (state.user.display_name || state.user.email)) || "");
  dom.connectionState.textContent = state.connection_message || "Connected";
  const environments = Array.isArray(state.environments) ? state.environments : [];
  const running = Object.values(state.environment_states || {}).filter((item) => item.phase === "running").length;
  dom.environmentSummary.textContent = `${environments.length} total / ${running} running`;
  dom.appError.textContent = state.last_error || "";
  setHidden(dom.appError, !state.last_error);
  dom.environmentRows.replaceChildren(...environments.map((environment) => renderEnvironment(environment, state.environment_states || {})));
  setHidden(dom.emptyState, environments.length !== 0);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: options.method ? {"Content-Type": "application/json", "X-Cloak-CSRF": csrfToken} : {},
    body: options.method ? JSON.stringify(options.body || {}) : undefined,
    cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}

async function loadState() {
  try {
    const result = await request("/api/state");
    render(result.state);
  } catch (error) {
    if (currentState && currentState.signed_in) {
      dom.appError.textContent = error.message;
      setHidden(dom.appError, false);
    }
  }
}

async function mutate(path) {
  try {
    await request(path, {method: "POST", body: {}});
    await loadState();
  } catch (error) {
    dom.appError.textContent = error.message;
    setHidden(dom.appError, false);
  }
}

dom.environmentRows.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  button.disabled = true;
  mutate(`/api/environments/${encodeURIComponent(button.dataset.environmentId)}/${button.dataset.action}`);
});

dom.createButton.addEventListener("click", () => dom.createDialog.showModal());
dom.closeCreateButton.addEventListener("click", () => dom.createDialog.close());
dom.cancelCreateButton.addEventListener("click", () => dom.createDialog.close());
dom.refreshButton.addEventListener("click", () => mutate("/api/refresh"));
dom.logoutButton.addEventListener("click", async () => {
  await mutate("/api/logout");
  render((await request("/api/state")).state);
});

async function boot() {
  const session = await request("/api/session");
  csrfToken = session.csrf_token;
  render(session.state);
  pollTimer = window.setInterval(() => {
    if (currentState && (currentState.signed_in || currentState.restoring_session)) {
      loadState();
    }
  }, 1200);
}

window.addEventListener("beforeunload", () => {
  if (pollTimer) window.clearInterval(pollTimer);
});

boot().catch((error) => {
  dom.loginShell.hidden = false;
  dom.loginError.textContent = error.message;
  dom.loginError.hidden = false;
});
