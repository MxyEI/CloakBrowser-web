"use strict";

const state = {
  csrf: "",
  session: null,
  view: "environments",
  environments: [],
  groups: [],
  members: [],
  platformUsers: [],
  extensions: [],
  agents: [],
  leases: [],
  tasks: [],
  snapshots: [],
  audit: [],
  editingEnvironment: null,
  launchingEnvironment: null,
  confirmAction: null,
  workspaceLoading: false,
};

const PLATFORM_ROLES = ["member", "viewer", "operator", "admin", "owner"];
const PLATFORM_ROLE_LABELS = {
  member: "普通用户",
  viewer: "Viewer",
  operator: "Operator",
  admin: "Admin",
  owner: "Owner",
};

const elements = {
  authShell: document.querySelector("#authShell"),
  appShell: document.querySelector("#appShell"),
  loginTab: document.querySelector("#loginTab"),
  registerTab: document.querySelector("#registerTab"),
  loginForm: document.querySelector("#loginForm"),
  registerForm: document.querySelector("#registerForm"),
  authError: document.querySelector("#authError"),
  organizationSelect: document.querySelector("#organizationSelect"),
  currentUser: document.querySelector("#currentUser"),
  createOrganizationButton: document.querySelector("#createOrganizationButton"),
  logoutButton: document.querySelector("#logoutButton"),
  environmentRows: document.querySelector("#environmentRows"),
  environmentEmpty: document.querySelector("#environmentEmpty"),
  environmentCount: document.querySelector("#environmentCount"),
  environmentSearch: document.querySelector("#environmentSearch"),
  environmentGroupFilter: document.querySelector("#environmentGroupFilter"),
  createEnvironmentButton: document.querySelector("#createEnvironmentButton"),
  groupRows: document.querySelector("#groupRows"),
  groupEmpty: document.querySelector("#groupEmpty"),
  createGroupButton: document.querySelector("#createGroupButton"),
  memberRows: document.querySelector("#memberRows"),
  addMemberButton: document.querySelector("#addMemberButton"),
  platformUserRows: document.querySelector("#platformUserRows"),
  platformUserEmpty: document.querySelector("#platformUserEmpty"),
  createPlatformUserButton: document.querySelector("#createPlatformUserButton"),
  extensionRows: document.querySelector("#extensionRows"),
  extensionEmpty: document.querySelector("#extensionEmpty"),
  createExtensionButton: document.querySelector("#createExtensionButton"),
  agentRows: document.querySelector("#agentRows"),
  agentEmpty: document.querySelector("#agentEmpty"),
  createAgentButton: document.querySelector("#createAgentButton"),
  taskRows: document.querySelector("#taskRows"),
  taskEmpty: document.querySelector("#taskEmpty"),
  refreshTasksButton: document.querySelector("#refreshTasksButton"),
  auditRows: document.querySelector("#auditRows"),
  auditEmpty: document.querySelector("#auditEmpty"),
  refreshAuditButton: document.querySelector("#refreshAuditButton"),
  environmentDialog: document.querySelector("#environmentDialog"),
  environmentForm: document.querySelector("#environmentForm"),
  environmentDialogTitle: document.querySelector("#environmentDialogTitle"),
  environmentId: document.querySelector("#environmentId"),
  environmentRevision: document.querySelector("#environmentRevision"),
  environmentName: document.querySelector("#environmentName"),
  environmentGroup: document.querySelector("#environmentGroup"),
  environmentStorage: document.querySelector("#environmentStorage"),
  storagePolicyNotice: document.querySelector("#storagePolicyNotice"),
  environmentTags: document.querySelector("#environmentTags"),
  environmentProxyScheme: document.querySelector("#environmentProxyScheme"),
  environmentProxy: document.querySelector("#environmentProxy"),
  toggleEnvironmentProxyButton: document.querySelector("#toggleEnvironmentProxyButton"),
  environmentCurrentProxy: document.querySelector("#environmentCurrentProxy"),
  environmentClearProxyField: document.querySelector("#environmentClearProxyField"),
  environmentClearProxy: document.querySelector("#environmentClearProxy"),
  environmentGeoip: document.querySelector("#environmentGeoip"),
  environmentExtensions: document.querySelector("#environmentExtensions"),
  environmentAssignmentsField: document.querySelector("#environmentAssignmentsField"),
  environmentAssignments: document.querySelector("#environmentAssignments"),
  environmentSeed: document.querySelector("#environmentSeed"),
  environmentStartupUrl: document.querySelector("#environmentStartupUrl"),
  environmentTimezone: document.querySelector("#environmentTimezone"),
  environmentLocation: document.querySelector("#environmentLocation"),
  environmentLocale: document.querySelector("#environmentLocale"),
  environmentAdvancedFingerprint: document.querySelector("#environmentAdvancedFingerprint"),
  environmentAdvancedSummary: document.querySelector("#environmentAdvancedSummary"),
  environmentFingerprintPlatform: document.querySelector("#environmentFingerprintPlatform"),
  environmentFingerprintBrand: document.querySelector("#environmentFingerprintBrand"),
  environmentFingerprintBrandVersion: document.querySelector("#environmentFingerprintBrandVersion"),
  environmentFingerprintPlatformVersion: document.querySelector("#environmentFingerprintPlatformVersion"),
  environmentHardwareConcurrency: document.querySelector("#environmentHardwareConcurrency"),
  environmentDeviceMemory: document.querySelector("#environmentDeviceMemory"),
  environmentScreenSize: document.querySelector("#environmentScreenSize"),
  environmentTaskbarHeight: document.querySelector("#environmentTaskbarHeight"),
  environmentGpuVendor: document.querySelector("#environmentGpuVendor"),
  environmentGpuRenderer: document.querySelector("#environmentGpuRenderer"),
  environmentFingerprintNoise: document.querySelector("#environmentFingerprintNoise"),
  environmentAllowThirdPartyCookies: document.querySelector("#environmentAllowThirdPartyCookies"),
  environmentStorageQuota: document.querySelector("#environmentStorageQuota"),
  environmentHeadless: document.querySelector("#environmentHeadless"),
  environmentHumanize: document.querySelector("#environmentHumanize"),
  environmentConsistencyWarning: document.querySelector("#environmentConsistencyWarning"),
  environmentError: document.querySelector("#environmentError"),
  extensionDialog: document.querySelector("#extensionDialog"),
  extensionForm: document.querySelector("#extensionForm"),
  extensionName: document.querySelector("#extensionName"),
  extensionVersion: document.querySelector("#extensionVersion"),
  extensionFile: document.querySelector("#extensionFile"),
  extensionError: document.querySelector("#extensionError"),
  groupDialog: document.querySelector("#groupDialog"),
  groupForm: document.querySelector("#groupForm"),
  groupName: document.querySelector("#groupName"),
  groupDescription: document.querySelector("#groupDescription"),
  groupError: document.querySelector("#groupError"),
  memberDialog: document.querySelector("#memberDialog"),
  memberForm: document.querySelector("#memberForm"),
  memberEmail: document.querySelector("#memberEmail"),
  memberRole: document.querySelector("#memberRole"),
  memberError: document.querySelector("#memberError"),
  platformUserDialog: document.querySelector("#platformUserDialog"),
  platformUserForm: document.querySelector("#platformUserForm"),
  platformUserName: document.querySelector("#platformUserName"),
  platformUserEmail: document.querySelector("#platformUserEmail"),
  platformUserPassword: document.querySelector("#platformUserPassword"),
  platformUserError: document.querySelector("#platformUserError"),
  platformPasswordDialog: document.querySelector("#platformPasswordDialog"),
  platformPasswordForm: document.querySelector("#platformPasswordForm"),
  platformPasswordTitle: document.querySelector("#platformPasswordTitle"),
  platformPasswordUserId: document.querySelector("#platformPasswordUserId"),
  platformPasswordValue: document.querySelector("#platformPasswordValue"),
  platformPasswordError: document.querySelector("#platformPasswordError"),
  platformMembershipDialog: document.querySelector("#platformMembershipDialog"),
  platformMembershipForm: document.querySelector("#platformMembershipForm"),
  platformMembershipTitle: document.querySelector("#platformMembershipTitle"),
  platformMembershipUserId: document.querySelector("#platformMembershipUserId"),
  platformMembershipRows: document.querySelector("#platformMembershipRows"),
  platformMembershipOrganization: document.querySelector("#platformMembershipOrganization"),
  platformMembershipRole: document.querySelector("#platformMembershipRole"),
  platformMembershipError: document.querySelector("#platformMembershipError"),
  addPlatformMembershipButton: document.querySelector("#addPlatformMembershipButton"),
  organizationDialog: document.querySelector("#organizationDialog"),
  organizationForm: document.querySelector("#organizationForm"),
  organizationName: document.querySelector("#organizationName"),
  organizationError: document.querySelector("#organizationError"),
  agentDialog: document.querySelector("#agentDialog"),
  agentForm: document.querySelector("#agentForm"),
  agentName: document.querySelector("#agentName"),
  agentError: document.querySelector("#agentError"),
  launchDialog: document.querySelector("#launchDialog"),
  launchForm: document.querySelector("#launchForm"),
  launchDialogTitle: document.querySelector("#launchDialogTitle"),
  launchAgent: document.querySelector("#launchAgent"),
  launchError: document.querySelector("#launchError"),
  agentTokenDialog: document.querySelector("#agentTokenDialog"),
  agentTokenValue: document.querySelector("#agentTokenValue"),
  copyAgentTokenButton: document.querySelector("#copyAgentTokenButton"),
  confirmDialog: document.querySelector("#confirmDialog"),
  confirmTitle: document.querySelector("#confirmTitle"),
  confirmMessage: document.querySelector("#confirmMessage"),
  toastRegion: document.querySelector("#toastRegion"),
};

function textElement(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value == null ? "-" : String(value);
  return node;
}

function button(label, onClick, className = "") {
  const node = textElement("button", className, label);
  node.type = "button";
  node.addEventListener("click", onClick);
  return node;
}

function randomSeed() {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return 10_000 + (values[0] % 90_000);
}

function formatTime(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function setError(element, message = "") {
  element.textContent = message;
  element.hidden = !message;
}

function updateStoragePolicyNotice() {
  elements.storagePolicyNotice.hidden = elements.environmentStorage.value === "local";
}

function showToast(message, type = "") {
  const toast = textElement("div", `toast ${type}`.trim(), message);
  elements.toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

async function api(path, options = {}) {
  const request = { credentials: "same-origin", ...options };
  request.headers = { ...(options.headers || {}) };
  const structuredBody = request.body
    && typeof request.body !== "string"
    && !(request.body instanceof Blob)
    && !(request.body instanceof FormData)
    && !(request.body instanceof ArrayBuffer)
    && !ArrayBuffer.isView(request.body);
  if (structuredBody) {
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(request.body);
  }
  if (request.method && request.method !== "GET" && state.csrf) {
    request.headers["X-CSRF-Token"] = state.csrf;
  }
  const response = await fetch(path, request);
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(payload.detail)
      ? payload.detail.map((item) => item.msg).join("；")
      : payload.detail;
    const error = new Error(detail || `请求失败 (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function hasPermission(permission) {
  return Boolean(state.session?.permissions?.includes(permission));
}

function switchAuth(mode) {
  const login = mode === "login";
  elements.loginForm.hidden = !login;
  elements.registerForm.hidden = login;
  elements.loginTab.setAttribute("aria-selected", String(login));
  elements.registerTab.setAttribute("aria-selected", String(!login));
  setError(elements.authError);
}

function showAuth() {
  state.session = null;
  state.csrf = "";
  elements.appShell.hidden = true;
  elements.authShell.hidden = false;
  switchAuth("login");
}

function showApplication(session) {
  state.session = session;
  state.csrf = session.csrf_token;
  elements.authShell.hidden = true;
  elements.appShell.hidden = false;
  const accessLabel = session.is_superadmin ? "平台超管" : session.organization.role;
  elements.currentUser.textContent = `${session.user.display_name} · ${accessLabel}`;
  elements.organizationSelect.replaceChildren(
    ...session.organizations.map((organization) => {
      const suffix = organization.platform_access ? " · 平台访问" : "";
      const option = new Option(`${organization.name}${suffix}`, organization.id);
      option.selected = organization.id === session.organization.id;
      return option;
    }),
  );
  elements.createEnvironmentButton.hidden = !hasPermission("environments.create");
  elements.createGroupButton.hidden = !hasPermission("groups.manage");
  elements.addMemberButton.hidden = !hasPermission("members.manage");
  elements.createExtensionButton.hidden = !hasPermission("extensions.manage");
  elements.createAgentButton.hidden = !hasPermission("agents.manage");
  document.querySelector('[data-view="agents"]').hidden = !hasPermission("agents.read");
  document.querySelector('[data-view="tasks"]').hidden = !hasPermission("tasks.read");
  document.querySelector('[data-view="audit"]').hidden = !hasPermission("audit.read");
  document.querySelector('[data-view="platformUsers"]').hidden = !session.is_superadmin;
  if (!session.is_superadmin && state.view === "platformUsers") setView("environments");
}

async function refreshSession() {
  const session = await api("/api/session");
  showApplication(session);
  await loadWorkspace();
}

async function loadWorkspace() {
  if (state.workspaceLoading) return;
  state.workspaceLoading = true;
  try {
    const [groups, environments, members, extensions, agents, leases, tasks, snapshots, platformUsers] = await Promise.all([
      api("/api/groups"),
      api("/api/environments"),
      api("/api/members"),
      api("/api/extensions"),
      api("/api/agents"),
      api("/api/leases"),
      api("/api/tasks"),
      api("/api/snapshots"),
      state.session.is_superadmin ? api("/api/platform/users") : Promise.resolve({ users: [] }),
    ]);
    state.groups = groups.groups;
    state.environments = environments.environments;
    state.members = members.members;
    state.extensions = extensions.extensions;
    state.agents = agents.agents;
    state.leases = leases.leases;
    state.tasks = tasks.tasks;
    state.snapshots = snapshots.snapshots;
    state.platformUsers = platformUsers.users;
    renderGroups();
    renderEnvironments();
    renderMembers();
    renderPlatformUsers();
    renderExtensions();
    renderAgents();
    renderTasks();
    if (state.view === "audit" && hasPermission("audit.read")) await loadAudit();
  } finally {
    state.workspaceLoading = false;
  }
}

function setView(view) {
  if (view === "audit" && !hasPermission("audit.read")) view = "environments";
  if (view === "tasks" && !hasPermission("tasks.read")) view = "environments";
  if (view === "platformUsers" && !state.session?.is_superadmin) view = "environments";
  state.view = view;
  document.querySelectorAll(".view").forEach((section) => {
    section.hidden = section.id !== `${view}View`;
  });
  document.querySelectorAll(".workspace-tabs button").forEach((tab) => {
    if (tab.dataset.view === view) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  });
  if (view === "audit") loadAudit().catch((error) => showToast(error.message, "error"));
}

function groupOptions(selected = "", includeAll = false) {
  const options = [];
  options.push(new Option(includeAll ? "全部分组" : "未分组", ""));
  for (const group of state.groups) options.push(new Option(group.name, group.id));
  for (const option of options) option.selected = option.value === selected;
  return options;
}

function tagNodes(tags) {
  const list = document.createElement("div");
  list.className = "tag-list";
  list.replaceChildren(...tags.map((tag) => textElement("span", "tag", tag)));
  return list;
}

function renderEnvironments() {
  const query = elements.environmentSearch.value.trim().toLowerCase();
  const groupId = elements.environmentGroupFilter.value;
  const filtered = state.environments.filter((environment) => {
    const text = `${environment.name} ${(environment.tags || []).join(" ")}`.toLowerCase();
    return (!query || text.includes(query)) && (!groupId || environment.group_id === groupId);
  });
  const storageLabels = { local: "仅本地", backup: "云端备份", shared: "团队共享" };
  const leasesByEnvironment = new Map(
    state.leases.map((lease) => [lease.environment_id, lease]),
  );
  const tasksByEnvironment = new Map(
    state.tasks
      .filter((task) => task.status === "pending" || task.status === "claimed")
      .map((task) => [task.environment_id, task]),
  );
  const snapshotsByEnvironment = new Map(
    state.snapshots.map((snapshot) => [snapshot.environment_id, snapshot]),
  );
  const rows = filtered.map((environment) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const primary = document.createElement("div");
    primary.className = "cell-primary";
    primary.append(textElement("strong", "", environment.name));
    if (environment.tags?.length) primary.append(tagNodes(environment.tags));
    const assets = [];
    if (environment.proxy_configured) assets.push(`代理 ${environment.proxy_masked}`);
    if (environment.extension_ids?.length) assets.push(`${environment.extension_ids.length} 个扩展`);
    if (environment.assigned_users?.length) {
      assets.push(`分配 ${environment.assigned_users.map((user) => user.display_name).join("、")}`);
    }
    if (assets.length) primary.append(textElement("span", "environment-assets", assets.join(" · ")));
    nameCell.append(primary);
    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const lease = leasesByEnvironment.get(environment.id);
    const activeTask = tasksByEnvironment.get(environment.id);
    const snapshot = snapshotsByEnvironment.get(environment.id);
    if (hasPermission("environments.launch")) {
      if (activeTask) {
        const pending = button(activeTask.kind === "launch" ? "启动中" : "停止中", () => {});
        pending.disabled = true;
        actions.append(pending);
      } else if (lease) {
        actions.append(button("停止", () => confirmEnvironmentStop(environment, lease)));
      } else {
        actions.append(button("启动", () => openLaunchDialog(environment)));
      }
    }
    if (hasPermission("environments.edit")) {
      actions.append(button("编辑", () => openEnvironmentDialog(environment)));
    }
    if (snapshot && !lease && !activeTask && hasPermission("snapshots.manage")) {
      actions.append(
        button("删除云端数据", () => confirmSnapshotDelete(environment, snapshot), "danger-text"),
      );
    }
    if (hasPermission("environments.delete")) {
      actions.append(button("删除", () => confirmEnvironmentDelete(environment), "danger-text"));
    }
    actionCell.append(actions);
    const leaseCell = document.createElement("td");
    const statusClass = activeTask
      ? "status-pending"
      : (lease ? "status-online" : "status-idle");
    const statusText = activeTask
      ? (activeTask.kind === "launch" ? "正在启动" : "正在停止")
      : (lease ? `${lease.agent_name} · #${lease.fencing_token}` : "空闲");
    leaseCell.append(textElement(
      "span",
      `status-label ${statusClass}`,
      statusText,
    ));
    const storageCell = document.createElement("td");
    const storage = document.createElement("div");
    storage.className = "cell-primary";
    if (environment.storage_policy === "local") {
      storage.append(textElement("span", "status-label status-idle", storageLabels.local));
    } else if (snapshot) {
      storage.append(textElement(
        "span",
        "status-label status-succeeded",
        `${storageLabels[environment.storage_policy]} v${snapshot.version}`,
      ));
      const source = snapshot.uploaded_by_agent_name
        ? `${formatBytes(snapshot.ciphertext_size)} · ${snapshot.uploaded_by_agent_name}`
        : formatBytes(snapshot.ciphertext_size);
      storage.append(textElement("span", "", source));
    } else {
      storage.append(textElement("span", "status-label status-pending", "等待首次同步"));
    }
    storageCell.append(storage);
    const cells = [
      nameCell,
      textElement("td", "", environment.group_name || "未分组"),
      storageCell,
      leaseCell,
      textElement("td", "", environment.revision),
      textElement("td", "", formatTime(environment.updated_at)),
      actionCell,
    ];
    ["环境", "分组", "存储", "运行状态", "Revision", "更新时间", "操作"].forEach(
      (label, index) => { cells[index].dataset.label = label; },
    );
    row.append(...cells);
    return row;
  });
  elements.environmentRows.replaceChildren(...rows);
  elements.environmentEmpty.hidden = rows.length > 0;
  elements.environmentCount.textContent = `${filtered.length} / ${state.environments.length}`;
  const currentFilter = elements.environmentGroupFilter.value;
  elements.environmentGroupFilter.replaceChildren(...groupOptions(currentFilter, true));
}

function renderGroups() {
  const counts = new Map();
  for (const environment of state.environments) {
    if (environment.group_id) counts.set(environment.group_id, (counts.get(environment.group_id) || 0) + 1);
  }
  const rows = state.groups.map((group) => {
    const row = document.createElement("tr");
    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (hasPermission("groups.manage")) {
      actions.append(button("删除", () => confirmGroupDelete(group), "danger-text"));
    }
    actionCell.append(actions);
    row.append(
      textElement("td", "", group.name),
      textElement("td", "", group.description || "-"),
      textElement("td", "", counts.get(group.id) || 0),
      textElement("td", "", formatTime(group.updated_at)),
      actionCell,
    );
    return row;
  });
  elements.groupRows.replaceChildren(...rows);
  elements.groupEmpty.hidden = rows.length > 0;
}

function renderMembers() {
  const canManage = hasPermission("members.manage");
  const currentRole = state.session.organization.role;
  const rows = state.members.map((member) => {
    const row = document.createElement("tr");
    const roleCell = document.createElement("td");
    if (canManage && (currentRole === "owner" || member.role !== "owner")) {
      const select = document.createElement("select");
      select.setAttribute("aria-label", `设置 ${member.user.display_name} 的角色`);
      const roles = currentRole === "owner"
        ? ["member", "viewer", "operator", "admin", "owner"]
        : ["member", "viewer", "operator", "admin"];
      select.replaceChildren(...roles.map((role) => new Option(role, role, false, role === member.role)));
      select.addEventListener("change", () => updateMemberRole(member, select.value));
      roleCell.append(select);
    } else {
      roleCell.textContent = member.role;
    }
    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (canManage && (currentRole === "owner" || member.role !== "owner")) {
      actions.append(button("移除", () => confirmMemberRemove(member), "danger-text"));
    }
    actionCell.append(actions);
    row.append(
      textElement("td", "", member.user.display_name),
      textElement("td", "", member.user.email),
      roleCell,
      textElement("td", "", formatTime(member.created_at)),
      actionCell,
    );
    return row;
  });
  elements.memberRows.replaceChildren(...rows);
}

function renderPlatformUsers() {
  const rows = state.platformUsers.map((user) => {
    const row = document.createElement("tr");
    const identityCell = document.createElement("td");
    const identity = document.createElement("div");
    identity.className = "cell-primary";
    identity.append(
      textElement("strong", "", user.display_name),
      textElement("span", "", `${user.email}${user.is_superadmin ? " · 平台超管" : ""}`),
    );
    identityCell.append(identity);

    const statusCell = document.createElement("td");
    statusCell.append(textElement(
      "span",
      `status-label status-${user.is_active ? "online" : "revoked"}`,
      user.is_active ? "已启用" : "已停用",
    ));

    const organizations = user.memberships.length
      ? user.memberships.map((membership) => `${membership.organization_name} (${membership.role})`).join("、")
      : "未分配";
    const deviceCell = document.createElement("td");
    const devices = document.createElement("div");
    devices.className = "cell-primary";
    devices.append(
      textElement("strong", "", `${user.active_device_count} 台可用`),
      textElement("span", "", `累计 ${user.device_count} 台`),
    );
    deviceCell.append(devices);

    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    actions.append(button("团队权限", () => openPlatformMembershipDialog(user)));
    actions.append(button("重置密码", () => openPlatformPasswordDialog(user)));
    const statusButton = button(
      user.is_active ? "停用" : "启用",
      () => confirmPlatformUserStatus(user),
      user.is_active ? "danger-text" : "",
    );
    if (user.is_active && (user.id === state.session.user.id || user.is_superadmin)) {
      statusButton.disabled = true;
      statusButton.title = user.id === state.session.user.id
        ? "不能停用当前登录账号"
        : "配置中的平台超管不能停用";
    }
    actions.append(statusButton);
    actionCell.append(actions);
    row.append(
      identityCell,
      statusCell,
      textElement("td", "", organizations),
      deviceCell,
      textElement("td", "", formatTime(user.created_at)),
      actionCell,
    );
    return row;
  });
  elements.platformUserRows.replaceChildren(...rows);
  elements.platformUserEmpty.hidden = rows.length > 0;
  if (elements.platformMembershipDialog.open) renderPlatformMembershipDialog();
}

function renderExtensions() {
  const statusLabels = { pending: "等待上传", ready: "可用" };
  const rows = state.extensions.map((extension) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const name = document.createElement("div");
    name.className = "cell-primary";
    name.append(textElement("strong", "", extension.name));
    const manifestName = extension.manifest?.name;
    if (manifestName && manifestName !== extension.name) {
      name.append(textElement("span", "", manifestName));
    }
    nameCell.append(name);
    const statusCell = document.createElement("td");
    statusCell.append(textElement(
      "span",
      `status-label status-${extension.status === "ready" ? "succeeded" : "pending"}`,
      statusLabels[extension.status] || extension.status,
    ));

    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (hasPermission("extensions.manage")) {
      const remove = button("删除", () => confirmExtensionDelete(extension), "danger-text");
      if (extension.assigned_environments > 0) {
        remove.disabled = true;
        remove.title = "请先从所有环境中移除此扩展";
      }
      actions.append(remove);
    }
    actionCell.append(actions);
    row.append(
      nameCell,
      textElement("td", "", extension.version),
      statusCell,
      textElement("td", "", formatBytes(extension.content_size)),
      textElement("td", "", extension.assigned_environments),
      textElement("td", "", formatTime(extension.created_at)),
      actionCell,
    );
    return row;
  });
  elements.extensionRows.replaceChildren(...rows);
  elements.extensionEmpty.hidden = rows.length > 0;
}

function renderAgents() {
  const canManage = hasPermission("agents.manage");
  const statusLabels = { online: "在线", offline: "离线", revoked: "已撤销" };
  const rows = state.agents.map((agent) => {
    const row = document.createElement("tr");
    const hostCell = document.createElement("td");
    const host = document.createElement("div");
    host.className = "cell-primary";
    host.append(textElement("strong", "", agent.hostname || "尚未连接"));
    if (agent.platform) host.append(textElement("span", "", agent.platform));
    hostCell.append(host);

    const statusCell = document.createElement("td");
    statusCell.append(textElement(
      "span",
      `status-label status-${agent.status}`,
      statusLabels[agent.status] || agent.status,
    ));

    const portable = agent.capabilities?.profile_key_portable;
    const portabilityCell = document.createElement("td");
    portabilityCell.append(textElement(
      "span",
      `status-label status-${portable === true ? "succeeded" : "pending"}`,
      portable === true ? "可迁移" : portable === false ? "本机绑定" : "未知",
    ));

    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    if (canManage && agent.status !== "revoked") {
      actions.append(
        button("轮换密钥", () => confirmAgentTokenRotation(agent)),
        button("撤销", () => confirmAgentRevoke(agent), "danger-text"),
      );
    }
    actionCell.append(actions);
    row.append(
      textElement("td", "", agent.name),
      statusCell,
      hostCell,
      textElement("td", "", agent.version || "-"),
      portabilityCell,
      textElement("td", "", agent.active_leases),
      textElement("td", "", formatTime(agent.last_seen_at)),
      actionCell,
    );
    return row;
  });
  elements.agentRows.replaceChildren(...rows);
  elements.agentEmpty.hidden = rows.length > 0;
}

function renderTasks() {
  const kindLabels = { launch: "启动", stop: "停止" };
  const statusLabels = {
    pending: "等待领取",
    claimed: "执行中",
    succeeded: "成功",
    failed: "失败",
  };
  const rows = state.tasks.map((task) => {
    const row = document.createElement("tr");
    const taskCell = document.createElement("td");
    const taskInfo = document.createElement("div");
    taskInfo.className = "cell-primary";
    taskInfo.append(textElement("strong", "", kindLabels[task.kind] || task.kind));
    if (task.error) taskInfo.append(textElement("span", "task-error", task.error));
    taskCell.append(taskInfo);
    const statusCell = document.createElement("td");
    statusCell.append(textElement(
      "span",
      `status-label status-${task.status}`,
      statusLabels[task.status] || task.status,
    ));
    row.append(
      taskCell,
      textElement("td", "", task.environment_name),
      textElement("td", "", task.agent_name),
      statusCell,
      textElement("td", "", formatTime(task.created_at)),
      textElement("td", "", formatTime(task.completed_at)),
    );
    return row;
  });
  elements.taskRows.replaceChildren(...rows);
  elements.taskEmpty.hidden = rows.length > 0;
}

async function loadAudit() {
  if (!hasPermission("audit.read")) return;
  const result = await api("/api/audit");
  state.audit = result.entries;
  const names = new Map(state.members.map((member) => [member.user.id, member.user.display_name]));
  const rows = state.audit.map((entry) => {
    const row = document.createElement("tr");
    row.append(
      textElement("td", "", formatTime(entry.created_at)),
      textElement("td", "", entry.action),
      textElement("td", "", `${entry.target_type} · ${entry.target_id.slice(0, 8)}`),
      textElement("td", "", names.get(entry.actor_id) || entry.actor_id.slice(0, 8)),
    );
    return row;
  });
  elements.auditRows.replaceChildren(...rows);
  elements.auditEmpty.hidden = rows.length > 0;
}

function setSelectValue(select, value) {
  if (value && ![...select.options].some((option) => option.value === value)) {
    select.append(new Option(value, value));
  }
  select.value = value || "";
}

function renderEnvironmentExtensions(selectedIds = []) {
  const selected = new Set(selectedIds);
  const packages = state.extensions.filter((extension) => extension.status === "ready");
  if (packages.length === 0) {
    elements.environmentExtensions.replaceChildren(
      textElement("p", "extension-picker-empty", "暂无可用扩展包"),
    );
    return;
  }
  const choices = packages.map((extension) => {
    const label = document.createElement("label");
    label.className = "extension-choice";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = extension.id;
    input.checked = selected.has(extension.id);
    const details = document.createElement("span");
    details.append(
      textElement("strong", "", extension.name),
      textElement("small", "", `${extension.version} · ${formatBytes(extension.content_size)}`),
    );
    label.append(input, details);
    return label;
  });
  elements.environmentExtensions.replaceChildren(...choices);
}

function selectedExtensionIds() {
  return [...elements.environmentExtensions.querySelectorAll('input[type="checkbox"]:checked')]
    .map((input) => input.value);
}

function renderEnvironmentAssignments(selectedIds = []) {
  const canManage = hasPermission("assignments.manage");
  elements.environmentAssignmentsField.hidden = !canManage;
  if (!canManage) return;
  const selected = new Set(selectedIds);
  const members = state.members.filter((member) => member.role === "member");
  if (members.length === 0) {
    elements.environmentAssignments.replaceChildren(
      textElement("p", "extension-picker-empty", "暂无普通用户，请先在团队中添加 member"),
    );
    return;
  }
  elements.environmentAssignments.replaceChildren(...members.map((member) => {
    const label = document.createElement("label");
    label.className = "extension-choice";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = member.id;
    input.checked = selected.has(member.id);
    const details = document.createElement("span");
    details.append(
      textElement("strong", "", member.user.display_name),
      textElement("small", "", member.user.email),
    );
    label.append(input, details);
    return label;
  }));
}

function selectedAssignmentIds() {
  return [...elements.environmentAssignments.querySelectorAll('input[type="checkbox"]:checked')]
    .map((input) => input.value);
}

function environmentProxyValue() {
  const value = elements.environmentProxy.value.trim();
  if (!value || value.includes("://")) return value;
  return `${elements.environmentProxyScheme.value}://${value}`;
}

function updateProxyControls() {
  const clearing = elements.environmentClearProxy.checked;
  elements.environmentProxy.disabled = clearing;
  elements.environmentProxyScheme.disabled = clearing;
  if (clearing) {
    elements.environmentProxy.value = "";
  }
  const hasProxy = !clearing && Boolean(
    elements.environmentProxy.value.trim() || state.editingEnvironment?.proxy_configured,
  );
  elements.environmentGeoip.disabled = !hasProxy;
  if (!hasProxy) elements.environmentGeoip.checked = false;
  updateEnvironmentConsistencyWarnings();
}

function setEnvironmentScreenSize(width, height) {
  elements.environmentScreenSize.querySelector("option[data-custom-screen]")?.remove();
  const value = width && height ? `${width}x${height}` : "";
  if (value && ![...elements.environmentScreenSize.options].some((option) => option.value === value)) {
    const option = new Option(`${width} × ${height}`, value);
    option.dataset.customScreen = "true";
    elements.environmentScreenSize.append(option);
  }
  elements.environmentScreenSize.value = value;
}

function environmentScreenDimensions() {
  const match = /^(\d+)x(\d+)$/.exec(elements.environmentScreenSize.value);
  return match
    ? { screen_width: Number(match[1]), screen_height: Number(match[2]) }
    : { screen_width: 0, screen_height: 0 };
}

function environmentAdvancedPayload() {
  return {
    fingerprint_platform: elements.environmentFingerprintPlatform.value,
    fingerprint_brand: elements.environmentFingerprintBrand.value,
    fingerprint_brand_version: elements.environmentFingerprintBrandVersion.value.trim(),
    fingerprint_platform_version: elements.environmentFingerprintPlatformVersion.value.trim(),
    hardware_concurrency: Number(elements.environmentHardwareConcurrency.value),
    device_memory_gb: Number(elements.environmentDeviceMemory.value),
    ...environmentScreenDimensions(),
    gpu_vendor: elements.environmentGpuVendor.value.trim(),
    gpu_renderer: elements.environmentGpuRenderer.value.trim(),
    taskbar_height: Number(elements.environmentTaskbarHeight.value),
    fingerprint_noise: elements.environmentFingerprintNoise.checked,
    allow_third_party_cookies: elements.environmentAllowThirdPartyCookies.checked,
  };
}

function environmentAdvancedOverrideCount(config) {
  return [
    config.fingerprint_platform,
    config.fingerprint_brand,
    config.fingerprint_brand_version,
    config.fingerprint_platform_version,
    config.hardware_concurrency,
    config.device_memory_gb,
    config.screen_width,
    config.gpu_vendor,
    config.taskbar_height >= 0,
    !config.fingerprint_noise,
    config.allow_third_party_cookies,
  ].filter(Boolean).length;
}

function gpuFamily(value) {
  if (/apple/i.test(value)) return "Apple";
  if (/nvidia|geforce|quadro/i.test(value)) return "NVIDIA";
  if (/\bamd\b|radeon|ati technologies/i.test(value)) return "AMD";
  if (/intel/i.test(value)) return "Intel";
  return "";
}

function updateEnvironmentConsistencyWarnings() {
  if (!elements.environmentConsistencyWarning) return;
  const config = {
    ...environmentAdvancedPayload(),
    timezone: elements.environmentTimezone.value,
    location: elements.environmentLocation.value,
    locale: elements.environmentLocale.value,
    geoip: elements.environmentGeoip.checked,
    storage_quota_mb: Number(elements.environmentStorageQuota.value || 0),
  };
  const warnings = [];
  const locationTimezone = elements.environmentLocation.selectedOptions[0]?.dataset.timezone || "";
  if (config.location && config.timezone && locationTimezone && config.timezone !== locationTimezone) {
    warnings.push(`所选城市对应 ${locationTimezone}，与当前时区 ${config.timezone} 不一致`);
  }
  if (config.geoip && (config.timezone || config.locale || config.location)) {
    warnings.push("GeoIP 自动匹配与手动地区设置同时启用，手动值会优先；请确认它们与代理出口一致");
  }
  const hasGpuOverride = Boolean(config.gpu_vendor || config.gpu_renderer);
  if (hasGpuOverride && (!config.gpu_vendor || !config.gpu_renderer)) {
    warnings.push("GPU Vendor 和 Renderer 必须同时设置");
  }
  if (config.fingerprint_platform === "windows" && /apple/i.test(config.gpu_vendor)) {
    warnings.push("Windows 平台不应搭配 Apple GPU");
  }
  const vendorFamily = gpuFamily(config.gpu_vendor);
  const rendererFamily = gpuFamily(config.gpu_renderer);
  if (vendorFamily && rendererFamily && vendorFamily !== rendererFamily) {
    warnings.push(`GPU Vendor 属于 ${vendorFamily}，Renderer 却属于 ${rendererFamily}`);
  }
  if (config.fingerprint_platform === "windows" && config.taskbar_height === 95) {
    warnings.push("Windows 身份使用了更常见于 macOS 的 95 px 任务栏高度");
  }
  if (config.fingerprint_platform === "macos" && [40, 48].includes(config.taskbar_height)) {
    warnings.push("macOS 身份使用了更常见于 Windows 的任务栏高度");
  }
  if (config.storage_quota_mb && config.storage_quota_mb < 1024) {
    warnings.push("存储配额低于 1 GB，部分站点可能将环境判断为隐私模式");
  }
  if (!config.fingerprint_noise) warnings.push("指纹噪声已关闭");
  if (config.allow_third_party_cookies) {
    warnings.push("第三方 Cookie 兼容开关需要 Chromium 148+");
  }
  elements.environmentConsistencyWarning.hidden = warnings.length === 0;
  elements.environmentConsistencyWarning.replaceChildren(
    textElement("strong", "", "配置一致性提醒"),
    textElement("span", "", warnings.join("；")),
  );
}

function updateEnvironmentAdvancedState() {
  const config = environmentAdvancedPayload();
  const count = environmentAdvancedOverrideCount(config);
  elements.environmentAdvancedSummary.textContent = count ? `手动覆盖 ${count} 项` : "Seed 自动生成";
  const hasGpuOverride = Boolean(config.gpu_vendor || config.gpu_renderer);
  elements.environmentGpuVendor.required = hasGpuOverride;
  elements.environmentGpuRenderer.required = hasGpuOverride;
  updateEnvironmentConsistencyWarnings();
}

function openEnvironmentDialog(environment = null) {
  state.editingEnvironment = environment;
  elements.environmentForm.reset();
  setError(elements.environmentError);
  elements.environmentDialogTitle.textContent = environment ? "编辑环境" : "新建环境";
  elements.environmentId.value = environment?.id || "";
  elements.environmentRevision.value = environment?.revision || "";
  elements.environmentName.value = environment?.name || "";
  elements.environmentGroup.replaceChildren(...groupOptions(environment?.group_id || ""));
  elements.environmentStorage.value = environment?.storage_policy || "shared";
  updateStoragePolicyNotice();
  elements.environmentTags.value = (environment?.tags || []).join(", ");
  elements.environmentProxy.value = "";
  elements.environmentProxy.type = "password";
  elements.toggleEnvironmentProxyButton.textContent = "显示";
  elements.environmentProxyScheme.value = environment?.proxy_masked?.split("://", 1)[0] || "http";
  elements.environmentCurrentProxy.textContent = environment?.proxy_configured
    ? `当前：${environment.proxy_masked}。留空表示不修改。`
    : "尚未配置代理";
  elements.environmentClearProxy.checked = false;
  elements.environmentClearProxyField.hidden = !environment?.proxy_configured;
  elements.environmentGeoip.checked = environment?.config?.geoip ?? false;
  updateProxyControls();
  renderEnvironmentExtensions(environment?.extension_ids || []);
  renderEnvironmentAssignments(environment?.assigned_membership_ids || []);
  elements.environmentSeed.value = environment?.config?.fingerprint_seed || randomSeed();
  elements.environmentStartupUrl.value = environment?.config?.startup_url === "about:blank" ? "" : (environment?.config?.startup_url || "");
  setSelectValue(elements.environmentTimezone, environment?.config?.timezone || "");
  elements.environmentLocation.value = environment?.config?.location || "";
  setSelectValue(elements.environmentLocale, environment?.config?.locale || "");
  elements.environmentFingerprintPlatform.value = environment?.config?.fingerprint_platform || "";
  elements.environmentFingerprintBrand.value = environment?.config?.fingerprint_brand || "";
  elements.environmentFingerprintBrandVersion.value = environment?.config?.fingerprint_brand_version || "";
  elements.environmentFingerprintPlatformVersion.value = environment?.config?.fingerprint_platform_version || "";
  elements.environmentHardwareConcurrency.value = String(environment?.config?.hardware_concurrency || 0);
  elements.environmentDeviceMemory.value = String(environment?.config?.device_memory_gb || 0);
  setEnvironmentScreenSize(
    environment?.config?.screen_width || 0,
    environment?.config?.screen_height || 0,
  );
  elements.environmentTaskbarHeight.value = String(environment?.config?.taskbar_height ?? -1);
  elements.environmentGpuVendor.value = environment?.config?.gpu_vendor || "";
  elements.environmentGpuRenderer.value = environment?.config?.gpu_renderer || "";
  elements.environmentFingerprintNoise.checked = environment?.config?.fingerprint_noise ?? true;
  elements.environmentAllowThirdPartyCookies.checked = environment?.config?.allow_third_party_cookies ?? false;
  elements.environmentStorageQuota.value = environment?.config?.storage_quota_mb || 5000;
  elements.environmentHeadless.checked = environment?.config?.headless ?? false;
  elements.environmentHumanize.checked = environment?.config?.humanize ?? false;
  updateEnvironmentAdvancedState();
  elements.environmentAdvancedFingerprint.open = environmentAdvancedOverrideCount(
    environmentAdvancedPayload(),
  ) > 0;
  elements.environmentDialog.showModal();
  elements.environmentName.focus();
}

async function saveEnvironment(event) {
  event.preventDefault();
  setError(elements.environmentError);
  const existing = state.editingEnvironment;
  const config = {
    ...(existing?.config || {}),
    fingerprint_seed: Number(elements.environmentSeed.value),
    startup_url: elements.environmentStartupUrl.value.trim() || "about:blank",
    timezone: elements.environmentTimezone.value,
    location: elements.environmentLocation.value,
    locale: elements.environmentLocale.value,
    geoip: elements.environmentGeoip.checked,
    storage_quota_mb: Number(elements.environmentStorageQuota.value),
    ...environmentAdvancedPayload(),
    headless: elements.environmentHeadless.checked,
    humanize: elements.environmentHumanize.checked,
  };
  const groupId = elements.environmentGroup.value || null;
  const common = {
    name: elements.environmentName.value.trim(),
    tags: elements.environmentTags.value.split(/[,，]/).map((tag) => tag.trim()).filter(Boolean),
    storage_policy: elements.environmentStorage.value,
    config,
    extension_ids: selectedExtensionIds(),
  };
  if (hasPermission("assignments.manage")) {
    common.assigned_membership_ids = selectedAssignmentIds();
  }
  const proxy = environmentProxyValue();
  const clearProxy = elements.environmentClearProxy.checked;
  const hasProxy = Boolean(proxy || (existing?.proxy_configured && !clearProxy));
  if (elements.environmentGeoip.checked && !hasProxy) {
    setError(elements.environmentError, "设置冲突：启用按代理匹配地区前，请先填写代理凭证。");
    return;
  }
  const submit = elements.environmentForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    if (existing) {
      const changes = {
        ...common,
        expected_revision: existing.revision,
        group_id: groupId,
        clear_group: !groupId,
        clear_proxy: clearProxy,
      };
      if (proxy) changes.proxy = proxy;
      await api(`/api/environments/${existing.id}`, {
        method: "PATCH",
        body: changes,
      });
    } else {
      const changes = { ...common, group_id: groupId };
      if (proxy) changes.proxy = proxy;
      await api("/api/environments", { method: "POST", body: changes });
    }
    elements.environmentDialog.close();
    showToast(existing ? "环境已更新" : "环境已创建");
    await loadWorkspace();
  } catch (error) {
    setError(elements.environmentError, environmentSaveError(error));
  } finally {
    submit.disabled = false;
  }
}

function environmentSaveError(error) {
  if (error.status !== 409) return error.message;
  if (error.message.includes("updated by another team member")) {
    return "保存冲突：该环境已被其他成员更新。请关闭窗口，重新打开后再修改。";
  }
  if (error.message.includes("remote task")) {
    return "设置冲突：该环境有正在执行的远程任务，请等待任务结束后再保存。";
  }
  if (error.message.includes("stop the environment")) {
    return "设置冲突：该环境正在运行，请先停止环境，再修改代理、扩展、存储或运行设置。";
  }
  if (error.message.includes("name already exists")) {
    return "名称冲突：团队中已存在同名环境。";
  }
  return `设置冲突：${error.message}`;
}

function openLaunchDialog(environment) {
  state.launchingEnvironment = environment;
  elements.launchForm.reset();
  setError(elements.launchError);
  elements.launchDialogTitle.textContent = `启动 ${environment.name}`;
  const agents = state.agents.filter(
    (agent) => (
      agent.status === "online"
      && agent.capabilities?.browser_launch
      && (environment.storage_policy === "local" || agent.capabilities?.snapshot_sync)
      && (!environment.proxy_configured || agent.capabilities?.secret_sync)
      && (!environment.extension_ids?.length || agent.capabilities?.extension_sync)
    ),
  );
  elements.launchAgent.replaceChildren(
    ...agents.map((agent) => {
      let portability = "";
      if (environment.storage_policy !== "local") {
        if (agent.capabilities?.profile_key_portable === true) portability = " · 登录态可迁移";
        else if (agent.capabilities?.profile_key_portable === false) portability = " · 登录态本机绑定";
        else portability = " · 登录态兼容未知";
      }
      return new Option(
        `${agent.name}${agent.hostname ? ` · ${agent.hostname}` : ""}${portability}`,
        agent.id,
      );
    }),
  );
  const submit = elements.launchForm.querySelector('button[type="submit"]');
  submit.disabled = agents.length === 0;
  if (agents.length === 0) {
    elements.launchAgent.append(new Option("没有可用的在线节点", ""));
    setError(elements.launchError, "没有同时支持此环境存储、代理凭证和扩展同步要求的在线节点");
  }
  elements.launchDialog.showModal();
  elements.launchAgent.focus();
}

async function requestEnvironmentLaunch(event) {
  event.preventDefault();
  const environment = state.launchingEnvironment;
  if (!environment) return;
  setError(elements.launchError);
  const submit = elements.launchForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await api(`/api/environments/${environment.id}/launch`, {
      method: "POST",
      body: {
        agent_id: elements.launchAgent.value,
        expected_revision: environment.revision,
      },
    });
    elements.launchDialog.close();
    showToast("启动任务已提交");
    await loadWorkspace();
  } catch (error) {
    setError(elements.launchError, error.message);
  } finally {
    submit.disabled = false;
  }
}

function openGroupDialog() {
  elements.groupForm.reset();
  setError(elements.groupError);
  elements.groupDialog.showModal();
  elements.groupName.focus();
}

function openExtensionDialog() {
  elements.extensionForm.reset();
  setError(elements.extensionError);
  elements.extensionDialog.showModal();
  elements.extensionName.focus();
}

async function sha256Hex(file) {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function saveExtension(event) {
  event.preventDefault();
  setError(elements.extensionError);
  const submit = elements.extensionForm.querySelector('button[type="submit"]');
  const file = elements.extensionFile.files[0];
  if (!file) return;
  submit.disabled = true;
  let extensionId = "";
  try {
    const contentSha256 = await sha256Hex(file);
    const created = await api("/api/extensions", {
      method: "POST",
      body: {
        name: elements.extensionName.value.trim(),
        version: elements.extensionVersion.value.trim(),
        content_sha256: contentSha256,
        content_size: file.size,
      },
    });
    extensionId = created.extension.id;
    await api(`/api/extensions/${extensionId}/content`, {
      method: "PUT",
      headers: { "Content-Type": "application/zip" },
      body: file,
    });
    elements.extensionDialog.close();
    showToast("扩展包已上传");
    await loadWorkspace();
  } catch (error) {
    if (extensionId) {
      try {
        await api(`/api/extensions/${extensionId}`, { method: "DELETE" });
      } catch (_cleanupError) {
        // The pending package remains visible and can be removed manually.
      }
    }
    setError(elements.extensionError, error.status === 409
      ? `上传冲突：${error.message}`
      : error.message);
    await loadWorkspace().catch(() => {});
  } finally {
    submit.disabled = false;
  }
}

async function saveGroup(event) {
  event.preventDefault();
  setError(elements.groupError);
  try {
    await api("/api/groups", {
      method: "POST",
      body: { name: elements.groupName.value, description: elements.groupDescription.value },
    });
    elements.groupDialog.close();
    showToast("分组已创建");
    await loadWorkspace();
  } catch (error) {
    setError(elements.groupError, error.message);
  }
}

function openMemberDialog() {
  elements.memberForm.reset();
  setError(elements.memberError);
  elements.memberRole.querySelector('option[value="owner"]').hidden = state.session.organization.role !== "owner";
  elements.memberDialog.showModal();
  elements.memberEmail.focus();
}

async function saveMember(event) {
  event.preventDefault();
  setError(elements.memberError);
  try {
    await api("/api/members", {
      method: "POST",
      body: { email: elements.memberEmail.value, role: elements.memberRole.value },
    });
    elements.memberDialog.close();
    showToast("成员已添加");
    await loadWorkspace();
  } catch (error) {
    setError(elements.memberError, error.message);
  }
}

function openPlatformUserDialog() {
  elements.platformUserForm.reset();
  setError(elements.platformUserError);
  elements.platformUserDialog.showModal();
  elements.platformUserName.focus();
}

async function savePlatformUser(event) {
  event.preventDefault();
  setError(elements.platformUserError);
  const submit = elements.platformUserForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await api("/api/platform/users", {
      method: "POST",
      body: {
        display_name: elements.platformUserName.value,
        email: elements.platformUserEmail.value,
        password: elements.platformUserPassword.value,
      },
    });
    elements.platformUserDialog.close();
    showToast("平台用户已创建");
    await loadWorkspace();
  } catch (error) {
    setError(elements.platformUserError, error.message);
  } finally {
    submit.disabled = false;
  }
}

function openPlatformPasswordDialog(user) {
  elements.platformPasswordForm.reset();
  elements.platformPasswordUserId.value = user.id;
  elements.platformPasswordTitle.textContent = `重置 ${user.display_name} 的密码`;
  setError(elements.platformPasswordError);
  elements.platformPasswordDialog.showModal();
  elements.platformPasswordValue.focus();
}

async function resetPlatformUserPassword(event) {
  event.preventDefault();
  setError(elements.platformPasswordError);
  const userId = elements.platformPasswordUserId.value;
  const submit = elements.platformPasswordForm.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    await api(`/api/platform/users/${userId}/password`, {
      method: "PATCH",
      body: { password: elements.platformPasswordValue.value },
    });
    elements.platformPasswordDialog.close();
    showToast("登录密码已重置");
    if (userId === state.session.user.id) showAuth();
    else await loadWorkspace();
  } catch (error) {
    setError(elements.platformPasswordError, error.message);
  } finally {
    submit.disabled = false;
  }
}

function openPlatformMembershipDialog(user) {
  elements.platformMembershipUserId.value = user.id;
  elements.platformMembershipTitle.textContent = `${user.display_name} 的团队权限`;
  elements.platformMembershipRole.value = "member";
  setError(elements.platformMembershipError);
  renderPlatformMembershipDialog();
  elements.platformMembershipDialog.showModal();
}

function renderPlatformMembershipDialog() {
  const user = state.platformUsers.find(
    (item) => item.id === elements.platformMembershipUserId.value,
  );
  if (!user) {
    if (elements.platformMembershipDialog.open) elements.platformMembershipDialog.close();
    return;
  }
  const rows = user.memberships.map((membership) => {
    const row = document.createElement("div");
    row.className = "platform-membership-row";
    const identity = document.createElement("div");
    identity.className = "cell-primary";
    identity.append(
      textElement("strong", "", membership.organization_name),
      textElement("span", "", `加入于 ${formatTime(membership.created_at)}`),
    );
    const role = document.createElement("select");
    role.setAttribute("aria-label", `设置 ${membership.organization_name} 的角色`);
    role.replaceChildren(...PLATFORM_ROLES.map((value) => new Option(
      PLATFORM_ROLE_LABELS[value],
      value,
      false,
      value === membership.role,
    )));
    role.addEventListener("change", () => updatePlatformMembership(user, membership, role));
    const remove = button("移除", () => confirmPlatformMembershipRemove(user, membership));
    if (
      user.id === state.session.user.id
      && membership.organization_id === state.session.organization.id
    ) {
      remove.disabled = true;
      remove.title = "不能移除当前账号在活动团队中的权限";
    }
    row.append(identity, role, remove);
    return row;
  });
  if (rows.length === 0) {
    rows.push(textElement("div", "platform-membership-empty", "尚未加入团队"));
  }
  elements.platformMembershipRows.replaceChildren(...rows);

  const joinedOrganizationIds = new Set(
    user.memberships.map((membership) => membership.organization_id),
  );
  const availableOrganizations = state.session.organizations.filter(
    (organization) => !joinedOrganizationIds.has(organization.id),
  );
  if (availableOrganizations.length) {
    elements.platformMembershipOrganization.replaceChildren(
      ...availableOrganizations.map(
        (organization) => new Option(organization.name, organization.id),
      ),
    );
    elements.platformMembershipOrganization.disabled = false;
    elements.addPlatformMembershipButton.disabled = false;
  } else {
    elements.platformMembershipOrganization.replaceChildren(
      new Option("已加入所有团队", ""),
    );
    elements.platformMembershipOrganization.disabled = true;
    elements.addPlatformMembershipButton.disabled = true;
  }
}

async function savePlatformMembership(event) {
  event.preventDefault();
  setError(elements.platformMembershipError);
  const userId = elements.platformMembershipUserId.value;
  elements.addPlatformMembershipButton.disabled = true;
  try {
    await api(`/api/platform/users/${userId}/memberships`, {
      method: "POST",
      body: {
        organization_id: elements.platformMembershipOrganization.value,
        role: elements.platformMembershipRole.value,
      },
    });
    showToast("团队权限已添加");
    await loadWorkspace();
  } catch (error) {
    setError(elements.platformMembershipError, error.message);
  } finally {
    if (elements.platformMembershipDialog.open) renderPlatformMembershipDialog();
  }
}

async function updatePlatformMembership(user, membership, select) {
  select.disabled = true;
  try {
    await api(`/api/platform/users/${user.id}/memberships/${membership.id}`, {
      method: "PATCH",
      body: { role: select.value },
    });
    showToast("团队角色已更新");
    await loadWorkspace();
  } catch (error) {
    showToast(error.message, "error");
    await loadWorkspace();
  }
}

function confirmPlatformMembershipRemove(user, membership) {
  askConfirmation(
    "移除团队权限",
    `从“${membership.organization_name}”移除 ${user.display_name}？`,
    async () => {
      await api(`/api/platform/users/${user.id}/memberships/${membership.id}`, {
        method: "DELETE",
      });
      showToast("团队权限已移除");
      await loadWorkspace();
    },
  );
}

function openAgentDialog() {
  elements.agentForm.reset();
  setError(elements.agentError);
  elements.agentDialog.showModal();
  elements.agentName.focus();
}

function showAgentToken(token) {
  elements.agentTokenValue.value = token;
  elements.agentTokenDialog.showModal();
  elements.agentTokenValue.select();
}

async function saveAgent(event) {
  event.preventDefault();
  setError(elements.agentError);
  try {
    const result = await api("/api/agents", {
      method: "POST",
      body: { name: elements.agentName.value },
    });
    elements.agentDialog.close();
    showAgentToken(result.agent_token);
    await loadWorkspace();
  } catch (error) {
    setError(elements.agentError, error.message);
  }
}

async function copyAgentToken() {
  const token = elements.agentTokenValue.value;
  try {
    await navigator.clipboard.writeText(token);
  } catch (_error) {
    elements.agentTokenValue.select();
    document.execCommand("copy");
  }
  showToast("节点密钥已复制");
}

async function updateMemberRole(member, role) {
  try {
    await api(`/api/members/${member.id}`, { method: "PATCH", body: { role } });
    showToast("成员角色已更新");
    await refreshSession();
  } catch (error) {
    showToast(error.message, "error");
    await loadWorkspace();
  }
}

function askConfirmation(title, message, action) {
  elements.confirmTitle.textContent = title;
  elements.confirmMessage.textContent = message;
  state.confirmAction = action;
  elements.confirmDialog.returnValue = "cancel";
  elements.confirmDialog.showModal();
}

function confirmPlatformUserStatus(user) {
  const enabling = !user.is_active;
  const action = enabling ? "启用" : "停用";
  askConfirmation(
    `${action}平台用户`,
    `${action} ${user.display_name}（${user.email}）？`,
    async () => {
      await api(`/api/platform/users/${user.id}/status`, {
        method: "PATCH",
        body: { is_active: enabling },
      });
      showToast(`平台用户已${action}`);
      await loadWorkspace();
    },
  );
}

function confirmEnvironmentDelete(environment) {
  askConfirmation("删除环境", `删除“${environment.name}”的云端配置？`, async () => {
    await api(`/api/environments/${environment.id}`, { method: "DELETE" });
    showToast("环境已删除");
    await loadWorkspace();
  });
}

function confirmEnvironmentStop(environment, lease) {
  askConfirmation(
    "停止环境",
    `停止“${environment.name}”在 ${lease.agent_name} 上的浏览器？`,
    async () => {
      await api(`/api/environments/${environment.id}/stop`, { method: "POST" });
      showToast("停止任务已提交");
      await loadWorkspace();
    },
  );
}

function confirmSnapshotDelete(environment, snapshot) {
  askConfirmation(
    "删除云端数据",
    `删除“${environment.name}”的加密云端快照 v${snapshot.version}？节点上的本地数据不会删除。`,
    async () => {
      await api(`/api/environments/${environment.id}/snapshot`, { method: "DELETE" });
      showToast("云端快照已删除");
      await loadWorkspace();
    },
  );
}

function confirmExtensionDelete(extension) {
  askConfirmation(
    "删除扩展包",
    `删除“${extension.name} ${extension.version}”？已缓存到节点的副本不会再被环境使用。`,
    async () => {
      await api(`/api/extensions/${extension.id}`, { method: "DELETE" });
      showToast("扩展包已删除");
      await loadWorkspace();
    },
  );
}

function confirmGroupDelete(group) {
  askConfirmation("删除分组", `删除“${group.name}”？该分组中的环境将变为未分组。`, async () => {
    await api(`/api/groups/${group.id}`, { method: "DELETE" });
    showToast("分组已删除");
    await loadWorkspace();
  });
}

function confirmMemberRemove(member) {
  askConfirmation("移除成员", `从团队移除 ${member.user.display_name}？`, async () => {
    await api(`/api/members/${member.id}`, { method: "DELETE" });
    showToast("成员已移除");
    await loadWorkspace();
  });
}

function confirmAgentTokenRotation(agent) {
  askConfirmation("轮换节点密钥", `立即停用“${agent.name}”的当前密钥？`, async () => {
    const result = await api(`/api/agents/${agent.id}/rotate-token`, { method: "POST" });
    showAgentToken(result.agent_token);
    await loadWorkspace();
  });
}

function confirmAgentRevoke(agent) {
  askConfirmation("撤销执行节点", `撤销“${agent.name}”并释放其活跃租约？`, async () => {
    await api(`/api/agents/${agent.id}`, { method: "DELETE" });
    showToast("执行节点已撤销");
    await loadWorkspace();
  });
}

async function saveOrganization(event) {
  event.preventDefault();
  setError(elements.organizationError);
  try {
    await api("/api/organizations", { method: "POST", body: { name: elements.organizationName.value } });
    elements.organizationDialog.close();
    showToast("团队已创建");
    await refreshSession();
  } catch (error) {
    setError(elements.organizationError, error.message);
  }
}

async function submitAuth(form, path) {
  setError(elements.authError);
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(form));
    const result = await api(path, { method: "POST", body: payload });
    state.csrf = result.csrf_token;
    await refreshSession();
  } catch (error) {
    setError(elements.authError, error.message);
  } finally {
    submit.disabled = false;
  }
}

elements.loginTab.addEventListener("click", () => switchAuth("login"));
elements.registerTab.addEventListener("click", () => switchAuth("register"));
elements.loginForm.addEventListener("submit", (event) => { event.preventDefault(); submitAuth(elements.loginForm, "/api/auth/login"); });
elements.registerForm.addEventListener("submit", (event) => { event.preventDefault(); submitAuth(elements.registerForm, "/api/auth/register"); });
elements.logoutButton.addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } finally { showAuth(); }
});
elements.organizationSelect.addEventListener("change", async () => {
  try {
    await api("/api/session/organization", { method: "POST", body: { organization_id: elements.organizationSelect.value } });
    await refreshSession();
  } catch (error) {
    showToast(error.message, "error");
  }
});
document.querySelectorAll(".workspace-tabs button").forEach((tab) => tab.addEventListener("click", () => setView(tab.dataset.view)));
elements.environmentSearch.addEventListener("input", renderEnvironments);
elements.environmentGroupFilter.addEventListener("change", renderEnvironments);
elements.createEnvironmentButton.addEventListener("click", () => openEnvironmentDialog());
elements.createGroupButton.addEventListener("click", openGroupDialog);
elements.addMemberButton.addEventListener("click", openMemberDialog);
elements.createPlatformUserButton.addEventListener("click", openPlatformUserDialog);
elements.createExtensionButton.addEventListener("click", openExtensionDialog);
elements.createAgentButton.addEventListener("click", openAgentDialog);
elements.refreshAuditButton.addEventListener("click", () => loadAudit().catch((error) => showToast(error.message, "error")));
elements.refreshTasksButton.addEventListener("click", () => loadWorkspace().catch((error) => showToast(error.message, "error")));
elements.environmentForm.addEventListener("submit", saveEnvironment);
elements.environmentStorage.addEventListener("change", updateStoragePolicyNotice);
elements.environmentClearProxy.addEventListener("change", updateProxyControls);
elements.environmentProxy.addEventListener("input", () => {
  if (elements.environmentProxy.value) elements.environmentClearProxy.checked = false;
  updateProxyControls();
});
elements.toggleEnvironmentProxyButton.addEventListener("click", () => {
  const show = elements.environmentProxy.type === "password";
  elements.environmentProxy.type = show ? "text" : "password";
  elements.toggleEnvironmentProxyButton.textContent = show ? "隐藏" : "显示";
});
elements.environmentGeoip.addEventListener("change", updateEnvironmentConsistencyWarnings);
elements.environmentTimezone.addEventListener("change", updateEnvironmentConsistencyWarnings);
elements.environmentLocale.addEventListener("change", updateEnvironmentConsistencyWarnings);
elements.environmentLocation.addEventListener("change", () => {
  const timezone = elements.environmentLocation.selectedOptions[0]?.dataset.timezone;
  if (timezone) setSelectValue(elements.environmentTimezone, timezone);
  if (elements.environmentLocation.value && !elements.environmentLocale.value) {
    setSelectValue(elements.environmentLocale, "en-US");
  }
  updateEnvironmentConsistencyWarnings();
});
elements.environmentStorageQuota.addEventListener("input", updateEnvironmentConsistencyWarnings);
[
  elements.environmentFingerprintPlatform,
  elements.environmentFingerprintBrand,
  elements.environmentHardwareConcurrency,
  elements.environmentDeviceMemory,
  elements.environmentScreenSize,
  elements.environmentTaskbarHeight,
  elements.environmentFingerprintNoise,
  elements.environmentAllowThirdPartyCookies,
].forEach((input) => input.addEventListener("change", updateEnvironmentAdvancedState));
[
  elements.environmentFingerprintBrandVersion,
  elements.environmentFingerprintPlatformVersion,
  elements.environmentGpuVendor,
  elements.environmentGpuRenderer,
].forEach((input) => input.addEventListener("input", updateEnvironmentAdvancedState));
elements.extensionForm.addEventListener("submit", saveExtension);
elements.launchForm.addEventListener("submit", requestEnvironmentLaunch);
elements.groupForm.addEventListener("submit", saveGroup);
elements.memberForm.addEventListener("submit", saveMember);
elements.platformUserForm.addEventListener("submit", savePlatformUser);
elements.platformPasswordForm.addEventListener("submit", resetPlatformUserPassword);
elements.platformMembershipForm.addEventListener("submit", savePlatformMembership);
elements.agentForm.addEventListener("submit", saveAgent);
elements.copyAgentTokenButton.addEventListener("click", copyAgentToken);
elements.agentTokenDialog.addEventListener("close", () => {
  elements.agentTokenValue.value = "";
});
elements.organizationForm.addEventListener("submit", saveOrganization);
elements.createOrganizationButton.addEventListener("click", () => {
  elements.organizationForm.reset();
  setError(elements.organizationError);
  elements.organizationDialog.showModal();
  elements.organizationName.focus();
});
document.querySelector("#generateCloudSeedButton").addEventListener("click", () => {
  elements.environmentSeed.value = randomSeed();
});
document.querySelectorAll("[data-close-dialog]").forEach((control) => {
  control.addEventListener("click", () => document.querySelector(`#${control.dataset.closeDialog}`).close());
});
elements.confirmDialog.addEventListener("close", async () => {
  const action = state.confirmAction;
  state.confirmAction = null;
  if (elements.confirmDialog.returnValue !== "default" || !action) return;
  try {
    await action();
  } catch (error) {
    showToast(error.message, "error");
  }
});

async function initialize() {
  try {
    await refreshSession();
  } catch (error) {
    if (error.status === 401) showAuth();
    else {
      showAuth();
      setError(elements.authError, error.message);
    }
  }
}

initialize();

window.setInterval(() => {
  if (!state.session || document.hidden) return;
  loadWorkspace().catch((error) => showToast(error.message, "error"));
}, 5000);
