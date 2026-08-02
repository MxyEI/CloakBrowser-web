"use strict";

const LOCATION_LABELS = {
  "new-york": "New York, NY · 40.7128, -74.0060",
  chicago: "Chicago, IL · 41.8781, -87.6298",
  denver: "Denver, CO · 39.7392, -104.9903",
  phoenix: "Phoenix, AZ · 33.4484, -112.0740",
  "los-angeles": "Los Angeles, CA · 34.0522, -118.2437",
  anchorage: "Anchorage, AK · 61.2181, -149.9003",
  honolulu: "Honolulu, HI · 21.3099, -157.8581",
};

const state = {
  csrf: "",
  profiles: [],
  filter: "all",
  group: "all",
  search: "",
  selected: new Set(),
  editingId: null,
  deleteId: null,
  fingerprintId: null,
  proxyCheck: null,
  pollTimer: null,
  profilesSignature: null,
  renderPending: false,
  previewTimer: null,
  previewLoading: false,
  previewQueued: false,
  previewGeneration: 0,
  previewDetails: null,
};

const elements = {
  rows: document.querySelector("#profileRows"),
  empty: document.querySelector("#emptyState"),
  emptyTitle: document.querySelector("#emptyTitle"),
  emptyCreate: document.querySelector("#emptyCreateButton"),
  total: document.querySelector("#totalCount"),
  running: document.querySelector("#runningCount"),
  proxy: document.querySelector("#proxyCount"),
  search: document.querySelector("#searchInput"),
  groupFilter: document.querySelector("#groupFilter"),
  selectVisible: document.querySelector("#selectVisibleInput"),
  selectionCount: document.querySelector("#selectionCount"),
  profileModal: document.querySelector("#profileModal"),
  confirmModal: document.querySelector("#confirmModal"),
  fingerprintModal: document.querySelector("#fingerprintModal"),
  form: document.querySelector("#profileForm"),
  profileId: document.querySelector("#profileId"),
  name: document.querySelector("#nameInput"),
  group: document.querySelector("#groupInput"),
  tags: document.querySelector("#tagsInput"),
  groupOptions: document.querySelector("#groupOptions"),
  seed: document.querySelector("#seedInput"),
  seedPreviewRows: document.querySelector("#seedPreviewRows"),
  seedPreviewStatus: document.querySelector("#seedPreviewStatus"),
  previewSeedButton: document.querySelector("#previewSeedButton"),
  startupUrl: document.querySelector("#startupUrlInput"),
  proxyInput: document.querySelector("#proxyInput"),
  proxyScheme: document.querySelector("#proxySchemeInput"),
  currentProxy: document.querySelector("#currentProxy"),
  proxyResult: document.querySelector("#proxyResult"),
  proxyResultIp: document.querySelector("#proxyResultIp"),
  proxyChange: document.querySelector("#proxyChange"),
  checkProxyButton: document.querySelector("#checkProxyButton"),
  lockProxyIp: document.querySelector("#lockProxyIpInput"),
  proxyLockState: document.querySelector("#proxyLockState"),
  lockedProxyIp: document.querySelector("#lockedProxyIp"),
  acceptProxyIpButton: document.querySelector("#acceptProxyIpButton"),
  clearProxyField: document.querySelector("#clearProxyField"),
  clearProxy: document.querySelector("#clearProxyInput"),
  timezone: document.querySelector("#timezoneInput"),
  location: document.querySelector("#locationInput"),
  locale: document.querySelector("#localeInput"),
  geoip: document.querySelector("#geoipInput"),
  advancedFingerprintPanel: document.querySelector("#advancedFingerprintPanel"),
  advancedFingerprintSummary: document.querySelector("#advancedFingerprintSummary"),
  consistencyWarning: document.querySelector("#consistencyWarning"),
  fingerprintPlatform: document.querySelector("#fingerprintPlatformInput"),
  fingerprintBrand: document.querySelector("#fingerprintBrandInput"),
  fingerprintBrandVersion: document.querySelector("#fingerprintBrandVersionInput"),
  fingerprintPlatformVersion: document.querySelector("#fingerprintPlatformVersionInput"),
  hardwareConcurrency: document.querySelector("#hardwareConcurrencyInput"),
  deviceMemory: document.querySelector("#deviceMemoryInput"),
  screenSize: document.querySelector("#screenSizeInput"),
  taskbarHeight: document.querySelector("#taskbarHeightInput"),
  gpuVendor: document.querySelector("#gpuVendorInput"),
  gpuRenderer: document.querySelector("#gpuRendererInput"),
  fingerprintNoise: document.querySelector("#fingerprintNoiseInput"),
  allowThirdPartyCookies: document.querySelector("#allowThirdPartyCookiesInput"),
  headless: document.querySelector("#headlessInput"),
  humanize: document.querySelector("#humanizeInput"),
  quota: document.querySelector("#quotaInput"),
  notes: document.querySelector("#notesInput"),
  modalTitle: document.querySelector("#modalTitle"),
  modalKicker: document.querySelector("#modalKicker"),
  saveButton: document.querySelector("#saveButton"),
  confirmText: document.querySelector("#confirmText"),
  toastRegion: document.querySelector("#toastRegion"),
  batchLaunch: document.querySelector("#batchLaunchButton"),
  batchStop: document.querySelector("#batchStopButton"),
  importButton: document.querySelector("#importButton"),
  importFile: document.querySelector("#importFileInput"),
  exportButton: document.querySelector("#exportButton"),
  exportMenu: document.querySelector("#exportMenu"),
  fingerprintTitle: document.querySelector("#fingerprintTitle"),
  fingerprintConfigRows: document.querySelector("#fingerprintConfigRows"),
  fingerprintActualRows: document.querySelector("#fingerprintActualRows"),
  fingerprintCaptureStatus: document.querySelector("#fingerprintCaptureStatus"),
};

function randomSeed() {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return 10000 + (values[0] % 90000);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-Cloak-CSRF"] = state.csrf;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `请求失败 (${response.status})`);
  }
  return data;
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type === "error" ? "error" : ""}`;
  toast.textContent = message;
  elements.toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 3600);
}

function statusLabel(status) {
  return {
    running: "运行中",
    starting: "启动中",
    stopping: "停止中",
    stopped: "已停止",
    error: "启动失败",
  }[status] || "未知";
}

function formatTime(value) {
  if (!value) return "从未";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "从未";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function filteredProfiles() {
  const query = state.search.trim().toLowerCase();
  return state.profiles.filter((profile) => {
    const statusMatches = state.filter === "all"
      || (state.filter === "running" && ["running", "starting", "stopping"].includes(profile.status))
      || (state.filter === "stopped" && ["stopped", "error"].includes(profile.status));
    const groupMatches = state.group === "all" || profile.group === state.group;
    const queryMatches = !query || [
      profile.name,
      profile.group,
      ...(profile.tags || []),
      profile.proxy_masked,
      profile.fingerprint_seed,
      profile.notes,
    ].some((value) => String(value || "").toLowerCase().includes(query));
    return statusMatches && groupMatches && queryMatches;
  });
}

function textElement(tag, className, value) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = value;
  return element;
}

function createRow(profile) {
  const row = document.createElement("tr");
  row.dataset.profileId = profile.id;
  row.classList.toggle("selected", state.selected.has(profile.id));

  const nameCell = document.createElement("td");
  const nameCellWrap = document.createElement("div");
  nameCellWrap.className = "environment-cell-wrap";
  const select = document.createElement("input");
  select.type = "checkbox";
  select.className = "profile-select";
  select.dataset.profileSelect = profile.id;
  select.checked = state.selected.has(profile.id);
  select.setAttribute("aria-label", `选择环境 ${profile.name}`);
  const nameWrap = textElement("div", "environment-name", "");
  nameWrap.append(textElement("strong", "", profile.name));
  const labels = document.createElement("div");
  labels.className = "environment-labels";
  if (profile.group) labels.append(textElement("span", "group-label", profile.group));
  for (const tag of (profile.tags || []).slice(0, 3)) {
    labels.append(textElement("span", "tag-label", tag));
  }
  if (!labels.children.length) labels.append(textElement("span", "environment-id", profile.notes || profile.id));
  nameWrap.append(labels);
  if (profile.notes) nameWrap.title = profile.notes;
  if (profile.error) {
    const error = textElement("span", "status-error-line", profile.error);
    error.title = profile.error;
    nameWrap.append(error);
  }
  nameCellWrap.append(select, nameWrap);
  nameCell.append(nameCellWrap);

  const statusCell = document.createElement("td");
  const badge = textElement("span", `status-badge ${profile.status}`, statusLabel(profile.status));
  if (profile.error) badge.title = profile.error;
  statusCell.append(badge);

  const seedCell = document.createElement("td");
  seedCell.append(textElement("span", "seed-value", String(profile.fingerprint_seed)));

  const proxyCell = document.createElement("td");
  proxyCell.append(textElement(
    "span",
    "proxy-value",
    profile.proxy_configured ? profile.proxy_masked : "未配置",
  ));
  if (profile.proxy_exit_ip) {
    const ip = textElement("span", "proxy-ip-line", `出口 ${profile.proxy_exit_ip}`);
    ip.title = `检测时间：${formatTime(profile.proxy_checked_at)}`;
    proxyCell.append(ip);
  }
  if (profile.lock_proxy_ip) {
    const lock = textElement(
      "span",
      `proxy-lock-line${profile.proxy_ip_conflict ? " conflict" : ""}`,
      profile.locked_proxy_ip ? `锁定 ${profile.locked_proxy_ip}` : "等待首次锁定",
    );
    proxyCell.append(lock);
  }

  const timeCell = document.createElement("td");
  timeCell.append(textElement("span", "muted", formatTime(profile.last_launched_at)));

  const actionCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "row-actions";
  const active = ["starting", "running", "stopping"].includes(profile.status);
  const primaryAction = textElement("button", `row-action ${active ? "stop" : "launch"}`, active ? "停止" : "启动");
  primaryAction.type = "button";
  primaryAction.dataset.action = active ? "stop" : "launch";
  primaryAction.dataset.id = profile.id;
  primaryAction.disabled = profile.status === "starting" || profile.status === "stopping";

  const moreWrap = document.createElement("div");
  moreWrap.className = "more-wrap";
  const more = textElement("button", "more-button", "⋯");
  more.type = "button";
  more.title = "更多操作";
  more.setAttribute("aria-label", "更多操作");
  more.dataset.action = "menu";
  more.dataset.id = profile.id;
  const menu = document.createElement("div");
  menu.className = "row-menu";
  menu.hidden = true;
  const menuItems = [
    ["fingerprint", "指纹详情", ""],
    ["edit", "编辑", ""],
    ["clone", "复制环境", ""],
    ["delete", "删除", "danger-text"],
  ];
  if (profile.proxy_ip_conflict) {
    menuItems.splice(1, 0, ["accept-proxy-ip", "接受当前 IP", "warning-text"]);
  }
  for (const [action, label, className] of menuItems) {
    const item = textElement("button", className, label);
    item.type = "button";
    item.dataset.action = action;
    item.dataset.id = profile.id;
    item.disabled = active && ["edit", "delete"].includes(action);
    menu.append(item);
  }
  moreWrap.append(more, menu);
  actions.append(primaryAction, moreWrap);
  actionCell.append(actions);
  row.append(nameCell, statusCell, seedCell, proxyCell, timeCell, actionCell);
  return row;
}

function render() {
  const profiles = filteredProfiles();
  elements.rows.replaceChildren(...profiles.map(createRow));
  const noProfiles = state.profiles.length === 0;
  const noMatches = profiles.length === 0;
  elements.empty.hidden = !noMatches;
  elements.rows.closest("table").hidden = noMatches;
  elements.emptyTitle.textContent = noProfiles ? "还没有浏览器环境" : "没有匹配的环境";
  elements.emptyCreate.hidden = !noProfiles;
  elements.total.textContent = String(state.profiles.length);
  elements.running.textContent = String(state.profiles.filter((item) => item.status === "running").length);
  elements.proxy.textContent = String(state.profiles.filter((item) => item.proxy_configured).length);
  const selected = state.profiles.filter((item) => state.selected.has(item.id));
  elements.batchLaunch.disabled = !selected.some((item) => ["stopped", "error"].includes(item.status));
  elements.batchStop.disabled = !selected.some((item) => ["starting", "running", "stopping"].includes(item.status));
  elements.exportButton.disabled = selected.length === 0;
  if (!selected.length) {
    elements.exportMenu.hidden = true;
    elements.exportButton.setAttribute("aria-expanded", "false");
  }
  const allVisibleSelected = profiles.length > 0 && profiles.every((item) => state.selected.has(item.id));
  const someVisibleSelected = profiles.some((item) => state.selected.has(item.id));
  elements.selectVisible.checked = allVisibleSelected;
  elements.selectVisible.indeterminate = someVisibleSelected && !allVisibleSelected;
  elements.selectVisible.disabled = profiles.length === 0;
  elements.selectionCount.textContent = state.selected.size ? `已选 ${state.selected.size}` : "全选当前";
}

function renderGroupFilters() {
  const groups = [...new Set(state.profiles.map((item) => item.group).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right, "zh-CN"));
  if (state.group !== "all" && !groups.includes(state.group)) state.group = "all";
  elements.groupFilter.replaceChildren(
    new Option("全部分组", "all"),
    ...groups.map((group) => new Option(group, group)),
  );
  elements.groupFilter.value = state.group;
  elements.groupOptions.replaceChildren(...groups.map((group) => {
    const option = document.createElement("option");
    option.value = group;
    return option;
  }));
}

function hasOpenProfileMenu() {
  return Boolean(elements.rows.querySelector(".row-menu:not([hidden])"));
}

function commitProfilesRender() {
  renderGroupFilters();
  render();
  state.renderPending = false;
}

function requestProfilesRender() {
  if (hasOpenProfileMenu()) {
    state.renderPending = true;
    return;
  }
  commitProfilesRender();
}

function flushPendingProfilesRender() {
  if (state.renderPending && !hasOpenProfileMenu()) commitProfilesRender();
}

async function loadProfiles({ quiet = false } = {}) {
  try {
    const data = await api("/api/profiles");
    const profilesSignature = JSON.stringify(data.profiles);
    const profilesChanged = profilesSignature !== state.profilesSignature;
    state.profiles = data.profiles;
    state.profilesSignature = profilesSignature;
    state.selected = new Set([...state.selected].filter((id) => state.profiles.some((item) => item.id === id)));
    if (profilesChanged) requestProfilesRender();
    if (state.fingerprintId && !elements.fingerprintModal.hidden) {
      renderFingerprintDetails(profileById(state.fingerprintId));
    }
  } catch (error) {
    if (!quiet) showToast(error.message, "error");
  }
}

function profileById(id) {
  return state.profiles.find((profile) => profile.id === id);
}

function renderProxyLockState(profile = null, result = null) {
  const enabled = elements.lockProxyIp.checked;
  const lockedIp = result?.locked_ip ?? profile?.locked_proxy_ip ?? "";
  const currentIp = result?.exit_ip ?? profile?.proxy_exit_ip ?? "";
  const conflict = Boolean(enabled && lockedIp && currentIp && lockedIp !== currentIp);
  elements.proxyLockState.hidden = !enabled;
  elements.proxyLockState.classList.toggle("conflict", conflict);
  elements.lockedProxyIp.textContent = lockedIp || "首次启动时设置";
  elements.acceptProxyIpButton.hidden = !(state.editingId && conflict);
}

function syncGeoipAvailability() {
  const savedProxy = profileById(state.editingId)?.proxy_configured ?? false;
  const hasProxy = !elements.clearProxy.checked && Boolean(elements.proxyInput.value.trim() || savedProxy);
  elements.geoip.disabled = !hasProxy;
  if (!hasProxy) elements.geoip.checked = false;
}

function proxyValue() {
  const value = elements.proxyInput.value.trim();
  if (!value || value.includes("://")) return value;
  return `${elements.proxyScheme.value}://${value}`;
}

function setTimezoneValue(value) {
  elements.timezone.querySelector("option[data-custom-timezone]")?.remove();
  if (value && ![...elements.timezone.options].some((option) => option.value === value)) {
    const option = new Option(value, value);
    option.dataset.customTimezone = "true";
    elements.timezone.append(option);
  }
  elements.timezone.value = value || "";
}

function setLocaleValue(value) {
  elements.locale.querySelector("option[data-custom-locale]")?.remove();
  if (value && ![...elements.locale.options].some((option) => option.value === value)) {
    const option = new Option(value, value);
    option.dataset.customLocale = "true";
    elements.locale.append(option);
  }
  elements.locale.value = value || "";
}

function setScreenSizeValue(width, height) {
  elements.screenSize.querySelector("option[data-custom-screen]")?.remove();
  const value = width && height ? `${width}x${height}` : "";
  if (value && ![...elements.screenSize.options].some((option) => option.value === value)) {
    const option = new Option(`${width} × ${height}`, value);
    option.dataset.customScreen = "true";
    elements.screenSize.append(option);
  }
  elements.screenSize.value = value;
}

function screenDimensions() {
  const match = /^(\d+)x(\d+)$/.exec(elements.screenSize.value);
  return match
    ? { screen_width: Number(match[1]), screen_height: Number(match[2]) }
    : { screen_width: 0, screen_height: 0 };
}

function advancedFingerprintPayload() {
  return {
    fingerprint_platform: elements.fingerprintPlatform.value,
    fingerprint_brand: elements.fingerprintBrand.value,
    fingerprint_brand_version: elements.fingerprintBrandVersion.value.trim(),
    fingerprint_platform_version: elements.fingerprintPlatformVersion.value.trim(),
    hardware_concurrency: Number(elements.hardwareConcurrency.value),
    device_memory_gb: Number(elements.deviceMemory.value),
    ...screenDimensions(),
    gpu_vendor: elements.gpuVendor.value.trim(),
    gpu_renderer: elements.gpuRenderer.value.trim(),
    taskbar_height: Number(elements.taskbarHeight.value),
    fingerprint_noise: elements.fingerprintNoise.checked,
    allow_third_party_cookies: elements.allowThirdPartyCookies.checked,
  };
}

function advancedOverrideCount(config) {
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

function advancedFingerprintLabel(config) {
  const count = advancedOverrideCount(config);
  return count ? `手动覆盖 ${count} 项` : "Seed 自动生成";
}

function updateAdvancedFingerprintState() {
  const config = advancedFingerprintPayload();
  elements.advancedFingerprintSummary.textContent = advancedFingerprintLabel(config);

  const hasGpuOverride = Boolean(config.gpu_vendor || config.gpu_renderer);
  elements.gpuVendor.required = hasGpuOverride;
  elements.gpuRenderer.required = hasGpuOverride;

  updateConsistencyWarnings();
}

function gpuFamily(value) {
  if (/apple/i.test(value)) return "Apple";
  if (/nvidia|geforce|quadro/i.test(value)) return "NVIDIA";
  if (/\bamd\b|radeon|ati technologies/i.test(value)) return "AMD";
  if (/intel/i.test(value)) return "Intel";
  return "";
}

function currentConsistencyConfig() {
  return {
    ...advancedFingerprintPayload(),
    timezone: elements.timezone.value,
    location: elements.location.value,
    locale: elements.locale.value,
    geoip: elements.geoip.checked,
    storage_quota_mb: Number(elements.quota.value || 0),
  };
}

function previewMismatchLabels(config, details) {
  if (!details) return [];
  const mismatches = [];
  const actualPlatform = String(details.platform || "");
  if (config.fingerprint_platform === "windows" && !/win/i.test(actualPlatform)) mismatches.push("平台");
  if (config.fingerprint_platform === "macos" && !/mac/i.test(actualPlatform)) mismatches.push("平台");
  if (config.timezone && details.timezone && config.timezone !== details.timezone) mismatches.push("时区");
  if (config.locale && details.language && config.locale.toLowerCase() !== String(details.language).toLowerCase()) mismatches.push("语言");
  if (config.hardware_concurrency && config.hardware_concurrency !== Number(details.hardware_concurrency)) mismatches.push("CPU 线程");
  if (config.device_memory_gb && config.device_memory_gb !== Number(details.device_memory_gb)) mismatches.push("设备内存");

  const screen = details.screen || {};
  if (config.screen_width && (
    config.screen_width !== Number(screen.width) || config.screen_height !== Number(screen.height)
  )) mismatches.push("屏幕分辨率");
  if (config.taskbar_height >= 0 && screen.height != null && screen.avail_height != null
      && config.taskbar_height !== Number(screen.height) - Number(screen.avail_height)) {
    mismatches.push("任务栏高度");
  }

  const comparableText = (value) => String(value || "").trim().replace(/\s+/g, " ").toLowerCase();
  if (config.gpu_vendor && comparableText(config.gpu_vendor) !== comparableText(details.webgl_vendor)) mismatches.push("GPU Vendor");
  if (config.gpu_renderer && comparableText(config.gpu_renderer) !== comparableText(details.webgl_renderer)) mismatches.push("GPU Renderer");

  if (config.storage_quota_mb && details.storage_quota_mb != null) {
    const quotaDifference = Math.abs(config.storage_quota_mb - Number(details.storage_quota_mb));
    if (quotaDifference > Math.max(32, config.storage_quota_mb * 0.02)) mismatches.push("存储配额");
  }

  const brandTokens = { Chrome: "Chrome", Edge: "Edg", Opera: "OPR", Vivaldi: "Vivaldi" };
  const brandToken = brandTokens[config.fingerprint_brand];
  if (brandToken) {
    const escapedToken = brandToken.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = new RegExp(`${escapedToken}/([0-9.]+)`).exec(String(details.user_agent || ""));
    if (!match) mismatches.push("浏览器品牌");
    else if (config.fingerprint_brand_version && match[1] !== config.fingerprint_brand_version) mismatches.push("浏览器版本");
  }
  return [...new Set(mismatches)];
}

function collectConsistencyWarnings(details = state.previewDetails) {
  const config = currentConsistencyConfig();
  const warnings = [];

  const locationTimezone = elements.location.selectedOptions[0]?.dataset.timezone || "";
  if (config.location && config.timezone && locationTimezone && config.timezone !== locationTimezone) {
    warnings.push(`所选城市对应 ${locationTimezone}，与当前时区 ${config.timezone} 不一致`);
  }
  if (config.geoip && (config.timezone || config.locale || config.location)) {
    warnings.push("GeoIP 自动匹配与手动地区设置同时启用，手动值会优先；请确认它们与代理出口一致");
  }

  const hostIsMac = /Mac/i.test(navigator.platform || "");
  const effectivePlatform = config.fingerprint_platform || (hostIsMac ? "macos" : "windows");
  if (config.fingerprint_platform === "windows" && hostIsMac) {
    warnings.push("当前宿主为 macOS，Windows 身份可能与系统字体和图形特征不一致");
  }
  if (config.fingerprint_platform === "macos" && !hostIsMac) {
    warnings.push("当前宿主不是 macOS，macOS 身份可能与系统字体和图形特征不一致");
  }

  const hasGpuOverride = Boolean(config.gpu_vendor || config.gpu_renderer);
  if (hasGpuOverride && (!config.gpu_vendor || !config.gpu_renderer)) {
    warnings.push("GPU Vendor 和 Renderer 必须同时设置");
  }
  if (effectivePlatform === "windows" && /apple/i.test(config.gpu_vendor)) {
    warnings.push("Windows 平台不应搭配 Apple GPU");
  }
  const vendorFamily = gpuFamily(config.gpu_vendor);
  const rendererFamily = gpuFamily(config.gpu_renderer);
  if (vendorFamily && rendererFamily && vendorFamily !== rendererFamily) {
    warnings.push(`GPU Vendor 属于 ${vendorFamily}，Renderer 却属于 ${rendererFamily}`);
  }
  if (effectivePlatform === "windows" && config.taskbar_height === 95) {
    warnings.push("Windows 身份使用了更常见于 macOS 的 95 px 任务栏高度");
  }
  if (effectivePlatform === "macos" && [40, 48].includes(config.taskbar_height)) {
    warnings.push("macOS 身份使用了更常见于 Windows 的任务栏高度");
  }
  if (config.storage_quota_mb && config.storage_quota_mb < 1024) {
    warnings.push("存储配额低于 1 GB，部分站点可能将环境判断为隐私模式");
  }
  if (!config.fingerprint_noise) {
    warnings.push("指纹噪声已关闭");
  }
  if (config.allow_third_party_cookies) {
    warnings.push("第三方 Cookie 兼容开关需要 Chromium 148+");
  }

  const previewMismatches = previewMismatchLabels(config, details);
  if (previewMismatches.length) {
    warnings.push(`指纹预览未按设置生效：${previewMismatches.join("、")}`);
  }
  return warnings;
}

function updateConsistencyWarnings(details = state.previewDetails) {
  const warnings = collectConsistencyWarnings(details);
  elements.consistencyWarning.hidden = warnings.length === 0;
  elements.consistencyWarning.replaceChildren(
    textElement("strong", "", "配置一致性提醒"),
    textElement("span", "", warnings.join("；")),
  );
}

function fingerprintPreviewPayload() {
  return {
    fingerprint_seed: Number(elements.seed.value),
    timezone: elements.timezone.value,
    location: elements.location.value,
    locale: elements.locale.value,
    storage_quota_mb: Number(elements.quota.value || 5000),
    ...advancedFingerprintPayload(),
  };
}

function fingerprintPreviewSignature() {
  return JSON.stringify(fingerprintPreviewPayload());
}

function renderSeedPreview(details = null, status = "等待采集", error = false) {
  const payload = fingerprintPreviewPayload();
  const screen = details?.screen || {};
  const language = details
    ? [details.language, ...(details.languages || []).filter((item) => item !== details.language)].filter(Boolean).join(", ")
    : (payload.locale || "浏览器默认");
  const timezone = details?.timezone || payload.timezone || "浏览器默认";
  const rows = details ? [
    ["Seed", String(payload.fingerprint_seed || "-")],
    ["平台", details.platform],
    ["User-Agent", details.user_agent],
    ["语言", language],
    ["时区", timezone],
    ["CPU 线程", details.hardware_concurrency],
    ["设备内存", details.device_memory_gb == null ? "-" : `${details.device_memory_gb} GB`],
    ["屏幕", screen.width ? `${screen.width} × ${screen.height}` : "-"],
    ["WebGL Vendor", details.webgl_vendor],
    ["WebGL Renderer", details.webgl_renderer],
    ["存储配额", details.storage_quota_mb == null ? `${payload.storage_quota_mb} MB` : `${details.storage_quota_mb} MB`],
    ["地理位置", LOCATION_LABELS[payload.location] || "浏览器默认"],
  ] : [
    ["Seed", String(payload.fingerprint_seed || "-")],
    ["语言", language],
    ["时区", timezone],
    ["地理位置", LOCATION_LABELS[payload.location] || "浏览器默认"],
  ];
  elements.seedPreviewStatus.textContent = status;
  elements.seedPreviewStatus.classList.toggle("error", error);
  renderFingerprintRows(elements.seedPreviewRows, rows);
}

function scheduleFingerprintPreview(delay = 500) {
  window.clearTimeout(state.previewTimer);
  state.previewDetails = null;
  updateConsistencyWarnings();
  renderSeedPreview(null, "等待刷新");
  state.previewTimer = window.setTimeout(previewFingerprint, delay);
}

async function previewFingerprint() {
  window.clearTimeout(state.previewTimer);
  state.previewTimer = null;
  if (elements.profileModal.hidden) return;
  const payload = fingerprintPreviewPayload();
  if (!Number.isInteger(payload.fingerprint_seed) || payload.fingerprint_seed < 1 || payload.fingerprint_seed > 2147483647) {
    renderSeedPreview(null, "Seed 无效", true);
    return;
  }
  if (state.previewLoading) {
    state.previewQueued = true;
    return;
  }

  const generation = state.previewGeneration;
  const signature = fingerprintPreviewSignature();
  state.previewLoading = true;
  state.previewQueued = false;
  elements.previewSeedButton.disabled = true;
  renderSeedPreview(null, "正在采集");
  try {
    const result = await api("/api/fingerprint/preview", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (generation === state.previewGeneration && signature === fingerprintPreviewSignature()) {
      state.previewDetails = result.details;
      updateConsistencyWarnings(result.details);
      renderSeedPreview(result.details, `实测 · ${formatTime(result.details.captured_at)}`);
    } else {
      state.previewQueued = true;
    }
  } catch (error) {
    if (generation === state.previewGeneration && signature === fingerprintPreviewSignature()) {
      state.previewDetails = null;
      updateConsistencyWarnings();
      renderSeedPreview(null, error.message, true);
    }
  } finally {
    state.previewLoading = false;
    elements.previewSeedButton.disabled = false;
    if (state.previewQueued && !elements.profileModal.hidden) scheduleFingerprintPreview(0);
  }
}

function openProfileModal(profile = null) {
  elements.toastRegion.replaceChildren();
  state.editingId = profile ? profile.id : null;
  state.proxyCheck = null;
  elements.form.reset();
  elements.profileId.value = profile?.id || "";
  elements.name.value = profile?.name || "";
  elements.group.value = profile?.group || "";
  elements.tags.value = (profile?.tags || []).join(", ");
  elements.seed.value = profile?.fingerprint_seed || randomSeed();
  elements.startupUrl.value = profile?.startup_url === "about:blank" ? "" : (profile?.startup_url || "");
  elements.proxyInput.value = "";
  elements.proxyScheme.value = profile?.proxy_masked?.split("://", 1)[0] || "http";
  elements.proxyInput.type = "password";
  document.querySelector("#toggleProxyButton").textContent = "显示";
  elements.currentProxy.textContent = profile?.proxy_masked || "";
  elements.proxyResult.hidden = !profile?.proxy_exit_ip;
  elements.proxyResultIp.textContent = profile?.proxy_exit_ip || "";
  elements.proxyChange.textContent = "";
  elements.lockProxyIp.checked = profile?.lock_proxy_ip ?? false;
  elements.clearProxyField.hidden = !profile?.proxy_configured;
  elements.clearProxy.checked = false;
  renderProxyLockState(profile);
  setTimezoneValue(profile?.timezone || "");
  elements.location.value = profile?.location || "";
  setLocaleValue(profile?.locale || "");
  elements.geoip.checked = Boolean(profile?.proxy_configured && profile?.geoip);
  syncGeoipAvailability();
  elements.fingerprintPlatform.value = profile?.fingerprint_platform || "";
  elements.fingerprintBrand.value = profile?.fingerprint_brand || "";
  elements.fingerprintBrandVersion.value = profile?.fingerprint_brand_version || "";
  elements.fingerprintPlatformVersion.value = profile?.fingerprint_platform_version || "";
  elements.hardwareConcurrency.value = String(profile?.hardware_concurrency || 0);
  elements.deviceMemory.value = String(profile?.device_memory_gb || 0);
  setScreenSizeValue(profile?.screen_width || 0, profile?.screen_height || 0);
  elements.taskbarHeight.value = String(profile?.taskbar_height ?? -1);
  elements.gpuVendor.value = profile?.gpu_vendor || "";
  elements.gpuRenderer.value = profile?.gpu_renderer || "";
  elements.fingerprintNoise.checked = profile?.fingerprint_noise ?? true;
  elements.allowThirdPartyCookies.checked = profile?.allow_third_party_cookies ?? false;
  elements.advancedFingerprintPanel.open = advancedOverrideCount(advancedFingerprintPayload()) > 0;
  elements.headless.checked = profile?.headless ?? false;
  elements.humanize.checked = profile?.humanize ?? false;
  elements.quota.value = profile?.storage_quota_mb || 5000;
  elements.notes.value = profile?.notes || "";
  state.previewGeneration += 1;
  state.previewQueued = false;
  const captured = profile?.fingerprint_details && Object.keys(profile.fingerprint_details).length
    ? profile.fingerprint_details
    : null;
  state.previewDetails = captured;
  updateAdvancedFingerprintState();
  renderSeedPreview(captured, captured ? `最近实测 · ${formatTime(captured.captured_at)}` : "等待采集");
  elements.modalKicker.textContent = profile ? "环境设置" : "新环境";
  elements.modalTitle.textContent = profile ? "编辑浏览器环境" : "新建浏览器环境";
  elements.saveButton.textContent = profile ? "保存修改" : "创建环境";
  elements.profileModal.hidden = false;
  document.body.style.overflow = "hidden";
  if (!captured) scheduleFingerprintPreview(100);
  window.setTimeout(() => elements.name.focus(), 0);
}

function closeProfileModal() {
  window.clearTimeout(state.previewTimer);
  state.previewTimer = null;
  state.previewGeneration += 1;
  state.previewQueued = false;
  state.previewDetails = null;
  elements.profileModal.hidden = true;
  document.body.style.overflow = "";
  state.editingId = null;
}

function formPayload() {
  return {
    name: elements.name.value,
    group: elements.group.value,
    tags: elements.tags.value.split(/[,，]/).map((tag) => tag.trim()).filter(Boolean),
    fingerprint_seed: Number(elements.seed.value),
    proxy: proxyValue(),
    clear_proxy: elements.clearProxy.checked,
    lock_proxy_ip: elements.lockProxyIp.checked,
    geoip: elements.geoip.checked,
    headless: elements.headless.checked,
    humanize: elements.humanize.checked,
    timezone: elements.timezone.value,
    location: elements.location.value,
    locale: elements.locale.value,
    startup_url: elements.startupUrl.value || "about:blank",
    storage_quota_mb: Number(elements.quota.value),
    ...advancedFingerprintPayload(),
    notes: elements.notes.value,
  };
}

async function saveProfile(event) {
  event.preventDefault();
  elements.saveButton.disabled = true;
  try {
    const editing = Boolean(state.editingId);
    const payload = formPayload();
    const response = await api(editing ? `/api/profiles/${state.editingId}` : "/api/profiles", {
      method: editing ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    const savedId = response.profile.id;
    if (state.proxyCheck && state.proxyCheck.proxy === payload.proxy && response.profile.proxy_configured) {
      try {
        await api("/api/proxy/check", {
          method: "POST",
          body: JSON.stringify({ profile_id: savedId }),
        });
      } catch (error) {
        showToast(error.message, "error");
      }
    }
    closeProfileModal();
    await loadProfiles();
    showToast(editing ? "环境已更新" : "环境已创建");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    elements.saveButton.disabled = false;
  }
}

async function checkProxy() {
  const proxy = proxyValue();
  elements.checkProxyButton.disabled = true;
  elements.checkProxyButton.textContent = "检测中";
  try {
    const result = await api("/api/proxy/check", {
      method: "POST",
      body: JSON.stringify({
        profile_id: state.editingId,
        proxy,
      }),
    });
    state.proxyCheck = { proxy, result };
    elements.proxyResult.hidden = false;
    elements.proxyResultIp.textContent = result.exit_ip;
    elements.proxyChange.textContent = result.lock_conflict
      ? `与锁定 IP ${result.locked_ip} 不一致`
      : result.changed ? `原出口 ${result.previous_ip}` : "";
    renderProxyLockState(profileById(state.editingId), result);
    showToast(result.lock_conflict ? "代理出口 IP 与锁定值不一致" : result.changed ? "代理出口 IP 已变化" : "代理连接正常", result.lock_conflict || result.changed ? "error" : "success");
    if (state.editingId && !proxy) {
      await loadProfiles({ quiet: true });
      renderProxyLockState(profileById(state.editingId), result);
    }
  } catch (error) {
    elements.proxyResult.hidden = true;
    showToast(error.message, "error");
  } finally {
    elements.checkProxyButton.disabled = false;
    elements.checkProxyButton.textContent = "检测代理";
  }
}

function fingerprintRow(label, value) {
  return [
    textElement("dt", "", label),
    textElement("dd", "", value ?? "-"),
  ];
}

function renderFingerprintRows(container, rows) {
  container.replaceChildren(...rows.flatMap(([label, value]) => fingerprintRow(label, value)));
}

function renderFingerprintDetails(profile) {
  if (!profile) return;
  const configuredTimezone = profile.timezone || (profile.geoip ? "GeoIP 自动" : "浏览器默认");
  const configuredLocale = profile.locale || (profile.geoip ? "GeoIP 自动" : "浏览器默认");
  const configuredLocation = LOCATION_LABELS[profile.location] || "浏览器默认";
  const configuredScreen = profile.screen_width
    ? `${profile.screen_width} × ${profile.screen_height}`
    : "Seed 默认";
  renderFingerprintRows(elements.fingerprintConfigRows, [
    ["Fingerprint seed", String(profile.fingerprint_seed)],
    ["高级覆盖", advancedFingerprintLabel(profile)],
    ["平台身份", profile.fingerprint_platform || "Seed 默认"],
    ["浏览器品牌", profile.fingerprint_brand || "Seed 默认"],
    ["浏览器版本", profile.fingerprint_brand_version || "Seed 默认"],
    ["系统版本", profile.fingerprint_platform_version || "Seed 默认"],
    ["CPU 线程", profile.hardware_concurrency || "Seed 默认"],
    ["设备内存", profile.device_memory_gb ? `${profile.device_memory_gb} GB` : "Seed 默认"],
    ["屏幕", configuredScreen],
    ["GPU", profile.gpu_vendor ? `${profile.gpu_vendor} · ${profile.gpu_renderer}` : "Seed 默认"],
    ["任务栏高度", profile.taskbar_height >= 0 ? `${profile.taskbar_height} px` : "平台默认"],
    ["指纹噪声", profile.fingerprint_noise ? "开启" : "关闭"],
    ["第三方 Cookie", profile.allow_third_party_cookies ? "允许" : "限制"],
    ["代理协议", profile.proxy_configured ? profile.proxy_masked.split("://", 1)[0].toUpperCase() : "无代理"],
    ["时区", configuredTimezone],
    ["地理位置", configuredLocation],
    ["语言", configuredLocale],
    ["GeoIP", profile.geoip ? "开启" : "关闭"],
    ["存储配额", `${profile.storage_quota_mb} MB`],
    ["运行模式", profile.headless ? "无头" : "有界面"],
    ["行为拟真", profile.humanize ? "开启" : "关闭"],
  ]);

  const details = profile.fingerprint_details || {};
  const screen = details.screen || {};
  const viewport = details.viewport || {};
  const hasDetails = Object.keys(details).length > 0;
  elements.fingerprintCaptureStatus.textContent = hasDetails ? `已采集 · ${formatTime(details.captured_at)}` : "尚未采集";
  renderFingerprintRows(elements.fingerprintActualRows, hasDetails ? [
    ["User-Agent", details.user_agent],
    ["平台", details.platform],
    ["语言", [details.language, ...(details.languages || []).filter((item) => item !== details.language)].filter(Boolean).join(", ")],
    ["时区", details.timezone],
    ["CPU 线程", details.hardware_concurrency],
    ["设备内存", details.device_memory_gb == null ? "-" : `${details.device_memory_gb} GB`],
    ["屏幕", screen.width ? `${screen.width} × ${screen.height}（可用 ${screen.avail_width} × ${screen.avail_height}）` : "-"],
    ["色深", screen.color_depth == null ? "-" : `${screen.color_depth} bit`],
    ["视口", viewport.inner_width ? `${viewport.inner_width} × ${viewport.inner_height}` : "-"],
    ["窗口", viewport.outer_width ? `${viewport.outer_width} × ${viewport.outer_height}` : "-"],
    ["设备像素比", viewport.device_pixel_ratio],
    ["WebGL Vendor", details.webgl_vendor],
    ["WebGL Renderer", details.webgl_renderer],
    ["存储配额", details.storage_quota_mb == null ? "-" : `${details.storage_quota_mb} MB`],
    ["触控点", details.max_touch_points],
    ["Cookie", details.cookie_enabled ? "启用" : "禁用"],
    ["Do Not Track", details.do_not_track || "未设置"],
  ] : [["采集状态", "尚未采集"]]);
}

function openFingerprintModal(profile) {
  if (!profile) return;
  state.fingerprintId = profile.id;
  elements.fingerprintTitle.textContent = `${profile.name} · 指纹详情`;
  renderFingerprintDetails(profile);
  elements.fingerprintModal.hidden = false;
  document.body.style.overflow = "hidden";
}

function closeFingerprintModal() {
  state.fingerprintId = null;
  elements.fingerprintModal.hidden = true;
  document.body.style.overflow = "";
}

async function batchAction(action) {
  const eligible = action === "launch"
    ? state.profiles.filter((item) => state.selected.has(item.id) && ["stopped", "error"].includes(item.status))
    : state.profiles.filter((item) => state.selected.has(item.id) && ["starting", "running", "stopping"].includes(item.status));
  if (!eligible.length) return;
  const button = action === "launch" ? elements.batchLaunch : elements.batchStop;
  button.disabled = true;
  try {
    const result = await api("/api/profiles/batch", {
      method: "POST",
      body: JSON.stringify({ action, profile_ids: eligible.map((item) => item.id) }),
    });
    await loadProfiles();
    const failures = Object.keys(result.errors).length;
    showToast(failures ? `${failures} 个环境操作失败` : action === "launch" ? "选中环境正在启动" : "选中环境正在停止", failures ? "error" : "success");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    render();
  }
}

async function exportSelected(includeProxyCredentials) {
  const profileIds = state.profiles
    .filter((profile) => state.selected.has(profile.id))
    .map((profile) => profile.id);
  if (!profileIds.length) return;
  elements.exportMenu.hidden = true;
  elements.exportButton.setAttribute("aria-expanded", "false");
  elements.exportButton.disabled = true;
  try {
    const exported = await api("/api/profiles/export", {
      method: "POST",
      body: JSON.stringify({
        profile_ids: profileIds,
        include_proxy_credentials: includeProxyCredentials,
      }),
    });
    const blob = new Blob([`${JSON.stringify(exported, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const date = new Date().toISOString().slice(0, 10);
    link.href = url;
    link.download = `cloakbrowser-profiles-${date}${includeProxyCredentials ? "-with-proxy" : ""}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast(`已导出 ${exported.profiles.length} 个环境`);
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    render();
  }
}

async function importProfileFile(event) {
  const [file] = event.target.files;
  event.target.value = "";
  if (!file) return;
  if (file.size > 500 * 1024) {
    showToast("导入文件不能超过 500 KB", "error");
    return;
  }
  elements.importButton.disabled = true;
  try {
    const parsed = JSON.parse(await file.text());
    const payload = Array.isArray(parsed) ? { profiles: parsed } : parsed;
    if (!payload || typeof payload !== "object") throw new Error("导入文件格式无效");
    const result = await api("/api/profiles/import", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    await loadProfiles();
    const failures = Object.keys(result.errors).length;
    showToast(
      failures ? `已导入 ${result.created.length} 个环境，${failures} 条失败` : `已导入 ${result.created.length} 个环境`,
      failures ? "error" : "success",
    );
  } catch (error) {
    showToast(error instanceof SyntaxError ? "导入文件不是有效的 JSON" : error.message, "error");
  } finally {
    elements.importButton.disabled = false;
  }
}

async function runAction(id, action) {
  const messages = {
    launch: "环境正在启动",
    stop: "环境正在停止",
    clone: "环境副本已创建",
  };
  try {
    await api(`/api/profiles/${id}/${action}`, { method: "POST", body: "{}" });
    await loadProfiles();
    showToast(messages[action]);
  } catch (error) {
    showToast(error.message, "error");
  }
}

async function acceptProxyIp(id) {
  if (!id) return;
  try {
    await api(`/api/profiles/${id}/accept-proxy-ip`, { method: "POST", body: "{}" });
    await loadProfiles();
    if (state.editingId === id) renderProxyLockState(profileById(id));
    showToast("已更新锁定的代理出口 IP");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function openDeleteModal(id) {
  const profile = profileById(id);
  if (!profile) return;
  state.deleteId = id;
  elements.confirmText.textContent = `“${profile.name}”将移入本地回收目录。`;
  elements.confirmModal.hidden = false;
}

function closeDeleteModal() {
  state.deleteId = null;
  elements.confirmModal.hidden = true;
}

async function deleteProfile() {
  if (!state.deleteId) return;
  const id = state.deleteId;
  try {
    await api(`/api/profiles/${id}`, { method: "DELETE", body: "{}" });
    closeDeleteModal();
    await loadProfiles();
    showToast("环境已移入回收目录");
  } catch (error) {
    showToast(error.message, "error");
  }
}

function closeMenus(except = null) {
  document.querySelectorAll(".row-menu").forEach((menu) => {
    if (menu !== except) {
      menu.hidden = true;
      if (menu === elements.exportMenu) elements.exportButton.setAttribute("aria-expanded", "false");
    }
  });
  flushPendingProfilesRender();
}

function handleRowAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const { action, id } = button.dataset;
  if (action === "menu") {
    const menu = button.parentElement.querySelector(".row-menu");
    const willOpen = menu.hidden;
    menu.hidden = !willOpen;
    closeMenus(menu);
    return;
  }
  closeMenus();
  if (action === "edit") openProfileModal(profileById(id));
  else if (action === "fingerprint") openFingerprintModal(profileById(id));
  else if (action === "delete") openDeleteModal(id);
  else if (action === "accept-proxy-ip") acceptProxyIp(id);
  else runAction(id, action);
}

async function initialize() {
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf_token;
    await loadProfiles();
    state.pollTimer = window.setInterval(() => loadProfiles({ quiet: true }), 1500);
  } catch (error) {
    showToast(error.message, "error");
  }
}

document.querySelector("#createButton").addEventListener("click", () => openProfileModal());
document.querySelector("#emptyCreateButton").addEventListener("click", () => openProfileModal());
document.querySelector("#refreshButton").addEventListener("click", () => loadProfiles());
document.querySelector("#generateSeedButton").addEventListener("click", () => {
  elements.seed.value = randomSeed();
  scheduleFingerprintPreview(0);
});
elements.previewSeedButton.addEventListener("click", () => scheduleFingerprintPreview(0));
elements.seed.addEventListener("input", () => scheduleFingerprintPreview());
elements.timezone.addEventListener("change", () => scheduleFingerprintPreview(250));
elements.locale.addEventListener("change", () => scheduleFingerprintPreview(250));
elements.quota.addEventListener("change", () => scheduleFingerprintPreview(250));
elements.geoip.addEventListener("change", () => updateConsistencyWarnings());
[
  elements.fingerprintPlatform,
  elements.fingerprintBrand,
  elements.hardwareConcurrency,
  elements.deviceMemory,
  elements.screenSize,
  elements.taskbarHeight,
  elements.fingerprintNoise,
  elements.allowThirdPartyCookies,
].forEach((input) => input.addEventListener("change", () => {
  updateAdvancedFingerprintState();
  scheduleFingerprintPreview(250);
}));
[
  elements.fingerprintBrandVersion,
  elements.fingerprintPlatformVersion,
  elements.gpuVendor,
  elements.gpuRenderer,
].forEach((input) => input.addEventListener("input", () => {
  updateAdvancedFingerprintState();
  scheduleFingerprintPreview();
}));
document.querySelector("#toggleProxyButton").addEventListener("click", (event) => {
  const show = elements.proxyInput.type === "password";
  elements.proxyInput.type = show ? "text" : "password";
  event.currentTarget.textContent = show ? "隐藏" : "显示";
});
elements.checkProxyButton.addEventListener("click", checkProxy);
elements.acceptProxyIpButton.addEventListener("click", () => acceptProxyIp(state.editingId));
elements.lockProxyIp.addEventListener("change", () => renderProxyLockState(profileById(state.editingId), state.proxyCheck?.result));
elements.batchLaunch.addEventListener("click", () => batchAction("launch"));
elements.batchStop.addEventListener("click", () => batchAction("stop"));
elements.importButton.addEventListener("click", () => elements.importFile.click());
elements.importFile.addEventListener("change", importProfileFile);
elements.exportButton.addEventListener("click", () => {
  const willOpen = elements.exportMenu.hidden;
  closeMenus(elements.exportMenu);
  elements.exportMenu.hidden = !willOpen;
  elements.exportButton.setAttribute("aria-expanded", String(willOpen));
});
elements.exportMenu.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-export-proxy]");
  if (!button) return;
  exportSelected(button.dataset.exportProxy === "true");
});
elements.selectVisible.addEventListener("change", () => {
  for (const profile of filteredProfiles()) {
    if (elements.selectVisible.checked) state.selected.add(profile.id);
    else state.selected.delete(profile.id);
  }
  render();
});
elements.proxyInput.addEventListener("input", () => {
  state.proxyCheck = null;
  elements.proxyResult.hidden = true;
  elements.proxyChange.textContent = "";
  syncGeoipAvailability();
  updateConsistencyWarnings();
});
elements.clearProxy.addEventListener("change", () => {
  if (elements.clearProxy.checked) {
    elements.lockProxyIp.checked = false;
    state.proxyCheck = null;
    elements.proxyResult.hidden = true;
    renderProxyLockState();
  }
  syncGeoipAvailability();
  updateConsistencyWarnings();
});
elements.location.addEventListener("change", (event) => {
  const timezone = event.target.selectedOptions[0]?.dataset.timezone;
  if (timezone) setTimezoneValue(timezone);
  if (event.target.value && !elements.locale.value) setLocaleValue("en-US");
  updateConsistencyWarnings();
  scheduleFingerprintPreview(250);
});
document.querySelectorAll("[data-close-modal]").forEach((button) => {
  button.addEventListener("click", closeProfileModal);
});
document.querySelectorAll("[data-close-fingerprint]").forEach((button) => {
  button.addEventListener("click", closeFingerprintModal);
});
document.querySelector("#cancelDeleteButton").addEventListener("click", closeDeleteModal);
document.querySelector("#confirmDeleteButton").addEventListener("click", deleteProfile);
elements.form.addEventListener("submit", saveProfile);
elements.rows.addEventListener("click", handleRowAction);
elements.rows.addEventListener("change", (event) => {
  const input = event.target.closest("input[data-profile-select]");
  if (!input) return;
  if (input.checked) state.selected.add(input.dataset.profileSelect);
  else state.selected.delete(input.dataset.profileSelect);
  render();
});
elements.search.addEventListener("input", (event) => {
  state.search = event.target.value;
  render();
});
elements.groupFilter.addEventListener("change", (event) => {
  state.group = event.target.value;
  render();
});
document.querySelector(".segmented").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-filter]");
  if (!button) return;
  state.filter = button.dataset.filter;
  document.querySelectorAll(".segmented button").forEach((item) => item.classList.toggle("active", item === button));
  render();
});
document.addEventListener("click", (event) => {
  if (!event.target.closest(".more-wrap, .export-wrap")) closeMenus();
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  closeMenus();
  if (!elements.confirmModal.hidden) closeDeleteModal();
  else if (!elements.fingerprintModal.hidden) closeFingerprintModal();
  else if (!elements.profileModal.hidden) closeProfileModal();
});
elements.profileModal.addEventListener("click", (event) => {
  if (event.target === elements.profileModal) closeProfileModal();
});
elements.confirmModal.addEventListener("click", (event) => {
  if (event.target === elements.confirmModal) closeDeleteModal();
});
elements.fingerprintModal.addEventListener("click", (event) => {
  if (event.target === elements.fingerprintModal) closeFingerprintModal();
});

initialize();
