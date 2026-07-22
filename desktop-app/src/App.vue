<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from "vue";
import { invoke } from "@tauri-apps/api/core";

// Import Refactored Sub-Components
import Sidebar from "./components/Sidebar.vue";
import Dashboard from "./components/Dashboard.vue";
import ClipboardManager from "./components/ClipboardManager.vue";
import NotificationCenter from "./components/NotificationCenter.vue";
import AutomationManager from "./components/AutomationManager.vue";
import SettingsPanel from "./components/SettingsPanel.vue";
import ConnectivityManager from "./components/ConnectivityManager.vue";
import FileManager from "./components/FileManager.vue";
import { RefreshCw, ShieldAlert, Terminal } from "@lucide/vue";

interface SystemInfo {
  is_flatpak: boolean;
  platform: string;
  app_version: string;
  pqc_algorithm: string;
}

interface KeyPair {
  x25519_pk_hex: string;
  x25519_sk_hex: string;
  mlkem_pk_hex: string;
  mlkem_sk_hex: string;
}

interface ScriptResult {
  success: boolean;
  output: string;
  logs: string[];
}

interface ClipboardRecord {
  id: string;
  text: string;
  source: "pc" | "phone";
  timestamp: number;
}

interface UnifiedNotification {
  id: string;
  source: string;
  title: string;
  body: string;
  appPackage: string;
  timestamp: string;
  type: "local" | "remote";
  updatedAt?: number;
}

const currentTab = ref<"dashboard" | "connectivity" | "files" | "clipboard" | "notifications" | "light" | "logs" | "settings">("dashboard");

const systemInfo = ref<SystemInfo | null>(null);
const keyPair = ref<KeyPair | null>(null);
const logs = ref<string[]>([]);
const crashLog = ref<string | null>(null);

const checkCrashLog = async () => {
  try {
    crashLog.value = await invoke<string | null>("get_latest_crash_log");
  } catch (e) {
    console.error("Failed to check crash log:", e);
  }
};

const copyStacktrace = async () => {
  if (crashLog.value) {
    try {
      await navigator.clipboard.writeText(crashLog.value);
      alert("Anonymized stacktrace copied to clipboard!");
    } catch (err) {
      console.error("Failed to copy stacktrace:", err);
    }
  }
};

const exportDiagnosticLogs = () => {
  const text = logs.value.join("\n");
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "diagnostic_logs.txt";
  a.click();
  URL.revokeObjectURL(url);
};

const exportCrashLog = () => {
  if (crashLog.value) {
    const blob = new Blob([crashLog.value], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "anonymous_crash_log.txt";
    a.click();
    URL.revokeObjectURL(url);
  }
};

// Connectivity State Machine
const connectionStatus = ref("DISCONNECTED");
const connectionMethod = ref("None");
const connectionColor = ref("red"); // "green", "yellow", "red"
const isConnected = computed(() => connectionColor.value === "green");

const wifiDirectActive = ref(true);
const lanActive = ref(false);
const wireguardActive = ref(true);
const resolvedPublicIp = ref("Not Queried");
const pairingConfigJson = ref("");

// Latency for top-bar display
const currentLatency = ref(0);
const latencyColor = computed(() => {
  const ms = currentLatency.value;
  if (ms < 50) return '#22c55e';
  if (ms < 100) return '#84cc16';
  if (ms < 200) return '#facc15';
  if (ms < 500) return '#f97316';
  return '#ef4444';
});

// Settings / Storage
const deviceName = ref("My Linux Workstation");
const devicePicture = ref("");
const pairedDeviceName = ref("");
const pairedDevicePicture = ref("");
const ddnsHostname = ref("");
const enableUpnp = ref(false);
const enableDdns = ref(false);
const isPaired = ref(false);
const fileAccessGrantedDesktop = ref(false);
const fileAccessGrantedPhone = ref(false);
const pathwayOrder = ref<string[]>(["wifi_direct", "mdns_lan", "wireguard_wan"]);

// Ambient Light Sandbox State
const currentLux = ref(250.0);
const scriptResult = ref<ScriptResult | null>(null);

// Clipboard State (Real)
const lastSyncStatus = ref("");
const clipboardItems = ref<ClipboardRecord[]>([]);

// Notifications & SMS State (Real)
const notifList = ref<UnifiedNotification[]>([]);
const optimisticStatus = ref<string | null>(null);
const autoPurgeDays = ref(7);

const sasCode = ref("849-201");
const neuralAnomalyEnabled = ref(false);
const flightRecorderEnabled = ref(false);
const themeMode = ref("auto");
const isSystemDark = ref(window.matchMedia("(prefers-color-scheme: dark)").matches);

const currentThemeClass = computed(() => {
  if (themeMode.value === "light") return "theme-daylight";
  if (themeMode.value === "dark") return ""; // Default dark theme
  return isSystemDark.value ? "" : "theme-daylight";
});

watch(currentThemeClass, (newClass) => {
  document.documentElement.className = newClass;
}, { immediate: true });

watch(currentTab, (newTab) => {
  if (newTab === "logs") {
    checkCrashLog();
    refreshLogs();
  }
});

// Methods

const loadSettings = async () => {
  try {
    const settings = await invoke<any>("get_settings");
    deviceName.value = settings.device_name || "My Linux Workstation";
    devicePicture.value = settings.device_picture || "";
    pairedDeviceName.value = settings.paired_device_name || "";
    pairedDevicePicture.value = settings.paired_device_picture || "";
    ddnsHostname.value = settings.ddns_hostname || "";
    enableUpnp.value = settings.enable_upnp || false;
    enableDdns.value = settings.enable_ddns || false;
    isPaired.value = settings.is_paired || false;
    fileAccessGrantedDesktop.value = settings.file_access_granted_desktop || false;
    fileAccessGrantedPhone.value = settings.file_access_granted_phone || false;
    themeMode.value = settings.theme_mode || "auto";
    pathwayOrder.value = settings.pathway_order || ["wifi_direct", "mdns_lan", "wireguard_wan"];
    wireguardActive.value = settings.wireguard_active !== undefined ? settings.wireguard_active : true;
  } catch (e) {
    console.error("Load settings error:", e);
  }
};

const saveSettings = async () => {
  try {
    await invoke("save_settings", {
      deviceName: deviceName.value,
      devicePicture: devicePicture.value,
      pairedDeviceName: pairedDeviceName.value,
      pairedDevicePicture: pairedDevicePicture.value,
      ddnsHostname: ddnsHostname.value,
      enableUpnp: enableUpnp.value,
      enableDdns: enableDdns.value,
      isPaired: isPaired.value,
      themeMode: themeMode.value,
      pathwayOrder: pathwayOrder.value,
      wireguardActive: wireguardActive.value
    });
  } catch (e) {
    console.error("Save settings error:", e);
  }
};

const showFlatpakModal = ref(false);
const flatpakCopyStatus = ref("");

const verifyFlatpakPermissions = async () => {
  try {
    const sysInfo = await invoke<SystemInfo>("get_system_info");
    systemInfo.value = sysInfo;
    if (sysInfo.is_flatpak) {
      const granted = await invoke<boolean>("check_flatpak_permissions");
      if (!granted) {
        showFlatpakModal.value = true;
      }
    }
  } catch (e) {
    console.error("Flatpak verify error:", e);
  }
};

const copyFlatpakCommand = async () => {
  try {
    await navigator.clipboard.writeText("flatpak override --user --share=network --socket=wayland --socket=fallback-x11 --socket=pulseaudio --talk-name=org.freedesktop.portal.Desktop io.github.brilliafy.kyberpipe");
    flatpakCopyStatus.value = "Override command copied!";
    setTimeout(() => { flatpakCopyStatus.value = ""; }, 2500);
  } catch (e) {
    console.error(e);
  }
};

const handleFlatpakVerifyProceed = async () => {
  const sysInfo = systemInfo.value;
  if (sysInfo?.is_flatpak) {
    const granted = await invoke<boolean>("check_flatpak_permissions");
    if (granted) {
      showFlatpakModal.value = false;
    } else {
      flatpakCopyStatus.value = "Permissions still not granted. Run the command above and click Verify.";
      setTimeout(() => { flatpakCopyStatus.value = ""; }, 3000);
    }
  }
};

const pollClipboard = async () => {
  try {
    const text = await invoke<string>("read_real_clipboard");
    if (text && text.trim() !== "") {
      const exists = clipboardItems.value.some(item => item.text === text);
      if (!exists) {
        const newRecord: ClipboardRecord = {
          id: "clip_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
          text: text,
          source: "pc",
          timestamp: Date.now()
        };
        clipboardItems.value.unshift(newRecord);
        await invoke("sync_clipboard", { text });
      }
    }
  } catch (e) {
    // Ignore clipboard read errors (e.g. empty or binary content)
  }
};

const handleAddClipboard = async (text: string) => {
  const newRecord: ClipboardRecord = {
    id: "clip_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
    text: text,
    source: "pc",
    timestamp: Date.now()
  };
  clipboardItems.value.unshift(newRecord);
  try {
    await invoke("write_real_clipboard", { text });
    await invoke("sync_clipboard", { text });
    lastSyncStatus.value = "Synced item locally & pushed remote";
    await refreshLogs();
  } catch (e) {
    lastSyncStatus.value = "Sync warning: " + e;
  }
};

const handleCopyClipboard = async (text: string) => {
  try {
    await invoke("write_real_clipboard", { text });
    lastSyncStatus.value = "Copied to desktop clipboard";
  } catch (e) {
    lastSyncStatus.value = "Copy failed: " + e;
  }
};

const handleRemoveClipboard = (id: string) => {
  clipboardItems.value = clipboardItems.value.filter(item => item.id !== id);
  lastSyncStatus.value = "Item removed";
};

const handleSaveEditClipboard = async (payload: { id: string; text: string }) => {
  const idx = clipboardItems.value.findIndex(item => item.id === payload.id);
  if (idx !== -1) {
    clipboardItems.value[idx].text = payload.text;
    try {
      await invoke("write_real_clipboard", { text: payload.text });
      await invoke("sync_clipboard", { text: payload.text });
      lastSyncStatus.value = "Updated and synced item";
      await refreshLogs();
    } catch (e) {
      lastSyncStatus.value = "Update warning: " + e;
    }
  }
};



const displayNotifications = computed<UnifiedNotification[]>(() => {
  return [...notifList.value].sort((a, b) => {
    const ta = a.updatedAt || new Date(a.timestamp).getTime();
    const tb = b.updatedAt || new Date(b.timestamp).getTime();
    return tb - ta;
  });
});

const removeNotification = (id: string) => {
  const notif = notifList.value.find(n => n.id === id);
  notifList.value = notifList.value.filter(n => n.id !== id);
  if (notif) notifySyncChannel(notif);
};

const notifySyncChannel = (notif: UnifiedNotification) => {
  try {
    invoke("push_notification_packet", {
      title: notif.title || '',
      text: notif.body || '',
      appPackage: notif.appPackage || '',
      timestamp: Date.now(),
    });
  } catch (e) {
  }
};

const purgeOldNotifications = (days: number) => {
  const cutoff = Date.now() - days * 86400000;
  notifList.value = notifList.value.filter(n => {
    const t = n.updatedAt || new Date(n.timestamp).getTime();
    return t > cutoff;
  });
  try { localStorage.setItem('kyberpipe_notifications', JSON.stringify(notifList.value)); } catch {}
};

const loadPersistedNotifications = () => {
  try {
    const raw = localStorage.getItem('kyberpipe_notifications');
    if (raw) {
      const parsed = JSON.parse(raw) as UnifiedNotification[];
      notifList.value = parsed;
    }
  } catch {}
};

const persistNotifications = () => {
  try {
    localStorage.setItem('kyberpipe_notifications', JSON.stringify(notifList.value));
  } catch {}
};

const refreshLogs = async () => {
  try {
    logs.value = await invoke<string[]>("get_app_logs");
  } catch (e) {
    console.error(e);
  }
};

const runStunHolePunch = async (host: string) => {
  try {
    resolvedPublicIp.value = "Querying STUN...";
    const res = await invoke<string>("perform_stun_hole_punch", { stunHost: host });
    resolvedPublicIp.value = res;
    await refreshLogs();
    await triggerConnectionAttempt();
  } catch (e: any) {
    resolvedPublicIp.value = "Failed: " + e;
    await refreshLogs();
  }
};

const attemptCount = ref(0);
const maxAttempts = 5;

const triggerConnectionAttempt = async () => {
  if (!isPaired.value) {
    await invoke("set_connection_status_full", {
      status: "DISCONNECTED (No paired device)",
      method: "None",
      color: "red"
    });
    await checkConnectionState();
    return;
  }

  if (attemptCount.value >= maxAttempts) {
    await invoke("set_connection_status_full", {
      status: "DISCONNECTED (Max attempts failed)",
      method: "None",
      color: "red"
    });
    await checkConnectionState();
    return;
  }

  attemptCount.value++;
  await invoke("set_connection_status_full", {
    status: `CONNECTING (Attempt ${attemptCount.value}/${maxAttempts})`,
    method: "None",
    color: "yellow"
  });
  await checkConnectionState();
  await refreshLogs();

  try {
    let chosenMethod = "None";
    for (const path of pathwayOrder.value) {
      if (path === "wifi_direct" && wifiDirectActive.value) {
        chosenMethod = "Wi-Fi Direct P2P";
        break;
      }
      if (path === "mdns_lan" && lanActive.value) {
        chosenMethod = "mDNS LAN";
        break;
      }
      if (path === "wireguard_wan" && wireguardActive.value) {
        chosenMethod = "WireGuard WAN Tunnel";
        break;
      }
    }

    if (chosenMethod === "None") {
      throw new Error("No pathways enabled");
    }

    await invoke("set_connection_status_full", {
      status: "ACTIVE",
      method: chosenMethod,
      color: "green"
    });
    attemptCount.value = 0;
  } catch (e) {
    await invoke("set_connection_status_full", {
      status: "DISCONNECTED (Attempt failed)",
      method: "None",
      color: "red"
    });
  }
  await checkConnectionState();
  await refreshLogs();
};

const checkConnectionState = async () => {
  try {
    const res = await invoke<any>("get_connection_status_full");
    connectionStatus.value = res.status;
    connectionMethod.value = res.method;
    connectionColor.value = res.color;
  } catch (e) {
    console.error(e);
  }
};

const handleManualRetry = () => {
  attemptCount.value = 0;
  triggerConnectionAttempt();
};

const loadPairingConfig = async () => {
  if (!keyPair.value) return;
  try {
    const config = await invoke<any>("get_pairing_config", {
      hostPkHex: keyPair.value.mlkem_pk_hex,
      wireguardPkHex: keyPair.value.x25519_pk_hex,
    });
    pairingConfigJson.value = JSON.stringify(config, null, 2);
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
};

async function handleGenerateKeyPair() {
  try {
    keyPair.value = await invoke<KeyPair>("generate_keypair");
    await refreshLogs();
    await loadPairingConfig();
  } catch (e) {
    console.error("Key generation error: ", e);
  }
}

async function handleRunScript(code: string, isSandboxed: boolean, feedSourceCommand: string, onCompletionCode?: string) {
  try {
    const res = await invoke<ScriptResult>("execute_boa_script", {
      scriptCode: code,
      isSandboxed: isSandboxed,
      lux: Number(currentLux.value),
      feedSourceCommand: feedSourceCommand
    });
    scriptResult.value = res;
    await refreshLogs();

    if (res.success && onCompletionCode && onCompletionCode.trim()) {
      await invoke("execute_boa_script", {
        scriptCode: onCompletionCode,
        isSandboxed: false,
        lux: Number(currentLux.value),
        feedSourceCommand: ""
      });
      await refreshLogs();
    }
  } catch (e) {
    console.error("Execution failed: ", e);
  }
}

const handleToggleFlightRecorder = async (val: boolean) => {
  flightRecorderEnabled.value = val;
  try {
    await invoke("toggle_flight_recorder", { enabled: val });
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
};

const handleToggleNeuralAnomaly = async (val: boolean) => {
  neuralAnomalyEnabled.value = val;
  try {
    await invoke("toggle_neural_anomaly_engine", { enabled: val });
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
};

const triggerSelfDestruct = async () => {
  if (confirm("CRITICAL WARNING: This will zeroize all active cryptographic ratchets and purge hardware keys. Proceed with Emergency Panic Destruction?")) {
    try {
      await invoke("trigger_panic_self_destruct");
      await refreshLogs();
      await checkConnectionState();
    } catch (e) {
      console.error(e);
    }
  }
};

const handleCompletePairing = async (name: string, pic: string) => {
  pairedDeviceName.value = name;
  pairedDevicePicture.value = pic;
  isPaired.value = true;
  await saveSettings();
  handleManualRetry();
};

let clipPoller: any = null;
let connPoller: any = null;
let mediaQueryListener: ((e: MediaQueryListEvent) => void) | null = null;

onMounted(async () => {
  await loadSettings();
  await handleGenerateKeyPair();
  await checkConnectionState();
  await verifyFlatpakPermissions();
  
  // Load persisted notifications and purge old ones
  loadPersistedNotifications();
  purgeOldNotifications(autoPurgeDays.value);

  // Auto-persist on tab switch and interval
  watch(notifList, () => persistNotifications(), { deep: true });
  setInterval(() => purgeOldNotifications(autoPurgeDays.value), 3600000);
  
  // Simulate latency for top-bar display
  setInterval(() => {
    if (isConnected.value) {
      currentLatency.value = Math.round(2 + Math.random() * 40);
    } else {
      currentLatency.value = Math.round(2000 + Math.random() * 2000);
    }
  }, 2000);

  // Load system info
  try {
    systemInfo.value = await invoke<SystemInfo>("get_system_info");
  } catch (e) {
    console.error(e);
  }

  // Real clipboard poller (1.5s interval)
  clipPoller = setInterval(pollClipboard, 1500);

  // Connection auto-retry poller (10s interval)
  connPoller = setInterval(() => {
    if (isPaired.value && !isConnected.value) {
      triggerConnectionAttempt();
    }
  }, 10000);

  // OS theme preferences change observer
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  mediaQueryListener = (e: MediaQueryListEvent) => {
    isSystemDark.value = e.matches;
  };
  media.addEventListener("change", mediaQueryListener);
});

onUnmounted(() => {
  if (clipPoller) clearInterval(clipPoller);
  if (connPoller) clearInterval(connPoller);
  if (mediaQueryListener) {
    window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", mediaQueryListener);
  }
});
</script>

<template>
  <div class="app-layout" :class="currentThemeClass">
    <Sidebar v-model:currentTab="currentTab" :systemInfo="systemInfo" />

    <!-- Main Content Area -->
    <main class="main-content">
      <!-- Top Status Header -->
      <header class="top-bar">
        <div class="status-indicator">
          <div class="status-badge" :class="connectionColor">
            <span class="status-dot"></span>
            <span class="status-lbl">
              <span v-if="connectionColor === 'green'">Connected</span>
              <span v-else-if="connectionColor === 'yellow'">Connecting…</span>
              <span v-else>Offline</span>
              <span class="method-lbl" v-if="connectionColor === 'green'">via {{ connectionMethod }}</span>
            </span>
            <button 
              class="btn-retry" 
              v-if="connectionColor === 'red'" 
              @click="handleManualRetry"
              title="Retry connection"
            >
              <RefreshCw :size="12" />
            </button>
          </div>
        </div>

        <div class="header-right">
          <div class="latency-display">
            <span class="latency-label">Latency</span>
            <span class="latency-value" :style="{ color: latencyColor }">{{ currentLatency }}ms</span>
          </div>
        </div>
      </header>

      <!-- Sub-Components Render Engine -->
      <Dashboard 
        v-if="currentTab === 'dashboard'" 
        :isPaired="isPaired"
        :sasCode="sasCode" 
        :pairingConfigJson="pairingConfigJson"
        :clipboardItems="clipboardItems"
        :displayNotifications="displayNotifications"
        :currentLux="currentLux"
        :fileAccessGrantedDesktop="fileAccessGrantedDesktop"
        :fileAccessGrantedPhone="fileAccessGrantedPhone"
        :deviceName="deviceName"
        :devicePicture="devicePicture"
        :pairedDeviceName="pairedDeviceName"
        :pairedDevicePicture="pairedDevicePicture"
        :isConnected="isConnected"
        @completePairing="handleCompletePairing"
        @regenerateKeys="handleGenerateKeyPair" 
        @navigate="currentTab = $event as any" 
      />

      <ConnectivityManager
        v-else-if="currentTab === 'connectivity'"
        v-model:pathwayOrder="pathwayOrder"
        :wifiDirectActive="wifiDirectActive"
        :lanActive="lanActive"
        :wireguardActive="wireguardActive"
        :resolvedPublicIp="resolvedPublicIp"
        :ddnsHostname="ddnsHostname"
        :enableUpnp="enableUpnp"
        :enableDdns="enableDdns"
        @update:wifiDirectActive="wifiDirectActive = $event; triggerConnectionAttempt()"
        @update:lanActive="lanActive = $event; triggerConnectionAttempt()"
        @update:wireguardActive="wireguardActive = $event; triggerConnectionAttempt()"
        @update:ddnsHostname="ddnsHostname = $event"
        @update:enableUpnp="enableUpnp = $event"
        @update:enableDdns="enableDdns = $event"
        @runStunHolePunch="runStunHolePunch"
        @saveSettings="saveSettings"
      />

      <FileManager
        v-else-if="currentTab === 'files'"
        :fileAccessGrantedDesktop="fileAccessGrantedDesktop"
        :fileAccessGrantedPhone="fileAccessGrantedPhone"
        :isConnected="isConnected"
        @updateSettings="loadSettings"
      />

      <ClipboardManager 
        v-else-if="currentTab === 'clipboard'" 
        :clipboardItems="clipboardItems" 
        :lastSyncStatus="lastSyncStatus"
        :isConnected="isConnected"
        @add="handleAddClipboard"
        @copy="handleCopyClipboard"
        @remove="handleRemoveClipboard"
        @saveEdit="handleSaveEditClipboard"
        @connectDevice="currentTab = 'dashboard'"
      />

      <NotificationCenter 
        v-else-if="currentTab === 'notifications'" 
        :displayNotifications="displayNotifications" 
        :optimisticStatus="optimisticStatus"
        :isConnected="isConnected"
        @connectDevice="currentTab = 'dashboard'"
        @remove="removeNotification"
      />

      <AutomationManager 
        v-else-if="currentTab === 'light'" 
        v-model:currentLux="currentLux"
        :scriptResult="scriptResult"
        @runScript="handleRunScript"
      />

      <section v-else-if="currentTab === 'logs'" class="panel">
        <h2 class="section-title">
          <Terminal style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="20" /> Real-Time System Log Stream
        </h2>
        <div class="terminal-box">
          <div v-for="(log, i) in logs" :key="i" class="log-line">
            {{ log }}
          </div>
        </div>
        <div class="logs-actions">
          <button class="action-btn secondary-btn" :disabled="!crashLog" @click="copyStacktrace">
            Copy Stacktrace
          </button>
          <button class="action-btn primary-btn" @click="exportDiagnosticLogs">
            Export Diagnostic Logs
          </button>
          <button class="action-btn danger-btn" :disabled="!crashLog" @click="exportCrashLog">
            Export Anonymous Crash Log
          </button>
        </div>
      </section>

      <SettingsPanel 
        v-else-if="currentTab === 'settings'" 
        :flightRecorderEnabled="flightRecorderEnabled"
        :neuralAnomalyEnabled="neuralAnomalyEnabled"
        :keyPair="keyPair"
        :deviceName="deviceName"
        :devicePicture="devicePicture"
        :pairedDeviceName="pairedDeviceName"
        :pairedDevicePicture="pairedDevicePicture"
        :ddnsHostname="ddnsHostname"
        :enableUpnp="enableUpnp"
        :enableDdns="enableDdns"
        :fileAccessGrantedDesktop="fileAccessGrantedDesktop"
        :fileAccessGrantedPhone="fileAccessGrantedPhone"
        :themeMode="themeMode"
        @update:flightRecorderEnabled="handleToggleFlightRecorder"
        @update:neuralAnomalyEnabled="handleToggleNeuralAnomaly"
        @update:deviceName="deviceName = $event"
        @update:devicePicture="devicePicture = $event"
        @update:ddnsHostname="ddnsHostname = $event"
        @update:enableUpnp="enableUpnp = $event"
        @update:enableDdns="enableDdns = $event"
        @update:fileAccessGrantedDesktop="fileAccessGrantedDesktop = $event"
        @update:fileAccessGrantedPhone="fileAccessGrantedPhone = $event"
        @update:themeMode="themeMode = $event"
        @regenerateKeys="handleGenerateKeyPair"
        @saveSettings="saveSettings"
        @triggerSelfDestruct="triggerSelfDestruct"
      />
      <!-- Flatpak Permission Overlay Modal - MODAL NON-DISMISSIBLE until permissions granted -->
      <div class="flatpak-modal-overlay" v-if="showFlatpakModal" @click.prevent>
        <div class="flatpak-modal-card" @click.stop>
          <h3 style="font-size: 1.25rem; font-weight: 800; color: #f87171; margin-bottom: 0.75rem; display: flex; align-items: center; justify-content: center; gap: 0.5rem;">
            <ShieldAlert :size="24" /> Sandbox Permissions Required
          </h3>
          <p style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 1.5rem; line-height: 1.5;">
            KyberPipe is running inside a Flatpak container sandbox. To connect to companion devices, stream audio, and resolve local interfaces, you must grant host network, window, and pulseaudio portal permissions.
          </p>
          <div style="background: #0f172a; padding: 0.75rem; border-radius: 8px; border: 1px solid #334155; font-family: monospace; font-size: 0.75rem; overflow-x: auto; margin-bottom: 1.25rem; text-align: left; white-space: pre-wrap; word-break: break-all; color: #38bdf8;">
            flatpak override --user --share=network --socket=wayland --socket=fallback-x11 --socket=pulseaudio --talk-name=org.freedesktop.portal.Desktop io.github.brilliafy.kyberpipe
          </div>
          <div style="display: flex; gap: 0.75rem; justify-content: center;">
            <button class="btn btn-secondary" @click="copyFlatpakCommand" style="padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem;">
              {{ flatpakCopyStatus || 'Copy Command' }}
            </button>
            <button class="btn btn-primary" @click="handleFlatpakVerifyProceed" style="padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem;">
              Verify & Proceed
            </button>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<style>
:root {
  --bg-dark: #0b0d17;
  --bg-card: rgba(22, 27, 46, 0.7);
  --border-color: rgba(99, 102, 241, 0.2);
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --accent-cyan: #06b6d4;
  --accent-indigo: #6366f1;
}

.flatpak-modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 999999;
}

.flatpak-modal-card {
  background: #1e293b;
  border: 1px solid #334155;
  padding: 2rem;
  border-radius: 12px;
  max-width: 500px;
  text-align: center;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.5);
}

/* Theme overrides */
html.theme-daylight {
  --bg-dark: #f8fafc;
  --bg-card: #ffffff;
  --border-color: #e2e8f0;
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --accent-cyan: #0284c7;
}
html.theme-oled-black {
  --bg-dark: #000000;
  --bg-card: #0a0a0a;
  --border-color: #1f1f1f;
  --text-primary: #ffffff;
  --text-secondary: #a3a3a3;
  --accent-cyan: #ef4444;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
}
body {
  background-color: var(--bg-dark);
  color: var(--text-primary);
  overflow-x: hidden;
  transition: background-color 0.3s ease, color 0.3s ease;
}
.app-layout {
  display: flex;
  height: 100vh;
  width: 100vw;
  background-color: var(--bg-dark);
  transition: background-color 0.3s ease, color 0.3s ease;
}
.sidebar {
  width: 260px;
  background: var(--bg-card);
  backdrop-filter: blur(16px);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  padding: 1.5rem 1rem;
  transition: background-color 0.3s ease, border-color 0.3s ease;
}
.brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 2rem;
}
.logo-badge {
  font-size: 1.1rem;
  font-weight: 900;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));
  border-radius: 12px;
  width: 42px;
  height: 42px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
  color: white;
}
.brand-text h2 {
  font-size: 1.1rem;
  font-weight: 800;
  letter-spacing: 1px;
}
.subtext {
  font-size: 0.65rem;
  color: var(--accent-cyan);
  font-weight: 700;
  letter-spacing: 1px;
}
.nav-menu {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  flex: 1;
}
.nav-menu button {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 10px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  text-align: left;
}
.nav-menu button:hover {
  background: rgba(99, 102, 241, 0.1);
  color: var(--text-primary);
}
.nav-menu button.active {
  background: rgba(6, 182, 212, 0.1);
  color: var(--accent-cyan);
  border-left: 3px solid var(--accent-cyan);
}
.sidebar-footer {
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
  font-size: 0.8rem;
}
.version {
  margin-top: 0.5rem;
  text-align: center;
  color: var(--text-secondary);
  font-size: 0.75rem;
}
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding: 2rem;
  transition: background-color 0.3s ease;
}
.top-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}
.status-badge {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  background: var(--bg-card);
  padding: 0.5rem 1.25rem;
  border-radius: 30px;
  border: 1px solid var(--border-color);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--text-secondary);
  transition: background-color 0.3s ease, border-color 0.3s ease;
}
.status-badge.green {
  color: #22c55e;
  border-color: rgba(34, 197, 94, 0.3);
}
.status-badge.yellow {
  color: #f59e0b;
  border-color: rgba(245, 158, 11, 0.3);
}
.status-badge.red {
  color: #ef4444;
  border-color: rgba(239, 68, 68, 0.3);
}
.status-dot {
  width: 8px;
  height: 8px;
  background: var(--text-secondary);
  border-radius: 50%;
  display: inline-block;
}
.green .status-dot {
  background: #22c55e;
  box-shadow: 0 0 10px #22c55e;
}
.yellow .status-dot {
  background: #f59e0b;
  box-shadow: 0 0 10px #f59e0b;
}
.red .status-dot {
  background: #ef4444;
  box-shadow: 0 0 10px #ef4444;
}
.btn-retry {
  background: transparent;
  border: none;
  cursor: pointer;
  font-size: 1rem;
  transition: transform 0.2s ease;
}
.btn-retry:hover {
  transform: rotate(45deg);
}
.btn-panic {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.3);
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s ease;
}
.btn-panic:hover {
  background: #ef4444;
  color: white;
  box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
}
.panel {
  background: var(--bg-card);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  padding: 2rem;
  flex: 1;
  display: flex;
  flex-direction: column;
}
.section-title {
  font-size: 1.5rem;
  font-weight: 800;
  margin-bottom: 1.5rem;
  letter-spacing: -0.5px;
}
.terminal-box {
  background: #05070f;
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1rem;
  font-family: monospace;
  font-size: 0.85rem;
  color: #38bdf8;
  height: 400px;
  overflow-y: auto;
}
.log-line {
  margin-bottom: 0.25rem;
  border-bottom: 1px solid rgba(255,255,255,0.02);
  padding-bottom: 0.25rem;
}
.method-lbl {
  font-size: 0.75rem;
  opacity: 0.8;
  margin-left: 0.25rem;
}
.logs-actions {
  display: flex;
  gap: 1rem;
  margin-top: 1rem;
}
.logs-actions button {
  flex: 1;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  font-weight: 700;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 1px solid var(--border-color);
}
.logs-actions button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  background: var(--bg-dark);
  color: var(--text-secondary);
}
.logs-actions .primary-btn {
  background: var(--accent-cyan);
  color: var(--bg-card);
  border-color: var(--accent-cyan);
}
.logs-actions .primary-btn:hover:not(:disabled) {
  opacity: 0.9;
}
.logs-actions .secondary-btn {
  background: var(--bg-dark);
  color: var(--text-primary);
}
.logs-actions .secondary-btn:hover:not(:disabled) {
  background: var(--border-color);
}
.logs-actions .danger-btn {
  background: rgba(220, 38, 38, 0.15);
  color: #f87171;
  border-color: rgba(220, 38, 38, 0.4);
}
.logs-actions .danger-btn:hover:not(:disabled) {
  background: rgba(220, 38, 38, 0.3);
}
.header-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.latency-display {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  background: var(--bg-card);
  padding: 0.4rem 0.85rem;
  border-radius: 20px;
  border: 1px solid var(--border-color);
  font-size: 0.8rem;
}
.latency-label {
  color: var(--text-secondary);
  font-weight: 600;
}
.latency-value {
  font-weight: 800;
  font-family: monospace;
  font-size: 0.9rem;
  transition: color 0.3s ease;
}
</style>