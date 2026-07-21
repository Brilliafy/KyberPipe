<script setup lang="ts">
import { ref, onMounted, computed } from "vue";
import { invoke } from "@tauri-apps/api/core";

// Import Refactored Sub-Components
import Sidebar from "./components/Sidebar.vue";
import Dashboard from "./components/Dashboard.vue";
import ClipboardManager from "./components/ClipboardManager.vue";
import NotificationCenter from "./components/NotificationCenter.vue";
import AutomationManager from "./components/AutomationManager.vue";
import SettingsPanel from "./components/SettingsPanel.vue";

interface SystemInfo {
  is_flatpak: boolean;
  platform: string;
  app_version: string;
  pqc_algorithm: String;
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

interface SmsPacket {
  sender: string;
  body: string;
  timestamp: number;
}

interface NotificationPacket {
  title: string;
  text: string;
  app_package: string;
  timestamp: number;
}

const currentTab = ref<"dashboard" | "light" | "clipboard" | "notifications" | "logs" | "settings">("dashboard");

const systemInfo = ref<SystemInfo | null>(null);
const keyPair = ref<KeyPair | null>(null);
const logs = ref<string[]>([]);
const connectionStatus = ref("Ready (Listening on UDP :9876)");
const wifiDirectActive = ref(true);
const lanActive = ref(false);
const resolvedPublicIp = ref("Not Queried");
const pairingConfigJson = ref("");

// Ambient Light Sandbox State
const currentLux = ref(250.0);
const scriptResult = ref<ScriptResult | null>(null);

// Clipboard State
const lastSyncStatus = ref("");
const clipboardItems = ref<string[]>([
  "Secure synchronization token block",
  "Identity public key fingerprint verification hash",
  "Kyberpipe active connection metadata"
]);

const handleAddClipboard = async (text: string) => {
  clipboardItems.value.unshift(text);
  try {
    await invoke("sync_clipboard", { text });
    lastSyncStatus.value = "Synced item to local and remote hosts";
    await refreshLogs();
  } catch (e) {
    lastSyncStatus.value = "Sync warning: " + e;
  }
};

const handleCopyClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    lastSyncStatus.value = "Copied item to system clipboard";
  } catch (e) {
    lastSyncStatus.value = "Copy failed: " + e;
  }
};

const handleRemoveClipboard = (index: number) => {
  clipboardItems.value.splice(index, 1);
  lastSyncStatus.value = "Item removed";
};

const handleSaveEditClipboard = async (payload: { index: number; text: string }) => {
  clipboardItems.value[payload.index] = payload.text;
  try {
    await invoke("sync_clipboard", { text: payload.text });
    lastSyncStatus.value = "Updated and synced item";
    await refreshLogs();
  } catch (e) {
    lastSyncStatus.value = "Update warning: " + e;
  }
};

// Ambient-Adaptive Theme Computed Property
const currentThemeClass = computed(() => {
  const lux = currentLux.value;
  if (lux > 500) return 'theme-daylight';
  if (lux < 5) return 'theme-oled-black';
  return 'theme-cyber-dark';
});

// Optimistic UI Action Dispatcher with Auto-Rollback
const optimisticStatus = ref<string | null>(null);
const sendOptimisticSms = async (payload: { sender: string; body: string }) => {
  const previousState = [...smsList.value];
  optimisticStatus.value = "Outgoing message dispatched";
  
  try {
    smsList.value = await invoke<SmsPacket[]>("push_sms_packet", {
      sender: payload.sender,
      body: payload.body,
      timestamp: Date.now(),
    });
    await refreshLogs();
    setTimeout(() => { optimisticStatus.value = null; }, 2000);
  } catch (e) {
    smsList.value = previousState; // Auto-rollback
    optimisticStatus.value = "Transmission failed (Rolled Back)";
  }
};

const smsList = ref<SmsPacket[]>([]);
const notifList = ref<NotificationPacket[]>([]);

const sasCode = ref("849-201");
const neuralAnomalyEnabled = ref(false); // Off by default
const flightRecorderEnabled = ref(false); // Disabled by default

const handleToggleFlightRecorder = async (val: boolean) => {
  flightRecorderEnabled.value = val;
  try {
    await invoke<string>("toggle_flight_recorder", { enabled: val });
    await refreshLogs();
  } catch (e: any) {
    console.error("Flight recorder error: ", e);
  }
};

const handleToggleNeuralAnomaly = async (val: boolean) => {
  neuralAnomalyEnabled.value = val;
  try {
    await invoke<string>("toggle_neural_anomaly_engine", { enabled: val });
    await refreshLogs();
  } catch (e: any) {
    console.error("Anomaly error: ", e);
  }
};

const triggerSelfDestruct = async () => {
  if (confirm("CRITICAL WARNING: This will zeroize all active cryptographic ratchets and purge hardware keys. Proceed with Emergency Panic Destruction?")) {
    try {
      await invoke<string>("trigger_panic_self_destruct");
      await refreshLogs();
    } catch (e: any) {
      console.error("Self destruct error: ", e);
    }
  }
};

async function loadSystemInfo() {
  try {
    systemInfo.value = await invoke<SystemInfo>("get_system_info");
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
}

async function handleGenerateKeyPair() {
  try {
    keyPair.value = await invoke<KeyPair>("generate_keypair");
    await refreshLogs();
    await loadPairingConfig();
  } catch (e) {
    console.error("Key generation error: ", e);
  }
}

const runStunHolePunch = async (host: string) => {
  try {
    resolvedPublicIp.value = "Querying STUN...";
    const res = await invoke<string>("perform_stun_hole_punch", { stunHost: host });
    resolvedPublicIp.value = res;
    await refreshLogs();
    await updateConnectionStatus();
  } catch (e: any) {
    resolvedPublicIp.value = "Failed: " + e;
    await refreshLogs();
  }
};

const updateConnectionStatus = async () => {
  try {
    const info = await invoke<{
      active_tier: number;
      active_path_description: string;
      latency_ms: number;
      public_endpoint: string;
    }>("evaluate_connection_status", {
      wifiDirectActive: wifiDirectActive.value,
      lanActive: lanActive.value,
      publicEndpoint: resolvedPublicIp.value,
    });
    connectionStatus.value = `Active: ${info.active_path_description} (${info.latency_ms}ms)`;
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
};

const loadPairingConfig = async () => {
  if (!keyPair.value) return;
  try {
    const config = await invoke<{
      host_identity_pk_hex: string;
      local_ip: string;
      wifi_direct_mac: string;
      wireguard_pk_hex: string;
      stun_endpoint: string;
      pairing_nonce_hex: string;
    }>("get_pairing_config", {
      hostPkHex: keyPair.value.mlkem_pk_hex,
      wireguardPkHex: keyPair.value.x25519_pk_hex,
    });
    pairingConfigJson.value = JSON.stringify(config, null, 2);
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
};


async function handleRunScript(code: string) {
  try {
    scriptResult.value = await invoke<ScriptResult>("execute_boa_script", {
      scriptCode: code,
      lux: Number(currentLux.value),
    });
    await refreshLogs();
  } catch (e) {
    console.error("Execution failed: ", e);
  }
}

async function handlePushMockNotification(payload: { title: string; text: string; app: string }) {
  try {
    notifList.value = await invoke<NotificationPacket[]>("push_notification_packet", {
      title: payload.title,
      text: payload.text,
      appPackage: payload.app,
      timestamp: Date.now(),
    });
    await invoke("send_desktop_notification", {
      title: `[Mirrored] ${payload.title}`,
      body: payload.text,
    });
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
}

interface UnifiedNotification {
  id: string;
  source: string;
  title: string;
  body: string;
  appPackage: string;
  timestamp: string;
}

const displayNotifications = computed<UnifiedNotification[]>(() => {
  const list: UnifiedNotification[] = [];
  for (const s of smsList.value) {
    list.push({
      id: `sms_${s.timestamp}`,
      source: "SMS Message",
      title: s.sender,
      body: s.body,
      appPackage: "telephony.sms",
      timestamp: new Date(s.timestamp).toLocaleTimeString(),
    });
  }
  for (const n of notifList.value) {
    list.push({
      id: `notif_${n.timestamp}`,
      source: "App Notification",
      title: n.title,
      body: n.text,
      appPackage: n.app_package,
      timestamp: new Date(n.timestamp).toLocaleTimeString(),
    });
  }
  return list.sort((a, b) => b.id.localeCompare(a.id));
});

async function refreshLogs() {
  try {
    logs.value = await invoke<string[]>("get_app_logs");
  } catch (e) {
    console.error(e);
  }
}

onMounted(async () => {
  await loadSystemInfo();
  await handleGenerateKeyPair();
  await updateConnectionStatus();
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
          <div class="status-badge" :class="{ connected: connectionStatus.includes('Ready') || connectionStatus.includes('Active') }">
            <span class="status-dot"></span>
            {{ connectionStatus }}
          </div>
        </div>

        <div class="header-right">
          <button class="btn btn-secondary btn-sm" style="margin-right: 0.5rem;" @click="currentTab = 'settings'">
            Settings
          </button>
          <button class="btn-panic" @click="triggerSelfDestruct">Self-Destruct Wipe</button>
        </div>
      </header>

      <!-- Sub-Components Render Engine -->
      <Dashboard 
        v-if="currentTab === 'dashboard'" 
        :sasCode="sasCode" 
        :wifiDirectActive="wifiDirectActive"
        :lanActive="lanActive"
        :resolvedPublicIp="resolvedPublicIp"
        :pairingConfigJson="pairingConfigJson"
        @update:wifiDirectActive="wifiDirectActive = $event; updateConnectionStatus()"
        @update:lanActive="lanActive = $event; updateConnectionStatus()"
        @runStunHolePunch="runStunHolePunch"
        @regenerateKeys="handleGenerateKeyPair" 
        @navigate="currentTab = $event as any" 
      />

      <ClipboardManager 
        v-else-if="currentTab === 'clipboard'" 
        :clipboardItems="clipboardItems" 
        :lastSyncStatus="lastSyncStatus"
        @add="handleAddClipboard"
        @copy="handleCopyClipboard"
        @remove="handleRemoveClipboard"
        @saveEdit="handleSaveEditClipboard"
      />

      <NotificationCenter 
        v-else-if="currentTab === 'notifications'" 
        :displayNotifications="displayNotifications" 
        :optimisticStatus="optimisticStatus"
        @sendSms="sendOptimisticSms"
        @sendNotif="handlePushMockNotification"
      />

      <AutomationManager 
        v-else-if="currentTab === 'light'" 
        v-model:currentLux="currentLux"
        :scriptResult="scriptResult"
        @runScript="handleRunScript"
      />

      <section v-else-if="currentTab === 'logs'" class="panel">
        <h2 class="section-title">Real-Time System Log Stream</h2>
        <div class="terminal-box">
          <div v-for="(log, i) in logs" :key="i" class="log-line">
            {{ log }}
          </div>
        </div>
      </section>

      <SettingsPanel 
        v-else-if="currentTab === 'settings'" 
        :flightRecorderEnabled="flightRecorderEnabled"
        :neuralAnomalyEnabled="neuralAnomalyEnabled"
        :keyPair="keyPair"
        @update:flightRecorderEnabled="handleToggleFlightRecorder"
        @update:neuralAnomalyEnabled="handleToggleNeuralAnomaly"
        @regenerateKeys="handleGenerateKeyPair"
      />
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

/* Ambient-Adaptive Theme Overrides */
.app-layout.theme-daylight {
  --bg-dark: #f8fafc;
  --bg-card: #ffffff;
  --border-color: #cbd5e1;
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --accent-cyan: #0284c7;
}

.app-layout.theme-oled-black {
  --bg-dark: #000000;
  --bg-card: #050505;
  --border-color: #262626;
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
}

.app-layout {
  display: flex;
  height: 100vh;
  width: 100vw;
  background: radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.1) 0%, transparent 40%),
              radial-gradient(circle at 90% 80%, rgba(6, 182, 212, 0.1) 0%, transparent 40%);
}

.sidebar {
  width: 260px;
  background: rgba(15, 20, 36, 0.85);
  backdrop-filter: blur(16px);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  padding: 1.5rem 1rem;
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
  background: linear-gradient(90deg, rgba(99, 102, 241, 0.25), rgba(6, 182, 212, 0.15));
  color: #ffffff;
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
  gap: 0.5rem;
  background: rgba(15, 23, 42, 0.6);
  padding: 0.5rem 1rem;
  border-radius: 30px;
  border: 1px solid var(--border-color);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--text-secondary);
}

.status-badge.connected {
  color: #22c55e;
  border-color: rgba(34, 197, 94, 0.3);
}

.status-dot {
  width: 8px;
  height: 8px;
  background: var(--text-secondary);
  border-radius: 50%;
  display: inline-block;
}

.connected .status-dot {
  background: #22c55e;
  box-shadow: 0 0 10px #22c55e;
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

.sas-card {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(6, 182, 212, 0.1));
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
  margin-bottom: 2rem;
}

.sas-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.sas-badge {
  background: rgba(6, 182, 212, 0.2);
  color: var(--accent-cyan);
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 700;
}

.sas-desc {
  font-size: 0.9rem;
  color: var(--text-secondary);
  margin-bottom: 1rem;
}

.sas-code-display {
  font-size: 2.2rem;
  font-weight: 900;
  letter-spacing: 4px;
  color: white;
  font-family: monospace;
}

.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1.5rem;
}

.card {
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
  border-radius: 12px;
  transition: all 0.3s ease;
}

.card:hover {
  border-color: var(--accent-cyan);
  transform: translateY(-2px);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.card-value {
  font-size: 1.4rem;
  font-weight: 800;
  color: white;
  margin-bottom: 0.25rem;
}

.card-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.quick-actions-box {
  background: rgba(15, 23, 42, 0.3);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
}

.button-group {
  display: flex;
  gap: 1rem;
  margin-top: 1rem;
  flex-wrap: wrap;
}

.btn {
  padding: 0.6rem 1.2rem;
  border-radius: 8px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s ease;
  font-size: 0.9rem;
  border: 1px solid transparent;
}

.btn-primary {
  background: var(--accent-indigo);
  color: white;
}

.btn-primary:hover {
  background: #4f46e5;
  box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
}

.btn-secondary {
  background: rgba(148, 163, 184, 0.1);
  color: var(--text-primary);
  border-color: rgba(148, 163, 184, 0.2);
}

.btn-secondary:hover {
  background: rgba(148, 163, 184, 0.2);
}

.btn-accent {
  background: var(--accent-cyan);
  color: #0f172a;
}

.btn-accent:hover {
  background: #0891b2;
  box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
}

.btn-sm {
  padding: 0.4rem 0.8rem;
  font-size: 0.8rem;
}

.editor-section {
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
  margin-bottom: 1.5rem;
}

.input-row {
  display: flex;
  gap: 0.75rem;
  margin-top: 0.5rem;
}

.input-row input {
  flex: 1;
  background: #0f172a;
  color: white;
  border: 1px solid var(--border-color);
  padding: 0.6rem 1rem;
  border-radius: 8px;
  font-size: 0.9rem;
}

.code-editor {
  width: 100%;
  background: #090d16;
  color: #a7f3d0;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1rem;
  font-family: monospace;
  font-size: 0.9rem;
  resize: vertical;
  margin-bottom: 0.75rem;
}

.result-box {
  background: rgba(6, 182, 212, 0.05);
  border: 1px solid rgba(6, 182, 212, 0.2);
  padding: 1.5rem;
  border-radius: 12px;
}

.console-output {
  background: #020617;
  color: #38bdf8;
  padding: 1rem;
  border-radius: 8px;
  font-family: monospace;
  font-size: 0.85rem;
  overflow-x: auto;
  margin-top: 0.5rem;
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

.key-card {
  margin-bottom: 1.5rem;
}

.key-field {
  margin-bottom: 1rem;
}

.code-box {
  width: 100%;
  background: #090d16;
  color: #e2e8f0;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.75rem;
  font-family: monospace;
  font-size: 0.85rem;
  resize: none;
}
</style>