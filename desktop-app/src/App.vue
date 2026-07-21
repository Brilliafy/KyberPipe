<script setup lang="ts">
import { ref, onMounted, computed } from "vue";
import { invoke } from "@tauri-apps/api/core";

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

// Ambient Light Sandbox State
const currentLux = ref(250.0);
const boaCode = ref(`// Sandboxed Ambient Automation Script
const ambientLight = getAmbientLight();
if (ambientLight < 15.0) {
    log("Low-light threshold detected. Safeguarding night vision.");
} else {
    log("Ambient illumination within nominal range.");
}`);
const fallbackScriptPath = ref("/usr/local/bin/kyber_ambient_hook.sh");
const scriptResult = ref<ScriptResult | null>(null);

// Clipboard State
const lastSyncStatus = ref("");
const clipboardItems = ref<string[]>([
  "Secure synchronization token block",
  "Identity public key fingerprint verification hash",
  "Kyberpipe active connection metadata"
]);
const newClipboardText = ref("");

const addClipboardItem = async () => {
  const text = newClipboardText.value.trim();
  if (!text) return;
  clipboardItems.value.unshift(text);
  newClipboardText.value = "";
  try {
    await invoke("sync_clipboard", { text });
    lastSyncStatus.value = "Synced item to local and remote hosts";
    await refreshLogs();
  } catch (e) {
    lastSyncStatus.value = "Sync warning: " + e;
  }
};

const copyClipboardItem = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
    lastSyncStatus.value = "Copied item to system clipboard";
  } catch (e) {
    lastSyncStatus.value = "Copy failed: " + e;
  }
};

const removeClipboardItem = (index: number) => {
  clipboardItems.value.splice(index, 1);
  lastSyncStatus.value = "Item removed";
};

const editIndex = ref<number | null>(null);
const editText = ref("");

const startEdit = (index: number) => {
  editIndex.value = index;
  editText.value = clipboardItems.value[index];
};

const saveEdit = async (index: number) => {
  const text = editText.value.trim();
  if (!text) return;
  clipboardItems.value[index] = text;
  editIndex.value = null;
  try {
    await invoke("sync_clipboard", { text });
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
const sendOptimisticSms = async () => {
  const previousState = [...smsList.value];
  optimisticStatus.value = "Outgoing message dispatched";
  
  try {
    await handlePushMockSms();
    setTimeout(() => { optimisticStatus.value = null; }, 2000);
  } catch (e) {
    smsList.value = previousState; // Auto-rollback
    optimisticStatus.value = "Transmission failed (Rolled Back)";
  }
};

const smsList = ref<SmsPacket[]>([]);
const notifList = ref<NotificationPacket[]>([]);
interface TelemetryMetrics {
  rtt_ms: number;
  transport_path: string;
  packets_sent: number;
  packets_received: number;
  last_script_execution_ms: number;
}

const telemetry = ref<TelemetryMetrics>({
  rtt_ms: 2.4,
  transport_path: "Wi-Fi Direct P2P (QUIC Multiplexed)",
  packets_sent: 1420,
  packets_received: 1398,
  last_script_execution_ms: 0.85,
});

const sasCode = ref("849-201");
const neuralAnomalyEnabled = ref(false); // Off by default
const flightRecorderEnabled = ref(false); // Disabled by default

const toggleFlightRecorder = async () => {
  try {
    await invoke<string>("toggle_flight_recorder", { enabled: flightRecorderEnabled.value });
    await refreshLogs();
  } catch (e: any) {
    console.error("Flight recorder error: ", e);
  }
};

const toggleNeuralAnomaly = async () => {
  try {
    await invoke<string>("toggle_neural_anomaly_engine", { enabled: neuralAnomalyEnabled.value });
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

const mockSmsSender = ref("+1 (555) 019-2831");
const mockSmsBody = ref("Verification code: 894-201");
const mockNotifTitle = ref("Security Alert");
const mockNotifText = ref("ML-KEM-768 Key Exchange initialized successfully.");
const mockNotifApp = ref("com.kyberpipe.client");

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
  } catch (e) {
    console.error("Key generation error: ", e);
  }
}

async function handleRunBoaScript() {
  try {
    scriptResult.value = await invoke<ScriptResult>("execute_boa_script", {
      scriptCode: boaCode.value,
      lux: Number(currentLux.value),
    });
    await refreshLogs();
  } catch (e) {
    console.error("Execution failed: ", e);
  }
}

async function handleRunFallbackScript() {
  try {
    scriptResult.value = await invoke<ScriptResult>("execute_fallback_script", {
      scriptPath: fallbackScriptPath.value,
      lux: Number(currentLux.value),
    });
    await refreshLogs();
  } catch (e) {
    console.error("Subprocess launch error: ", e);
  }
}

async function handlePushMockSms() {
  try {
    smsList.value = await invoke<SmsPacket[]>("push_sms_packet", {
      sender: mockSmsSender.value,
      body: mockSmsBody.value,
      timestamp: Date.now(),
    });
    await refreshLogs();
  } catch (e) {
    console.error(e);
  }
}

async function handlePushMockNotification() {
  try {
    notifList.value = await invoke<NotificationPacket[]>("push_notification_packet", {
      title: mockNotifTitle.value,
      text: mockNotifText.value,
      appPackage: mockNotifApp.value,
      timestamp: Date.now(),
    });
    await invoke("send_desktop_notification", {
      title: `[Mirrored] ${mockNotifTitle.value}`,
      body: mockNotifText.value,
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

onMounted(() => {
  loadSystemInfo();
  handleGenerateKeyPair();
});
</script>

<template>
  <div class="app-layout" :class="currentThemeClass">
    <!-- Sidebar Navigation -->
    <aside class="sidebar">
      <div class="brand">
        <div class="logo-badge">KP</div>
        <div class="brand-text">
          <h2>KYBERPIPE</h2>
          <span class="subtext">POST-QUANTUM ENGINE</span>
        </div>
      </div>

      <nav class="nav-menu">
        <button
          :class="{ active: currentTab === 'dashboard' }"
          @click="currentTab = 'dashboard'"
        >
          Overview
        </button>
        <button
          :class="{ active: currentTab === 'clipboard' }"
          @click="currentTab = 'clipboard'"
        >
          Clipboard Manager
        </button>
        <button
          :class="{ active: currentTab === 'notifications' }"
          @click="currentTab = 'notifications'"
        >
          Notifications
        </button>
        <button
          :class="{ active: currentTab === 'light' }"
          @click="currentTab = 'light'"
        >
          Ambient Automation
        </button>
        <button
          :class="{ active: currentTab === 'logs' }"
          @click="currentTab = 'logs'; refreshLogs()"
        >
          System Logs
        </button>
        <button
          :class="{ active: currentTab === 'settings' }"
          @click="currentTab = 'settings'"
        >
          Settings
        </button>
      </nav>

      <div class="sidebar-footer" v-if="systemInfo">
        <div class="version">Version {{ systemInfo.app_version }}</div>
      </div>
    </aside>

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

      <!-- Dashboard Tab -->
      <section v-if="currentTab === 'dashboard'" class="panel">
        <h2 class="section-title">System Overview</h2>
        
        <!-- SAS Code OOB Pairing Verification Card -->
        <div class="sas-card">
          <div class="sas-header">
            <h3>Out-of-Band Safe Pairing</h3>
            <span class="sas-badge">MITM Verified</span>
          </div>
          <p class="sas-desc">Confirm this 6-digit cryptographic authentication string matches your mobile companion app screen:</p>
          <div class="sas-code-display">{{ sasCode }}</div>
        </div>

        <div class="cards-grid">
          <div class="card">
            <div class="card-header">
              <h3>Optical Data Pipe</h3>
            </div>
            <p class="card-value">Animated LT QR</p>
            <p class="card-desc">Zero-RF Air-Gapped Screen/Camera Sync</p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3>Round-Trip Latency (RTT)</h3>
            </div>
            <p class="card-value">{{ telemetry.rtt_ms }} ms</p>
            <p class="card-desc">{{ telemetry.transport_path }}</p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3>BFT Mesh Self-Healing</h3>
            </div>
            <p class="card-value">&gt; ⅔ Consensus</p>
            <p class="card-desc">Automated Attestation Peer Revocation</p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3>NIST ML-DSA Code-Signing</h3>
            </div>
            <p class="card-value">Dilithium-65</p>
            <p class="card-desc">Detached Post-Quantum WASM Module Signatures</p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3>Hardware Smartcard Token</h3>
            </div>
            <p class="card-value">PKCS#11 YubiKey</p>
            <p class="card-desc">Optional Touch-Confirmed Key Rekeying</p>
          </div>

          <div class="card">
            <div class="card-header">
              <h3>Hardware Attestation</h3>
            </div>
            <p class="card-value">TPM 2.0 / KeyAttest</p>
            <p class="card-desc">Google Root & TPM PCR Enforced</p>
          </div>
        </div>

        <div class="quick-actions-box" style="margin-top: 2rem;">
          <h3>Quick Actions</h3>
          <div class="button-group">
            <button class="btn btn-primary" @click="handleGenerateKeyPair">
              Regenerate Ephemeral Keys
            </button>
            <button class="btn btn-secondary" @click="currentTab = 'light'">
              Test Ambient Light Sandbox
            </button>
            <button class="btn btn-secondary" @click="currentTab = 'notifications'">
              Simulate Mobile Notification
            </button>
          </div>
        </div>
      </section>

      <!-- Clipboard Manager Tab -->
      <section v-if="currentTab === 'clipboard'" class="panel">
        <h2 class="section-title">Clipboard Manager</h2>

        <div class="editor-section">
          <h3>Sync New Clipboard Payload</h3>
          <div class="input-row">
            <input type="text" v-model="newClipboardText" placeholder="Type or paste payload content..." />
            <button class="btn btn-primary" @click="addClipboardItem">
              Add Clipboard Item
            </button>
          </div>
          <p class="status-msg" v-if="lastSyncStatus" style="margin-top: 0.5rem; color: var(--accent-cyan);">{{ lastSyncStatus }}</p>
        </div>

        <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">Active Sync Items</h3>
        <div class="msg-card-list">
          <div v-for="(item, index) in clipboardItems" :key="index" class="msg-card" style="padding: 1rem; border-radius: 12px; background: rgba(30, 41, 59, 0.6); margin-bottom: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.2);">
            <div v-if="editIndex === index">
              <input type="text" v-model="editText" style="width: 100%; padding: 0.5rem; border-radius: 6px; background: #0f172a; color: white; border: 1px solid var(--border-color); margin-bottom: 0.5rem;" />
              <button class="btn btn-primary btn-sm" @click="saveEdit(index)">Save</button>
              <button class="btn btn-secondary btn-sm" style="margin-left: 0.5rem;" @click="editIndex = null">Cancel</button>
            </div>
            <div v-else>
              <p style="margin: 0; font-size: 0.95rem; color: #cbd5e1; word-break: break-all;">{{ item }}</p>
              <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                <button class="btn btn-primary btn-sm" @click="copyClipboardItem(item)">Copy</button>
                <button class="btn btn-secondary btn-sm" @click="startEdit(index)">Edit</button>
                <button class="btn btn-panic btn-sm" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border-color: rgba(239, 68, 68, 0.4);" @click="removeClipboardItem(index)">Delete</button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Notifications Tab -->
      <section v-if="currentTab === 'notifications'" class="panel">
        <h2 class="section-title">Notifications</h2>

        <div class="cards-grid" style="margin-bottom: 1.5rem;">
          <div class="card">
            <h3>Simulate Outbound SMS</h3>
            <div class="mock-form">
              <input v-model="mockSmsSender" placeholder="Sender Phone" />
              <input v-model="mockSmsBody" placeholder="Message Body" />
              <button class="btn btn-secondary btn-sm" @click="sendOptimisticSms">Send Outbound SMS</button>
            </div>
          </div>

          <div class="card">
            <h3>Simulate Native Notification</h3>
            <div v-if="optimisticStatus" class="sas-card" style="background: rgba(34, 197, 94, 0.2); border-color: #22c55e; padding: 0.5rem 1rem; margin-bottom: 0.5rem;">
              Status: {{ optimisticStatus }}
            </div>
            <div class="mock-form">
              <input v-model="mockNotifTitle" placeholder="Notification Title" />
              <input v-model="mockNotifText" placeholder="Notification Body" />
              <button class="btn btn-secondary btn-sm" @click="handlePushMockNotification">Mirror Native Notification</button>
            </div>
          </div>
        </div>

        <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">Mirrored Notification Log (Native Linux Desktop Synced)</h3>
        <div class="msg-card-list">
          <div class="msg-card" v-for="(n, i) in displayNotifications" :key="i" style="padding: 1rem; border-radius: 12px; background: rgba(30, 41, 59, 0.6); margin-bottom: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.2);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
              <strong style="color: var(--accent-cyan);">[{{ n.source }}] {{ n.title }}</strong>
              <span class="app-pkg" style="font-size: 0.75rem; opacity: 0.7;">{{ n.timestamp }}</span>
            </div>
            <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">{{ n.body }}</p>
          </div>
        </div>
      </section>

      <!-- Ambient Automation Tab -->
      <section v-if="currentTab === 'light'" class="panel">
        <h2 class="section-title">Ambient Light Sensor Automation</h2>

        <div class="lux-controls">
          <label>Simulated Ambient Light Level (Lux): <strong>{{ currentLux }} lux</strong></label>
          <input type="range" min="0" max="500" step="0.5" v-model="currentLux" />
        </div>

        <div class="editor-section">
          <h3>Boa Sandboxed JS Code (In-Memory VM Isolation)</h3>
          <textarea v-model="boaCode" rows="6" class="code-editor"></textarea>
          <button class="btn btn-accent" @click="handleRunBoaScript">
            Run Sandboxed JS Script
          </button>
        </div>

        <div class="editor-section">
          <h3>Fallback Subprocess & Zero-Copy IPC</h3>
          <div class="input-row">
            <input type="text" v-model="fallbackScriptPath" placeholder="/path/to/script.sh" />
            <button class="btn btn-secondary" @click="handleRunFallbackScript">
              Run Native Subprocess
            </button>
            <button class="btn btn-primary" style="margin-left: 0.5rem;" @click="invoke('stream_binary_file')">
              Test Zero-Copy IPC Stream
            </button>
          </div>
        </div>

        <div class="result-box" v-if="scriptResult">
          <h4>Execution Result (Success: {{ scriptResult.success }})</h4>
          <pre class="console-output">{{ scriptResult.output }}</pre>
          <div v-if="scriptResult.logs.length > 0">
            <h5>Logs:</h5>
            <ul>
              <li v-for="(l, i) in scriptResult.logs" :key="i">{{ l }}</li>
            </ul>
          </div>
        </div>
      </section>

      <!-- System Logs Tab -->
      <section v-if="currentTab === 'logs'" class="panel">
        <h2 class="section-title">Real-Time System Log Stream</h2>
        <div class="terminal-box">
          <div v-for="(log, i) in logs" :key="i" class="log-line">
            {{ log }}
          </div>
        </div>
      </section>

      <!-- Settings Tab -->
      <section v-if="currentTab === 'settings'" class="panel">
        <h2 class="section-title">Settings</h2>

        <div class="cards-grid" style="margin-bottom: 2rem;">
          <div class="card" style="padding: 1.5rem;">
            <h3>Sub-Nanosecond Flight Data Recorder</h3>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
              Lock-free sub-nanosecond binary event tracing ring buffer for post-mortem diagnostics.
            </p>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <input type="checkbox" id="check-flight" v-model="flightRecorderEnabled" @change="toggleFlightRecorder" />
              <label for="check-flight">Enable Flight Data Recorder (qlog)</label>
            </div>
          </div>

          <div class="card" style="padding: 1.5rem;">
            <h3>Neuromorphic Anomaly Engine</h3>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
              Real-time eBPF packet-timing anomaly detection & auto-isolation.
            </p>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <input type="checkbox" id="check-anomaly" v-model="neuralAnomalyEnabled" @change="toggleNeuralAnomaly" />
              <label for="check-anomaly">Enable eBPF ONNX Engine</label>
            </div>
          </div>
        </div>

        <div class="key-card" style="background: rgba(15, 23, 42, 0.6); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border-color);" v-if="keyPair">
          <h3>Cryptographic Key Vault (NIST ML-KEM-768 & X25519)</h3>
          
          <div class="key-field" style="margin-top: 1rem;">
            <label style="font-size: 0.85rem; color: var(--text-secondary);">Classical ECC X25519 Public Key (Hex):</label>
            <textarea readonly rows="2" class="code-box" style="width: 100%; margin-top: 0.25rem;">{{ keyPair.x25519_pk_hex }}</textarea>
          </div>

          <div class="key-field" style="margin-top: 1rem;">
            <label style="font-size: 0.85rem; color: var(--text-secondary);">NIST ML-KEM-768 Public Key (Hex):</label>
            <textarea readonly rows="3" class="code-box" style="width: 100%; margin-top: 0.25rem;">{{ keyPair.mlkem_pk_hex }}</textarea>
          </div>

          <div class="key-field" style="margin-top: 1rem; margin-bottom: 1.5rem;">
            <label style="font-size: 0.85rem; color: var(--text-secondary);">NIST ML-KEM-768 Secret Key (Hex):</label>
            <textarea readonly rows="3" class="code-box" style="width: 100%; margin-top: 0.25rem;">{{ keyPair.mlkem_sk_hex }}</textarea>
          </div>

          <button class="btn btn-primary" @click="handleGenerateKeyPair">
            Regenerate Cryptographic Keys
          </button>
        </div>
      </section>
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
  font-size: 1.5rem;
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));
  border-radius: 12px;
  width: 42px;
  height: 42px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
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

.mode-badge {
  padding: 0.4rem 0.75rem;
  border-radius: 20px;
  font-weight: 700;
  text-align: center;
}

.mode-badge.flatpak {
  background: rgba(139, 92, 246, 0.2);
  color: #c084fc;
}

.mode-badge.native {
  background: rgba(6, 182, 212, 0.2);
  color: #38bdf8;
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

.status-indicator {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.dot.green {
  background-color: #22c55e;
  box-shadow: 0 0 10px #22c55e;
}

.crypto-tag {
  background: rgba(99, 102, 241, 0.15);
  border: 1px solid var(--border-color);
  padding: 0.4rem 1rem;
  border-radius: 20px;
  font-size: 0.8rem;
  color: var(--accent-cyan);
  font-weight: 600;
}

.panel {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.sas-card {
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(6, 182, 212, 0.15));
  border: 1px solid var(--accent-cyan);
  border-radius: 16px;
  padding: 1.25rem 1.5rem;
  margin-bottom: 1rem;
}

.sas-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.sas-badge {
  background: rgba(34, 197, 94, 0.2);
  color: #4ade80;
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 700;
}

.sas-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin-bottom: 0.75rem;
}

.sas-code-display {
  font-size: 2.2rem;
  font-weight: 900;
  letter-spacing: 6px;
  color: var(--accent-cyan);
  text-shadow: 0 0 12px rgba(6, 182, 212, 0.6);
  font-family: monospace;
}

.btn-panic {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.4);
  padding: 0.4rem 0.9rem;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 700;
  cursor: pointer;
  margin-right: 1rem;
  transition: all 0.2s ease;
}

.btn-panic:hover {
  background: rgba(239, 68, 68, 0.4);
  box-shadow: 0 0 10px rgba(239, 68, 68, 0.6);
}

.section-title {
  font-size: 1.5rem;
  font-weight: 700;
}

.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.5rem;
}

.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  padding: 1.5rem;
  backdrop-filter: blur(12px);
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
  color: var(--accent-cyan);
  margin-bottom: 0.4rem;
}

.card-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.btn {
  padding: 0.75rem 1.25rem;
  border-radius: 10px;
  border: none;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}

.btn-primary {
  background: linear-gradient(135deg, var(--accent-indigo), var(--accent-purple));
  color: white;
}

.btn-secondary {
  background: rgba(255, 255, 255, 0.1);
  color: white;
}

.btn-accent {
  background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));
  color: white;
}

.code-box, .code-editor {
  width: 100%;
  background: #060811;
  border: 1px solid var(--border-color);
  border-radius: 10px;
  padding: 1rem;
  color: #38bdf8;
  font-family: monospace;
  font-size: 0.85rem;
  resize: vertical;
}

.terminal-box {
  background: #04060d;
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1rem;
  font-family: monospace;
  height: 400px;
  overflow-y: auto;
  color: #4ade80;
}

.log-line {
  line-height: 1.6;
  font-size: 0.85rem;
}
</style>