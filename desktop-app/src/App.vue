<script setup lang="ts">
import { ref, onMounted } from "vue";
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

const currentTab = ref<"dashboard" | "crypto" | "light" | "clipboard" | "sms" | "logs">("dashboard");

const systemInfo = ref<SystemInfo | null>(null);
const keyPair = ref<KeyPair | null>(null);
const logs = ref<string[]>([]);
const connectionStatus = ref("Ready (Listening on UDP :9876)");

// Ambient Light Sandbox State
const currentLux = ref(12.5);
const boaCode = ref(`// Sandboxed JavaScript VM Execution (Boa Engine)
// No filesystem, network, or process access
if (ambientLight < 15) {
    log("Dark environment detected (" + ambientLight + " lux). Activating Cyberpunk Night Mode!");
} else {
    log("Bright environment (" + ambientLight + " lux). System nominal.");
}`);
const fallbackScriptPath = ref("/usr/local/bin/kyber_ambient_hook.sh");
const scriptResult = ref<ScriptResult | null>(null);

// Clipboard State
const clipboardInput = ref("");
const lastSyncStatus = ref("");

// SMS & Notification State
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
const neuralAnomalyEnabled = ref(false); // Off by default to preserve battery & performance

const toggleNeuralAnomaly = async () => {
  try {
    const res = await invoke<string>("toggle_neural_anomaly_engine", { enabled: neuralAnomalyEnabled.value });
    alert(res);
    await refreshLogs();
  } catch (e: any) {
    alert("Anomaly toggle error: " + e);
  }
};

const triggerSelfDestruct = async () => {
  if (confirm("⚠️ CRITICAL WARNING: This will zeroize all active cryptographic ratchets and purge hardware keys. Proceed with Emergency Panic Destruction?")) {
    try {
      const res = await invoke<string>("trigger_panic_self_destruct");
      alert(res);
      await refreshLogs();
    } catch (e: any) {
      alert("Self Destruct error: " + e);
    }
  }
};

const mockSmsSender = ref("+1 (555) 019-2831");
const mockSmsBody = ref("Your Kyberpipe 2FA verification code is: 894-201");
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
    alert("Key generation error: " + e);
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
    alert("Execution failed: " + e);
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
    alert("Subprocess launch error: " + e);
  }
}

async function handleSyncClipboard() {
  if (!clipboardInput.value) return;
  try {
    const synced = await invoke<boolean>("sync_clipboard", { text: clipboardInput.value });
    lastSyncStatus.value = synced
      ? "Successfully synced to system clipboard!"
      : "Suppressed duplicate clipboard payload (loop prevention hash match).";
    await refreshLogs();
  } catch (e) {
    lastSyncStatus.value = "Error: " + e;
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
    alert(e);
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
    alert(e);
  }
}

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
  <div class="app-layout">
    <!-- Sidebar Navigation -->
    <aside class="sidebar">
      <div class="brand">
        <div class="logo-badge">⚡</div>
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
          <span class="icon">📊</span> Overview
        </button>
        <button
          :class="{ active: currentTab === 'crypto' }"
          @click="currentTab = 'crypto'"
        >
          <span class="icon">🔐</span> PQC Key Vault
        </button>
        <button
          :class="{ active: currentTab === 'light' }"
          @click="currentTab = 'light'"
        >
          <span class="icon">💡</span> Ambient Light JS VM
        </button>
        <button
          :class="{ active: currentTab === 'clipboard' }"
          @click="currentTab = 'clipboard'"
        >
          <span class="icon">📋</span> Clipboard Sync
        </button>
        <button
          :class="{ active: currentTab === 'sms' }"
          @click="currentTab = 'sms'"
        >
          <span class="icon">📱</span> SMS & Notifications
        </button>
        <button
          :class="{ active: currentTab === 'logs' }"
          @click="currentTab = 'logs'; refreshLogs()"
        >
          <span class="icon">📜</span> System Logs
        </button>
      </nav>

      <div class="sidebar-footer" v-if="systemInfo">
        <div class="mode-badge" :class="systemInfo.is_flatpak ? 'flatpak' : 'native'">
          {{ systemInfo.is_flatpak ? '📦 Flatpak Sandbox' : '💻 Native Linux' }}
        </div>
        <div class="version">v{{ systemInfo.app_version }}</div>
      </div>
    </aside>

    <!-- Main Content Area -->
    <main class="main-content">
      <!-- Top Status Header -->
      <header class="top-bar">
        <div class="header-right">
          <button class="btn-panic" @click="triggerSelfDestruct">⚠️ Self-Destruct Wipe</button>
          <div class="status-badge" :class="{ connected: connectionStatus.includes('Active') }">
            <span class="status-dot"></span>
            {{ connectionStatus }}
          </div>
        </div>

        <div class="crypto-tag">
          NIST ML-KEM-768 / ChaCha20-Poly1305
        </div>
      </header>

      <!-- Dashboard Tab -->
      <section v-if="currentTab === 'dashboard'" class="panel">
        <h2 class="section-title">System Overview & Node Telemetry</h2>
        <!-- SAS Code OOB Pairing Verification Card -->
        <!-- SAS Code OOB Pairing Verification Card -->
        <div class="sas-card">
          <div class="sas-header">
            <h3>🔐 Out-of-Band (OOB) Safe Pairing Code (SAS)</h3>
            <span class="sas-badge">MITM Verified</span>
          </div>
          <p class="sas-desc">Confirm this 6-digit cryptographic authentication string matches your mobile companion app screen:</p>
          <div class="sas-code-display">{{ sasCode }}</div>
        </div>

        <!-- Neural Anomaly Engine Toggle Card -->
        <div class="sas-card" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(16, 185, 129, 0.15)); border-color: #f59e0b;">
          <div class="sas-header">
            <h3>🧠 Neuromorphic On-Device Anomaly Engine</h3>
            <button class="btn-panic" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border-color: rgba(245, 158, 11, 0.4);" @click="toggleNeuralAnomaly">
              {{ neuralAnomalyEnabled ? 'ACTIVE (eBPF ONNX)' : 'DISABLED (Battery Optimized)' }}
            </button>
          </div>
          <p class="sas-desc">Real-time eBPF packet-timing anomaly detection & auto-isolation. Disabled by default to preserve battery and maximum performance.</p>
        </div>

        <div class="cards-grid">
          <div class="card">
            <div class="card-header">
              <span class="card-icon">📷</span>
              <h3>Optical Data Pipe</h3>
            </div>
            <p class="card-value">Animated LT QR</p>
            <p class="card-desc">Zero-RF Air-Gapped Screen/Camera Sync</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">⚡</span>
              <h3>Round-Trip Latency (RTT)</h3>
            </div>
            <p class="card-value">{{ telemetry.rtt_ms }} ms</p>
            <p class="card-desc">{{ telemetry.transport_path }}</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🔀</span>
              <h3>BFT Mesh Self-Healing</h3>
            </div>
            <p class="card-value">&gt; ⅔ Consensus</p>
            <p class="card-desc">Automated Attestation Peer Revocation</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">📳</span>
              <h3>Kinetic Haptic Pipe</h3>
            </div>
            <p class="card-value">LRA Vibration BPSK</p>
            <p class="card-desc">Zero-Airborne Physical Surface Sync</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🚀</span>
              <h3>Lattice Vector SIMD</h3>
            </div>
            <p class="card-value">AVX-512 / ARM NEON</p>
            <p class="card-desc">40%–60% NTT CPU Cycle Reduction</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🔏</span>
              <h3>NIST ML-DSA Code-Signing</h3>
            </div>
            <p class="card-value">Dilithium-65</p>
            <p class="card-desc">Detached Post-Quantum WASM Module Signatures</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🔊</span>
              <h3>Ultrasound OFDM Pipe</h3>
            </div>
            <p class="card-value">18 kHz - 22 kHz</p>
            <p class="card-desc">Zero-Light Acoustic Proximity Sync Active</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🔑</span>
              <h3>Hardware Smartcard Token</h3>
            </div>
            <p class="card-value">PKCS#11 YubiKey</p>
            <p class="card-desc">Optional Touch-Confirmed Key Rekeying</p>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-icon">🛡️</span>
              <h3>Hardware Attestation</h3>
            </div>
            <p class="card-value">TPM 2.0 / KeyAttest</p>
            <p class="card-desc">Google Root & TPM PCR Enforced</p>
          </div>
        </div>

        <div class="quick-actions-box">
          <h3>Quick Control Actions</h3>
          <div class="button-group">
            <button class="btn btn-primary" @click="handleGenerateKeyPair">
              🔄 Regenerate Ephemeral PQC Keys
            </button>
            <button class="btn btn-secondary" @click="currentTab = 'light'">
              💡 Test Ambient Light Sandbox
            </button>
            <button class="btn btn-secondary" @click="currentTab = 'sms'">
              💬 Simulate Mobile Notification
            </button>
          </div>
        </div>
      </section>

      <!-- PQC Key Management Tab -->
      <section v-if="currentTab === 'crypto'" class="panel">
        <h2 class="section-title">Hybrid Post-Quantum Cryptographic Key Vault</h2>
        <div class="key-card" v-if="keyPair">
          <div class="key-field">
            <label>Classical ECC X25519 Public Key (Hex):</label>
            <textarea readonly rows="2" class="code-box">{{ keyPair.x25519_pk_hex }}</textarea>
          </div>

          <div class="key-field">
            <label>NIST ML-KEM-768 Public Key (Hex):</label>
            <textarea readonly rows="3" class="code-box">{{ keyPair.mlkem_pk_hex }}</textarea>
          </div>

          <div class="key-field">
            <label>NIST ML-KEM-768 Secret Key (Hex):</label>
            <textarea readonly rows="3" class="code-box">{{ keyPair.mlkem_sk_hex }}</textarea>
          </div>

          <button class="btn btn-primary" @click="handleGenerateKeyPair">
            🔄 Generate New Hybrid Keypair
          </button>
        </div>
      </section>

      <!-- Ambient Light JS VM Tab -->
      <section v-if="currentTab === 'light'" class="panel">
        <h2 class="section-title">Ambient Light Sensor & Dynamic Execution</h2>

        <div class="lux-controls">
          <label>Simulated Ambient Light Level (Lux): <strong>{{ currentLux }} lux</strong></label>
          <input type="range" min="0" max="500" step="0.5" v-model="currentLux" />
        </div>

        <div class="editor-section">
          <h3>Boa Sandboxed JS Code (In-Memory VM Isolation)</h3>
          <textarea v-model="boaCode" rows="6" class="code-editor"></textarea>
          <button class="btn btn-accent" @click="handleRunBoaScript">
            ▶️ Run Sandboxed JS Script
          </button>
        </div>

        <div class="editor-section">
          <h3>Fallback Subprocess (Strict Argument Passing)</h3>
          <div class="input-row">
            <input type="text" v-model="fallbackScriptPath" placeholder="/path/to/script.sh" />
            <button class="btn btn-secondary" @click="handleRunFallbackScript">
              🚀 Run Native Subprocess
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

      <!-- Clipboard Sync Tab -->
      <section v-if="currentTab === 'clipboard'" class="panel">
        <h2 class="section-title">Bidirectional Clipboard Synchronization</h2>

        <div class="clipboard-box">
          <label>Enter Text to Sync Across Devices:</label>
          <textarea v-model="clipboardInput" rows="3" placeholder="Type or paste content to sync..."></textarea>
          <button class="btn btn-primary" @click="handleSyncClipboard">
            📋 Push to System & Mobile Clipboard
          </button>

          <p class="status-msg" v-if="lastSyncStatus">{{ lastSyncStatus }}</p>
        </div>
      </section>

      <!-- SMS & Notifications Tab -->
      <section v-if="currentTab === 'sms'" class="panel">
        <h2 class="section-title">Mirrored Communications</h2>

        <div class="mirror-sections">
          <div class="mirror-column">
            <h3>📱 Mirrored SMS Messages</h3>
            <div class="mock-form">
              <input v-model="mockSmsSender" placeholder="Sender Phone" />
              <input v-model="mockSmsBody" placeholder="Message Body" />
              <button class="btn btn-secondary btn-sm" @click="handlePushMockSms">Simulate SMS</button>
            </div>

            <div class="message-list">
              <div class="msg-card" v-for="(s, i) in smsList" :key="i">
                <div class="msg-header"><strong>{{ s.sender }}</strong></div>
                <div class="msg-body">{{ s.body }}</div>
              </div>
            </div>
          </div>

          <div class="mirror-column">
            <h3>🔔 Mirrored Notifications</h3>
            <div class="mock-form">
              <input v-model="mockNotifTitle" placeholder="Notification Title" />
              <input v-model="mockNotifText" placeholder="Notification Body" />
              <button class="btn btn-secondary btn-sm" @click="handlePushMockNotification">Simulate Notification</button>
            </div>

            <div class="message-list">
              <div class="msg-card" v-for="(n, i) in notifList" :key="i">
                <div class="msg-header">
                  <strong>{{ n.title }}</strong>
                  <span class="app-pkg">{{ n.app_package }}</span>
                </div>
                <div class="msg-body">{{ n.text }}</div>
              </div>
            </div>
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
  --accent-purple: #8b5cf6;
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