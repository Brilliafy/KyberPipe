<script setup lang="ts">
import { ref, watch } from "vue";
import QRCode from 'qrcode';
import { deflate } from 'pako';
import { 
  Shield, 
  QrCode, 
  Clipboard, 
  Bell, 
  Sun, 
  FolderOpen, 
  Camera, 
  CheckCircle, 
  ExternalLink, 
  Volume2
} from '@lucide/vue';

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
}

const props = defineProps<{
  isPaired: boolean;
  sasCode: string;
  pairingConfigJson: string;
  clipboardItems: ClipboardRecord[];
  displayNotifications: UnifiedNotification[];
  currentLux: number;
  fileAccessGrantedDesktop: boolean;
  fileAccessGrantedPhone: boolean;
  deviceName: string;
  devicePicture: string;
  pairedDeviceName: string;
  pairedDevicePicture: string;
  isConnected: boolean;
}>();

const emit = defineEmits<{
  (e: "regenerateKeys"): void;
  (e: "navigate", tab: string): void;
  (e: "completePairing", name: string, pic: string): void;
  (e: "saveSettings"): void;
}>();

const showNameModal = ref(false);
const inputDeviceName = ref("");
const inputDevicePic = ref("");
const copyStatusText = ref("");
const fileInputRef = ref<HTMLInputElement | null>(null);
const isUltrasonicActive = ref(false);
const qrDataUrl = ref("");

const generateQR = async () => {
  if (!props.pairingConfigJson) return;
  try {
    const compressed = deflate(props.pairingConfigJson);
    const bytes = new Uint8Array(compressed);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    console.log('QR compressed: ' + compressed.length + ' bytes -> ' + b64.length + ' base64 chars');
    qrDataUrl.value = await QRCode.toDataURL(b64, {
      width: 400,
      margin: 2,
      errorCorrectionLevel: 'L',
      color: { dark: '#000000', light: '#ffffff' }
    });
  } catch (e) {
    console.error('QR generation failed:', e);
  }
};

watch(() => props.pairingConfigJson, generateQR, { immediate: true });

const handleCopyLink = async () => {
  try {
    const encodedData = encodeURIComponent(props.pairingConfigJson);
    const deepLink = `https://brilliafy.github.io/kyberpipe/pair?data=${encodedData}`;
    await navigator.clipboard.writeText(deepLink);
    copyStatusText.value = "Copied remote pairing link to clipboard!";
    setTimeout(() => { copyStatusText.value = ""; }, 3000);
  } catch (e) {
    copyStatusText.value = "Failed to copy link";
  }
};

const submitPairingDetails = () => {
  emit("completePairing", inputDeviceName.value.trim() || "Android Phone", inputDevicePic.value);
  showNameModal.value = false;
};

const triggerFilePicker = () => {
  if (fileInputRef.value) {
    fileInputRef.value.click();
  }
};

const handleFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement;
  if (target.files && target.files[0]) {
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        inputDevicePic.value = e.target.result as string;
      }
    };
    reader.readAsDataURL(target.files[0]);
  }
};
</script>

<template>
  <div class="dashboard-wrapper">
    <!-- NOT PAIRED: Connection prompt is ALL the screen -->
    <div class="welcome-pairing-screen" v-if="!isPaired">
      <div class="welcome-box">
        <h2 class="welcome-title"><Shield style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="28" class="text-cyan" /> Welcome to KyberPipe</h2>
        <p class="welcome-subtitle">Post-Quantum P2P Sync Node. Pair your companion device to begin.</p>
        
        <div class="pairing-panel-layout">
          <!-- QR Card -->
          <div class="pair-card qr-side">
            <h3><QrCode style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Out-of-Band pairing configuration</h3>
            <p class="desc">Scan this QR code with the companion mobile app to establish a secure cryptographic trust chain.</p>
            
            <div class="qr-code-simulator">
              <img v-if="qrDataUrl" :src="qrDataUrl" class="qr-image" alt="Pairing QR code" />
            </div>
            
            <div class="sas-block">
              <span class="sas-label">Safe pairing SAS code:</span>
              <strong class="sas-display">{{ sasCode }}</strong>
            </div>
          </div>

          <!-- JSON & Actions Card -->
          <div class="pair-card config-side">
            <h3>Pairing Configuration JSON</h3>
            <pre class="json-box"><code>{{ pairingConfigJson }}</code></pre>
            
            <div class="pairing-buttons">
              <button class="btn btn-accent" @click="handleCopyLink">
                <ExternalLink style="margin-right: 0.25rem;" :size="14" /> Export Pairing Link
              </button>
            </div>
            
            <p v-if="copyStatusText" class="copy-status">{{ copyStatusText }}</p>
          </div>

          <!-- Ultrasonic Broadcast Panel -->
          <div class="pair-card config-side" style="margin-top: 1rem;">
            <h3>Ultrasonic Pairing Beacon</h3>
            <p class="card-desc">Emits encrypted pairing parameters over an inaudible 19.5 kHz audio carrier tone.</p>
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
              <span style="font-size: 0.85rem; color: var(--text-secondary); display: flex; align-items: center; gap: 0.35rem;">
                <Volume2 :size="14" class="text-cyan" /> Status: {{ isUltrasonicActive ? 'Actively Emitting Beacon (19,531 Hz)' : 'Muted (Inactive)' }}
              </span>
              <div v-if="isUltrasonicActive" class="beacon-pulse"></div>
            </div>
            <button class="btn btn-secondary-outline btn-sm" @click="isUltrasonicActive = !isUltrasonicActive">
              {{ isUltrasonicActive ? 'Disable Beacon' : 'Emit Ultrasonic Beacon' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- PAIRED VIEW: Grid of widgets -->
    <div class="connected-dashboard" v-else>
      <div class="dashboard-header-profile">
        <div class="profile-info-block">
          <div class="avatar-block">
            <img :src="pairedDevicePicture || 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><circle cx=%2250%22 cy=%2250%22 r=%2250%22 fill=%22%2306B6D4%22/><text x=%2250%22 y=%2260%22 font-size=%2235%22 fill=%22white%22 text-anchor=%22middle%22 font-weight=%22bold%22>PH</text></svg>'" alt="Companion avatar" />
          </div>
          <div>
            <h2 style="font-weight: 800; color: white;">Connected Node: {{ pairedDeviceName }}</h2>
            <p style="color: var(--accent-cyan); font-size: 0.85rem; font-weight: 700; display: flex; align-items: center; gap: 0.25rem;">
              <CheckCircle :size="12" /> Secure Post-Quantum KEM Tunnel established
            </p>
          </div>
        </div>
        <button class="btn btn-secondary" @click="emit('navigate', 'settings')">
          Edit Profile
        </button>
      </div>

      <div class="dashboard-widgets-grid">
        <!-- Clipboard widget (Read-only RICH MIME) -->
        <div class="widget-card clipboard-widget" @click="emit('navigate', 'clipboard')">
          <div class="widget-header">
            <h4><Clipboard style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Live Sync Clipboard</h4>
            <span>View All &rarr;</span>
          </div>
          <div class="widget-body">
            <div class="mini-clipboard-list" v-if="clipboardItems.length > 0">
              <div v-for="item in clipboardItems.slice(0, 3)" :key="item.id" class="mini-item">
                <span class="source-lbl" :class="item.source">{{ item.source === 'pc' ? 'PC' : 'Mobile' }}</span>
                <p class="mini-text">{{ item.text }}</p>
              </div>
            </div>
            <p v-else class="empty-widget-text">No synced clipboard payloads yet.</p>
          </div>
        </div>

        <!-- Notifications widget -->
        <div class="widget-card notifications-widget" @click="emit('navigate', 'notifications')">
          <div class="widget-header">
            <h4><Bell style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Active Notifications</h4>
            <span>View All &rarr;</span>
          </div>
          <div class="widget-body">
            <div class="mini-notif-list" v-if="displayNotifications.length > 0">
              <div v-for="notif in displayNotifications.slice(0, 3)" :key="notif.id" class="mini-item">
                <span class="source-lbl" :class="notif.type">{{ notif.type === 'local' ? 'PC' : 'Mobile' }}</span>
                <p class="mini-text"><strong>{{ notif.title }}</strong>: {{ notif.body }}</p>
              </div>
            </div>
            <p v-else class="empty-widget-text">No active notification events logged.</p>
          </div>
        </div>

        <!-- Ambient light gauge widget -->
        <div class="widget-card light-widget" @click="emit('navigate', 'light')">
          <div class="widget-header">
            <h4><Sun style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Ambient Light Telemetry</h4>
            <span>Run Sandbox &rarr;</span>
          </div>
          <div class="widget-body text-center">
            <div class="lux-label-big">{{ currentLux }} <span style="font-size: 1.25rem;">lux</span></div>
            <div class="lux-range-indicator">
              <div class="lux-bar" :style="{ width: Math.min((currentLux / 1000) * 100, 100) + '%' }"></div>
            </div>
            <p class="card-desc">Real-time light level reported by companion light sensor</p>
          </div>
        </div>

        <!-- Files Manager widget -->
        <div class="widget-card files-widget" @click="emit('navigate', 'files')">
          <div class="widget-header">
            <h4><FolderOpen style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> P2P File Explorer</h4>
            <span>Explore &rarr;</span>
          </div>
          <div class="widget-body">
            <div class="files-status-block">
              <div class="status-indicator-pair">
                <span>💻 PC Access:</span>
                <span class="badge" :class="{ ok: fileAccessGrantedDesktop }">
                  {{ fileAccessGrantedDesktop ? 'Granted' : 'Pending' }}
                </span>
              </div>
              <div class="status-indicator-pair">
                <span>📱 Phone Access:</span>
                <span class="badge" :class="{ ok: fileAccessGrantedPhone }">
                  {{ fileAccessGrantedPhone ? 'Granted' : 'Pending' }}
                </span>
              </div>
            </div>
            <button class="btn btn-primary btn-sm btn-full" style="margin-top: 1rem;">
              Access Folder System
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal to ask for device name and picture on pairing -->
    <div class="modal-overlay" v-if="showNameModal" @click.self="showNameModal = false">
      <div class="modal-content text-center">
        <h3>Secure Node Pairing Verified</h3>
        <p class="card-desc">Handshake successful! Please give this device a local nickname and profile avatar.</p>
        
        <div class="avatar-setup-block" style="margin: 1.5rem 0;">
          <div class="avatar-circle-picker mx-auto" @click="triggerFilePicker">
            <img :src="inputDevicePic || 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><circle cx=%2250%22 cy=%2250%22 r=%2250%22 fill=%22%2306B6D4%22/><text x=%2250%22 y=%2260%22 font-size=%2235%22 fill=%22white%22 text-anchor=%22middle%22 font-weight=%22bold%22>PH</text></svg>'" alt="Device Avatar" />
            <div class="picker-hover"><Camera :size="24" style="color:white;" /></div>
          </div>
          <input 
            type="file" 
            ref="fileInputRef" 
            style="display: none;" 
            accept="image/*" 
            @change="handleFileChange" 
          />
        </div>

        <div class="form-group" style="text-align: left; margin-bottom: 1.5rem;">
          <label>Companion Device nickname:</label>
          <input type="text" v-model="inputDeviceName" class="input-text" placeholder="e.g. My Personal Phone" />
        </div>

        <div class="modal-actions">
          <button class="btn btn-primary" @click="submitPairingDetails">
            Save Visual Profile & Connect
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.text-cyan {
  color: var(--accent-cyan);
}
.dashboard-wrapper {
  flex: 1;
  display: flex;
  flex-direction: column;
}
.welcome-pairing-screen {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
}
.welcome-box {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 20px;
  padding: 2.5rem;
  width: 1000px;
  max-width: 100%;
}
.welcome-title {
  font-size: 2rem;
  font-weight: 800;
  margin-bottom: 0.5rem;
  text-align: center;
}
.welcome-subtitle {
  color: var(--text-secondary);
  font-size: 0.95rem;
  text-align: center;
  margin-bottom: 2rem;
}
.pairing-panel-layout {
  display: grid;
  grid-template-columns: 1fr 1.2fr;
  gap: 2rem;
}
@media (max-width: 768px) {
  .pairing-panel-layout {
    grid-template-columns: 1fr;
  }
}
.pair-card {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.5rem;
}
.pair-card h3 {
  font-size: 1.1rem;
  font-weight: 700;
  margin-bottom: 0.5rem;
  color: var(--text-primary);
  display: flex;
  align-items: center;
}
.desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 1rem;
}
.qr-code-simulator {
  width: 280px;
  height: 280px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 1.5rem auto;
  background: #ffffff;
  border-radius: 10px;
  padding: 4px;
}
.qr-image {
  width: 100%;
  height: 100%;
  image-rendering: pixelated;
}

.sas-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-top: 1rem;
}
.sas-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.sas-display {
  font-size: 1.75rem;
  color: var(--accent-cyan);
  font-family: monospace;
  letter-spacing: 2px;
}
.json-box {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.75rem;
  font-family: monospace;
  font-size: 0.75rem;
  color: var(--text-primary);
  height: 180px;
  overflow-y: auto;
  overflow-x: hidden;
  white-space: pre-wrap;
  word-break: break-all;
  max-width: 100%;
  margin-bottom: 1.5rem;
}
.pairing-buttons {
  display: flex;
  gap: 1rem;
}
.copy-status {
  margin-top: 0.75rem;
  font-size: 0.8rem;
  color: var(--accent-cyan);
  text-align: center;
}

/* Connected view dashboard */
.connected-dashboard {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}
.dashboard-header-profile {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.profile-info-block {
  display: flex;
  align-items: center;
  gap: 1rem;
}
.avatar-block {
  width: 55px;
  height: 55px;
  border-radius: 50%;
  overflow: hidden;
  border: 2px solid var(--accent-cyan);
}
.avatar-block img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.dashboard-widgets-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
}
@media (max-width: 1024px) {
  .dashboard-widgets-grid {
    grid-template-columns: 1fr;
  }
}
.widget-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 16px;
  cursor: pointer;
  transition: all 0.3s ease;
}
.widget-card:hover {
  transform: translateY(-2px);
  border-color: var(--accent-cyan);
  box-shadow: 0 4px 20px rgba(6, 182, 212, 0.15);
}
.widget-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
  margin-bottom: 1rem;
}
.widget-header h4 {
  font-size: 1.05rem;
  font-weight: 800;
  color: var(--text-primary);
  display: flex;
  align-items: center;
}
.widget-header span {
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.widget-body {
  min-height: 120px;
}
.mini-clipboard-list, .mini-notif-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.mini-item {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  background: var(--bg-dark);
  padding: 0.5rem;
  border-radius: 6px;
}
.source-lbl {
  font-size: 0.65rem;
  font-weight: bold;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
}
.source-lbl.pc, .source-lbl.local {
  background: rgba(99, 102, 241, 0.2);
  color: var(--accent-indigo);
}
.source-lbl.phone, .source-lbl.remote {
  background: rgba(6, 182, 212, 0.2);
  color: var(--accent-cyan);
}
.mini-text {
  font-size: 0.8rem;
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}
.empty-widget-text {
  color: var(--text-secondary);
  font-size: 0.85rem;
  text-align: center;
  padding: 2.5rem 0;
}
.lux-label-big {
  font-size: 2.5rem;
  font-weight: 800;
  color: #f59e0b;
}
.lux-range-indicator {
  background: #334155;
  height: 8px;
  border-radius: 4px;
  width: 100%;
  margin: 0.75rem 0;
  overflow: hidden;
}
.lux-bar {
  background: #f59e0b;
  height: 100%;
  transition: width 0.3s ease;
}
.files-status-block {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.status-indicator-pair {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
}
.badge {
  background: rgba(239, 68, 68, 0.15);
  color: #ef4444;
  font-weight: 700;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.75rem;
}
.badge.ok {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
}
.btn-full {
  width: 100%;
}

/* Modal and picker styling */
.modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.8);
  backdrop-filter: blur(8px);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}
.modal-content {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  width: 450px;
  max-width: 90%;
  padding: 1.5rem;
  box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
}
.avatar-circle-picker {
  position: relative;
  width: 80px;
  height: 80px;
  border-radius: 50%;
  overflow: hidden;
  border: 2px solid var(--accent-cyan);
  cursor: pointer;
}
.avatar-circle-picker img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.picker-hover {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.6);
  opacity: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  transition: opacity 0.2s ease;
}
.avatar-circle-picker:hover .picker-hover {
  opacity: 1;
}
.mx-auto {
  margin-left: auto;
  margin-right: auto;
}
.text-center {
  text-align: center;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.form-group label {
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.input-text {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  font-size: 0.9rem;
  outline: none;
}
.modal-actions {
  display: flex;
  justify-content: center;
  margin-top: 1rem;
}
.beacon-pulse {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--accent-cyan);
  box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.7);
  animation: pulse-ring 1.5s infinite;
}
@keyframes pulse-ring {
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.7);
  }
  70% {
    transform: scale(1);
    box-shadow: 0 0 0 10px rgba(6, 182, 212, 0);
  }
  100% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(6, 182, 212, 0);
  }
}
.text-cyan {
  color: var(--accent-cyan);
}
</style>
