<script setup lang="ts">
import { ref } from "vue";
import { 
  Settings, 
  User, 
  Smartphone, 
  FolderLock, 
  Activity, 
  ShieldAlert, 
  Key, 
  Camera, 
  Eye,
  AlertTriangle
} from '@lucide/vue';

interface KeyPair {
  x25519_pk_hex: string;
  x25519_sk_hex: string;
  mlkem_pk_hex: string;
  mlkem_sk_hex: string;
}

defineProps<{
  flightRecorderEnabled: boolean;
  neuralAnomalyEnabled: boolean;
  keyPair: KeyPair | null;
  deviceName: string;
  devicePicture: string;
  pairedDeviceName: string;
  pairedDevicePicture: string;
  ddnsHostname: string;
  enableUpnp: boolean;
  enableDdns: boolean;
  fileAccessGrantedDesktop: boolean;
  fileAccessGrantedPhone: boolean;
  themeMode: string; // "light" | "dark" | "auto"
}>();

const emit = defineEmits<{
  (e: "update:flightRecorderEnabled", val: boolean): void;
  (e: "update:neuralAnomalyEnabled", val: boolean): void;
  (e: "update:deviceName", val: string): void;
  (e: "update:devicePicture", val: string): void;
  (e: "update:ddnsHostname", val: string): void;
  (e: "update:enableUpnp", val: boolean): void;
  (e: "update:enableDdns", val: boolean): void;
  (e: "update:fileAccessGrantedDesktop", val: boolean): void;
  (e: "update:fileAccessGrantedPhone", val: boolean): void;
  (e: "update:themeMode", val: string): void;
  (e: "regenerateKeys"): void;
  (e: "saveSettings"): void;
  (e: "triggerSelfDestruct"): void;
  (e: "deleteConnection"): void;
}>();

const fileInputRef = ref<HTMLInputElement | null>(null);

const confirmUnpair = () => {
  if (confirm("Are you sure you want to delete the pairing connection with this companion device? All secure channels will be destroyed.")) {
    emit("deleteConnection");
  }
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
        emit("update:devicePicture", e.target.result as string);
        emit("saveSettings");
      }
    };
    reader.readAsDataURL(target.files[0]);
  }
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title"><Settings style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="24" /> System Settings</h2>
    <p class="section-subtitle">Manage device profile identities, connectivity fallbacks, theme visual properties, and security authorizations.</p>

    <!-- Theme Visual Properties Card -->
    <div class="card theme-settings-card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
      <h3><Eye style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Theme Visual Properties</h3>
      <p class="card-desc">Configure application color accents and light/dark theme preference toggles.</p>
      
      <div class="form-group" style="max-width: 300px;">
        <label for="theme-select">Visual Color Mode:</label>
        <select 
          id="theme-select" 
          class="input-select" 
          :value="themeMode" 
          @change="emit('update:themeMode', ($event.target as HTMLSelectElement).value); emit('saveSettings')"
        >
          <option value="light">Light Theme Mode</option>
          <option value="dark">Dark Theme Mode</option>
          <option value="auto">System Default (Auto-detect)</option>
        </select>
      </div>

      <div class="theme-autodetect-row" style="margin-top: 0.75rem; font-size: 0.85rem; color: var(--text-secondary);">
        <span v-if="themeMode === 'auto'">
          Info: Autodetect from OS is currently enabled. Theme changes dynamically based on OS styling.
        </span>
      </div>
    </div>

    <!-- Profile Management Section -->
    <div class="card profile-card" style="margin-bottom: 1.5rem;">
      <h3><User style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Local Node Profile</h3>
      <p class="card-desc">Identify this Linux host visually inside KyberPipe. Affects local discovery name only.</p>
      
      <div class="profile-editor">
        <div class="avatar-circle" @click="triggerFilePicker">
          <img :src="devicePicture || 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><circle cx=%2250%22 cy=%2250%22 r=%2250%22 fill=%22%23334155%22/><text x=%2250%22 y=%2260%22 font-size=%2235%22 fill=%22white%22 text-anchor=%22middle%22 font-weight=%22bold%22>PC</text></svg>'" alt="Device Avatar" />
          <div class="avatar-hover">
            <Camera :size="20" style="color:white;" />
          </div>
        </div>
        <input 
          type="file" 
          ref="fileInputRef" 
          style="display: none;" 
          accept="image/*" 
          @change="handleFileChange" 
        />

        <div class="profile-fields">
          <div class="input-group">
            <label>Device Name:</label>
            <input 
              type="text" 
              class="input-text" 
              :value="deviceName" 
              @input="emit('update:deviceName', ($event.target as HTMLInputElement).value)"
              @blur="emit('saveSettings')"
              placeholder="e.g. My Ubuntu Desktop" 
            />
          </div>
        </div>
      </div>
    </div>

    <!-- Paired Device profile view -->
    <div class="card profile-card" style="margin-bottom: 1.5rem;" v-if="pairedDeviceName">
      <h3><Smartphone style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Paired Companion Profile</h3>
      <div class="profile-editor">
        <div class="avatar-circle-readonly">
          <img :src="pairedDevicePicture || 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><circle cx=%2250%22 cy=%2250%22 r=%2250%22 fill=%22%2306B6D4%22/><text x=%2250%22 y=%2260%22 font-size=%2235%22 fill=%22white%22 text-anchor=%22middle%22 font-weight=%22bold%22>PH</text></svg>'" alt="Paired Avatar" />
        </div>
        <div class="profile-fields" style="flex: 1; display: flex; justify-content: space-between; align-items: center; gap: 1rem;">
          <div>
            <h4>{{ pairedDeviceName }}</h4>
            <p class="card-desc" style="margin: 0;">Connected via post-quantum KEM session</p>
          </div>
          <button 
            style="background-color: #ef4444; color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.375rem; cursor: pointer; font-weight: bold; font-size: 0.85rem;"
            @click="confirmUnpair"
          >
            Delete Connection
          </button>
        </div>
      </div>
    </div>

    <!-- Storage Access / Permissions Management -->
    <div class="card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
      <h3><FolderLock style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Shared Folder & Storage Permissions</h3>
      <p class="card-desc">Authorize directories read/write options for secure cross-device file transfer.</p>
      <div class="permissions-settings">
        <label class="switch-row">
          <span class="toggle-switch">
            <input 
              type="checkbox" 
              :checked="fileAccessGrantedDesktop" 
              @change="emit('update:fileAccessGrantedDesktop', ($event.target as HTMLInputElement).checked); emit('saveSettings')"
            />
            <span class="toggle-slider"></span>
          </span>
          <span>Allow Phone to browse this PC's files</span>
        </label>
      </div>
    </div>


    <!-- Flight recorder and anomaly engine toggles -->
    <div class="cards-grid" style="margin-bottom: 2rem;">
      <div class="card" style="padding: 1.5rem;">
        <h3><Activity style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Flight Data Recorder</h3>
        <p class="card-desc">Lock-free sub-nanosecond binary event tracing ring buffer for post-mortem diagnostics.</p>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <label class="toggle-switch">
            <input 
              type="checkbox" 
              id="check-flight" 
              :checked="flightRecorderEnabled" 
              @change="emit('update:flightRecorderEnabled', ($event.target as HTMLInputElement).checked)" 
            />
            <span class="toggle-slider"></span>
          </label>
          <label for="check-flight" style="color: var(--text-primary); cursor: pointer; font-size: 0.85rem;">Enable Flight Data (qlog)</label>
        </div>
      </div>

      <div class="card" style="padding: 1.5rem;">
        <h3><ShieldAlert style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Neuromorphic Anomaly Engine</h3>
        <p class="card-desc">Real-time eBPF packet-timing anomaly detection & auto-isolation.</p>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <label class="toggle-switch">
            <input 
              type="checkbox" 
              id="check-anomaly" 
              :checked="neuralAnomalyEnabled" 
              @change="emit('update:neuralAnomalyEnabled', ($event.target as HTMLInputElement).checked)" 
            />
            <span class="toggle-slider"></span>
          </label>
          <label for="check-anomaly" style="color: var(--text-primary); cursor: pointer; font-size: 0.85rem;">Enable eBPF ONNX Engine</label>
        </div>
      </div>
    </div>

    <!-- Keys vault -->
    <div class="key-card" style="background: rgba(15, 23, 42, 0.6); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border-color);" v-if="keyPair">
      <h3><Key style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Cryptographic Key Vault (NIST ML-KEM-768 & X25519)</h3>
      
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

      <button class="btn btn-primary" @click="emit('regenerateKeys')">
        Regenerate Cryptographic Keys
      </button>
    </div>

    <!-- Danger Zone -->
    <div class="danger-zone" style="margin-top: 2rem;">
      <div class="danger-header">
        <AlertTriangle :size="18" style="margin-right: 0.35rem;" />
        <span>Danger Zone</span>
      </div>
      <div class="danger-card">
        <div class="danger-content">
          <div>
            <h4>Emergency Panic Self-Destruct</h4>
            <p>Zeroize all active cryptographic ratchets, purge TEE/StrongBox master keys, and wipe pairing state.</p>
          </div>
          <button class="btn btn-danger" @click="emit('triggerSelfDestruct')">
            <ShieldAlert :size="14" style="margin-right: 0.35rem;" /> Wipe All Keys
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.section-subtitle {
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-bottom: 1.5rem;
}
.card {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
  border-radius: 12px;
}
.card-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 1rem;
}
.profile-editor {
  display: flex;
  align-items: center;
  gap: 1.5rem;
}
.avatar-circle {
  position: relative;
  width: 70px;
  height: 70px;
  border-radius: 50%;
  overflow: hidden;
  border: 2px solid var(--accent-cyan);
  cursor: pointer;
}
.avatar-circle img, .avatar-circle-readonly img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.avatar-hover {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  opacity: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: opacity 0.2s ease;
}
.avatar-circle:hover .avatar-hover {
  opacity: 1;
}
.avatar-circle-readonly {
  width: 70px;
  height: 70px;
  border-radius: 50%;
  overflow: hidden;
  border: 2px solid var(--accent-indigo);
}
.profile-fields {
  flex: 1;
}
.input-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.input-group label {
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.input-text, .input-select {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  font-size: 0.9rem;
  outline: none;
}
.input-text:focus, .input-select:focus {
  border-color: var(--accent-indigo);
}
.permissions-settings {
  display: flex;
  flex-direction: column;
}
.switch-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 0.9rem;
  color: var(--text-primary);
  cursor: pointer;
}
.toggle-switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 22px;
  flex-shrink: 0;
}
.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background: #334155;
  border-radius: 22px;
  transition: 0.2s;
}
.toggle-slider:before {
  content: "";
  position: absolute;
  height: 16px;
  width: 16px;
  left: 3px;
  bottom: 3px;
  background: white;
  border-radius: 50%;
  transition: 0.2s;
}
.toggle-switch input:checked + .toggle-slider {
  background: var(--accent-cyan);
}
.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(18px);
}
.code-box {
  width: 100%;
  background: var(--bg-dark);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.75rem;
  font-family: monospace;
  font-size: 0.85rem;
  resize: none;
}
.danger-zone {
  border-top: 1px solid rgba(239, 68, 68, 0.3);
  padding-top: 1.5rem;
}
.danger-header {
  display: flex;
  align-items: center;
  color: #ef4444;
  font-weight: 800;
  font-size: 0.95rem;
  margin-bottom: 1rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}
.danger-card {
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.25);
  border-radius: 12px;
  padding: 1.25rem;
}
.danger-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}
.danger-content h4 {
  font-size: 0.95rem;
  font-weight: 700;
  color: #f87171;
  margin-bottom: 0.25rem;
}
.danger-content p {
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.btn-danger {
  background: #dc2626;
  color: white;
  border: none;
  padding: 0.6rem 1.2rem;
  border-radius: 8px;
  font-weight: 700;
  font-size: 0.85rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  transition: background 0.2s;
  white-space: nowrap;
}
.btn-danger:hover {
  background: #b91c1c;
}
</style>
