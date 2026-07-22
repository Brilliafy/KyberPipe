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
  Eye 
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
}>();

const fileInputRef = ref<HTMLInputElement | null>(null);

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
          ℹ️ Autodetect from OS is currently enabled. Theme changes dynamically based on OS styling.
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
        <div class="profile-fields">
          <h4>{{ pairedDeviceName }}</h4>
          <p class="card-desc" style="margin: 0;">Connected via post-quantum KEM session</p>
        </div>
      </div>
    </div>

    <!-- Storage Access / Permissions Management -->
    <div class="card" style="margin-bottom: 1.5rem; padding: 1.5rem;">
      <h3><FolderLock style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Shared Folder & Storage Permissions</h3>
      <p class="card-desc">Authorize directories read/write options for secure cross-device file transfer.</p>
      <div class="permissions-settings">
        <label class="switch-row">
          <input 
            type="checkbox" 
            :checked="fileAccessGrantedDesktop" 
            @change="emit('update:fileAccessGrantedDesktop', ($event.target as HTMLInputElement).checked); emit('saveSettings')"
          />
          <span>Allow Phone to browse this PC's files</span>
        </label>
        <label class="switch-row" style="margin-top: 0.5rem; display: block;">
          <input 
            type="checkbox" 
            :checked="fileAccessGrantedPhone" 
            @change="emit('update:fileAccessGrantedPhone', ($event.target as HTMLInputElement).checked); emit('saveSettings')"
          />
          <span>Allow PC to browse Android companion files</span>
        </label>
      </div>
    </div>

    <!-- Flight recorder and anomaly engine toggles -->
    <div class="cards-grid" style="margin-bottom: 2rem;">
      <div class="card" style="padding: 1.5rem;">
        <h3><Activity style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Flight Data Recorder</h3>
        <p class="card-desc">Lock-free sub-nanosecond binary event tracing ring buffer for post-mortem diagnostics.</p>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <input 
            type="checkbox" 
            id="check-flight" 
            :checked="flightRecorderEnabled" 
            @change="emit('update:flightRecorderEnabled', ($event.target as HTMLInputElement).checked)" 
          />
          <label for="check-flight" style="color: var(--text-primary); cursor: pointer;">Enable Flight Data (qlog)</label>
        </div>
      </div>

      <div class="card" style="padding: 1.5rem;">
        <h3><ShieldAlert style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="16" /> Neuromorphic Anomaly Engine</h3>
        <p class="card-desc">Real-time eBPF packet-timing anomaly detection & auto-isolation.</p>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <input 
            type="checkbox" 
            id="check-anomaly" 
            :checked="neuralAnomalyEnabled" 
            @change="emit('update:neuralAnomalyEnabled', ($event.target as HTMLInputElement).checked)" 
          />
          <label for="check-anomaly" style="color: var(--text-primary); cursor: pointer;">Enable eBPF ONNX Engine</label>
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
  gap: 0.5rem;
  font-size: 0.9rem;
  color: var(--text-primary);
  cursor: pointer;
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
</style>
