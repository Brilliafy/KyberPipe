<script setup lang="ts">
import { ref } from "vue";

const props = defineProps<{
  sasCode: string;
  wifiDirectActive: boolean;
  lanActive: boolean;
  resolvedPublicIp: string;
  pairingConfigJson: string;
}>();

const emit = defineEmits<{
  (e: "update:wifiDirectActive", val: boolean): void;
  (e: "update:lanActive", val: boolean): void;
  (e: "runStunHolePunch", stunHost: string): void;
  (e: "regenerateKeys"): void;
  (e: "navigate", tab: string): void;
}>();

const stunHostInput = ref("stun.l.google.com:19302");
const showPairingModal = ref(false);
const copyStatusText = ref("");

const handleCopyLink = async () => {
  try {
    const encodedData = encodeURIComponent(props.pairingConfigJson);
    const deepLink = `kyberpipe://pair?data=${encodedData}`;
    await navigator.clipboard.writeText(deepLink);
    copyStatusText.value = "Copied remote pairing link to clipboard!";
    setTimeout(() => { copyStatusText.value = ""; }, 3000);
  } catch (e) {
    copyStatusText.value = "Failed to copy link";
  }
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">System Overview</h2>

    <div class="dashboard-grid">
      <!-- Left Column: Safe Pairing and Connection Hierarchy -->
      <div class="dashboard-col">
        <!-- 3-Tier Connectivity Manager -->
        <div class="card connectivity-card">
          <div class="card-header">
            <h3>3-Tier Connectivity Manager</h3>
            <span class="active-badge">Active Failover</span>
          </div>
          <p class="card-desc">Evaluate and control active network interfaces by precedence:</p>

          <div class="interfaces-list">
            <!-- Tier 1 -->
            <div class="interface-item" :class="{ active: wifiDirectActive }">
              <div class="interface-header">
                <div class="interface-title">
                  <span class="tier-number">Tier 1</span>
                  <strong>Wi-Fi Direct (P2P Radio)</strong>
                </div>
                <div class="toggle-switch">
                  <input 
                    type="checkbox" 
                    id="toggle-wifi-direct" 
                    :checked="wifiDirectActive" 
                    @change="emit('update:wifiDirectActive', ($event.target as HTMLInputElement).checked)" 
                  />
                  <label for="toggle-wifi-direct"></label>
                </div>
              </div>
              <p class="interface-desc">Direct peer-to-peer radio connection. Highest speed, lowest latency (2.4ms).</p>
            </div>

            <!-- Tier 2 -->
            <div class="interface-item" :class="{ active: !wifiDirectActive && lanActive }">
              <div class="interface-header">
                <div class="interface-title">
                  <span class="tier-number">Tier 2</span>
                  <strong>Local Network (mDNS LAN)</strong>
                </div>
                <div class="toggle-switch">
                  <input 
                    type="checkbox" 
                    id="toggle-lan" 
                    :checked="lanActive" 
                    @change="emit('update:lanActive', ($event.target as HTMLInputElement).checked)" 
                  />
                  <label for="toggle-lan"></label>
                </div>
              </div>
              <p class="interface-desc">Local discovery over shared Wi-Fi Access Point/LAN via UDP multicast beacon (8.5ms).</p>
            </div>

            <!-- Tier 3 -->
            <div class="interface-item" :class="{ active: !wifiDirectActive && !lanActive }">
              <div class="interface-header">
                <div class="interface-title">
                  <span class="tier-number">Tier 3</span>
                  <strong>WireGuard WAN Tunnel Overlay</strong>
                </div>
                <span class="always-on">Fallback</span>
              </div>
              <p class="interface-desc">Seamless WAN backup using public STUN UDP hole-punching for off-grid remote sync (45.2ms).</p>
            </div>
          </div>
        </div>

        <!-- STUN & UDP Hole Punching -->
        <div class="card stun-card">
          <h3>Decentralized STUN Endpoint Resolver</h3>
          <p class="card-desc">Query public STUN servers for dynamic WAN reflexive ports without passing data through third-party servers.</p>
          
          <div class="stun-action-box">
            <input 
              type="text" 
              class="input-text" 
              v-model="stunHostInput" 
              placeholder="e.g. stun.l.google.com:19302"
            />
            <button class="btn btn-secondary btn-sm" @click="emit('runStunHolePunch', stunHostInput)">
              Query STUN & Punch
            </button>
          </div>

          <div class="stun-result">
            <span>Reflexive Public WAN Endpoint:</span>
            <code class="code-badge">{{ resolvedPublicIp }}</code>
          </div>
        </div>
      </div>

      <!-- Right Column: Safe Pairing -->
      <div class="dashboard-col">
        <!-- Out-of-Band safe pairing SAS code -->
        <div class="card sas-card">
          <div class="sas-header">
            <h3>Out-of-Band Safe Pairing</h3>
            <span class="sas-badge">MITM Verified</span>
          </div>
          <p class="sas-desc">Confirm this 6-digit cryptographic authentication string matches your mobile companion app screen:</p>
          <div class="sas-code-display">{{ sasCode }}</div>
          
          <div style="margin-top: 1.5rem; text-align: center;">
            <button class="btn btn-primary" @click="showPairingModal = true">
              Pair New Device (OOB Config)
            </button>
          </div>
        </div>

        <!-- Quick Actions -->
        <div class="card quick-actions-box">
          <h3>Quick Actions</h3>
          <div class="button-group-vertical">
            <button class="btn btn-secondary" @click="emit('regenerateKeys')">
              Regenerate Ephemeral Keys
            </button>
            <button class="btn btn-secondary" @click="emit('navigate', 'light')">
              Manage Automation Handlers
            </button>
            <button class="btn btn-secondary" @click="emit('navigate', 'notifications')">
              Simulate Notifications
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Out-of-Band Pairing Configuration Modal -->
    <div class="modal-overlay" v-if="showPairingModal" @click.self="showPairingModal = false">
      <div class="modal-content">
        <div class="modal-header">
          <h3>Out-of-Band Pairing Exchange</h3>
          <button class="close-btn" @click="showPairingModal = false">&times;</button>
        </div>
        
        <div class="modal-body">
          <p class="modal-desc">
            Scan the Out-of-Band credentials using your companion phone camera or export the remote pairing link.
          </p>

          <div class="pairing-container">
            <!-- Simulated QR Code -->
            <div class="qr-code-simulator">
              <div class="qr-corner top-left"></div>
              <div class="qr-corner top-right"></div>
              <div class="qr-corner bottom-left"></div>
              <div class="qr-matrix">
                <div v-for="i in 144" :key="i" class="qr-dot" :class="{ active: (i * 3 + 7) % 5 === 0 || (i * 7 + 13) % 8 === 0 }"></div>
              </div>
            </div>

            <!-- Configuration JSON payload -->
            <div class="config-json-payload">
              <h4>Pairing Payload (JSON Metadata)</h4>
              <pre class="json-box"><code>{{ pairingConfigJson }}</code></pre>
            </div>
          </div>

          <div class="modal-actions">
            <button class="btn btn-primary" @click="handleCopyLink">
              Export Remote Pairing Link
            </button>
            <button class="btn btn-secondary" @click="showPairingModal = false">
              Close
            </button>
          </div>

          <div v-if="copyStatusText" class="copy-status-bubble">
            {{ copyStatusText }}
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
  margin-top: 1.5rem;
}

@media (max-width: 1024px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}

.dashboard-col {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.connectivity-card, .stun-card, .sas-card, .quick-actions-box {
  padding: 1.5rem;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.active-badge {
  background: rgba(99, 102, 241, 0.2);
  color: #a5b4fc;
  font-size: 0.75rem;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  border: 1px solid rgba(99, 102, 241, 0.4);
}

.card-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin-bottom: 1rem;
}

.interfaces-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.interface-item {
  background: rgba(15, 23, 42, 0.3);
  border: 1px solid rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  padding: 0.75rem 1rem;
  transition: all 0.2s ease;
}

.interface-item.active {
  border-color: var(--accent-cyan);
  background: rgba(6, 182, 212, 0.05);
  box-shadow: 0 0 15px rgba(6, 182, 212, 0.1);
}

.interface-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.25rem;
}

.interface-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
}

.tier-number {
  background: rgba(255, 255, 255, 0.1);
  color: var(--text-primary);
  font-size: 0.7rem;
  font-weight: bold;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
}

.interface-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.always-on {
  font-size: 0.7rem;
  color: var(--text-secondary);
  border: 1px solid rgba(255, 255, 255, 0.2);
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
}

/* Custom Toggle Switch */
.toggle-switch {
  position: relative;
  width: 44px;
  height: 22px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-switch label {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: #334155;
  transition: .2s;
  border-radius: 34px;
}

.toggle-switch label:before {
  position: absolute;
  content: "";
  height: 16px;
  width: 16px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .2s;
  border-radius: 50%;
}

.toggle-switch input:checked + label {
  background-color: var(--accent-cyan);
}

.toggle-switch input:checked + label:before {
  transform: translateX(22px);
}

/* STUN section */
.stun-action-box {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.input-text {
  flex: 1;
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  padding: 0.5rem;
  border-radius: 6px;
  font-size: 0.85rem;
  outline: none;
}

.input-text:focus {
  border-color: var(--accent-indigo);
}

.stun-result {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.85rem;
  background: rgba(0, 0, 0, 0.2);
  padding: 0.75rem;
  border-radius: 6px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.code-badge {
  font-family: monospace;
  background: rgba(99, 102, 241, 0.15);
  color: #c084fc;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.85rem;
  border: 1px solid rgba(99, 102, 241, 0.3);
}

/* Safe Pairing display */
.sas-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.sas-badge {
  background: rgba(168, 85, 247, 0.2);
  color: #d8b4fe;
  font-size: 0.75rem;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  border: 1px solid rgba(168, 85, 247, 0.4);
}

.sas-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  line-height: 1.4;
  margin-bottom: 1.25rem;
}

.sas-code-display {
  font-size: 3.5rem;
  font-weight: 800;
  letter-spacing: 0.25rem;
  text-align: center;
  color: #c084fc;
  text-shadow: 0 0 20px rgba(192, 132, 252, 0.3);
  font-family: monospace;
  background: rgba(15, 23, 42, 0.4);
  padding: 1rem;
  border-radius: 12px;
  border: 1px solid rgba(192, 132, 252, 0.2);
}

.button-group-vertical {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-top: 1rem;
}

/* Modal Overlay */
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
  width: 600px;
  max-width: 90%;
  padding: 1.5rem;
  box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
  animation: modal-fadeIn 0.25s ease-out;
}

@keyframes modal-fadeIn {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid rgba(255,255,255,0.1);
  padding-bottom: 0.75rem;
  margin-bottom: 1rem;
}

.close-btn {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-size: 1.75rem;
  cursor: pointer;
  line-height: 1;
}

.close-btn:hover {
  color: var(--text-primary);
}

.modal-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin-bottom: 1.5rem;
}

.pairing-container {
  display: flex;
  gap: 1.5rem;
  align-items: center;
}

@media (max-width: 600px) {
  .pairing-container {
    flex-direction: column;
  }
}

.qr-code-simulator {
  width: 160px;
  height: 160px;
  background: #ffffff;
  padding: 10px;
  border-radius: 12px;
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
}

.qr-matrix {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 3px;
  width: 100%;
  height: 100%;
}

.qr-dot {
  background: #cbd5e1;
  border-radius: 1px;
}

.qr-dot.active {
  background: #0f172a;
}

.qr-corner {
  position: absolute;
  width: 40px;
  height: 40px;
  border: 4px solid #0f172a;
  background: transparent;
}

.qr-corner.top-left { top: 10px; left: 10px; border-right: none; border-bottom: none; }
.qr-corner.top-right { top: 10px; right: 10px; border-left: none; border-bottom: none; }
.qr-corner.bottom-left { bottom: 10px; left: 10px; border-right: none; border-top: none; }

.config-json-payload {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  width: 100%;
}

.config-json-payload h4 {
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.json-box {
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 8px;
  padding: 0.75rem;
  font-family: monospace;
  font-size: 0.75rem;
  max-height: 150px;
  overflow-y: auto;
  color: #a5b4fc;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  margin-top: 1.5rem;
  border-top: 1px solid rgba(255,255,255,0.1);
  padding-top: 1rem;
}

.copy-status-bubble {
  margin-top: 0.75rem;
  background: rgba(6, 182, 212, 0.15);
  color: var(--accent-cyan);
  border: 1px solid rgba(6, 182, 212, 0.3);
  padding: 0.5rem;
  border-radius: 6px;
  font-size: 0.8rem;
  text-align: center;
  animation: fadeIn 0.2s ease-out;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
</style>
