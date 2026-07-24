<script setup lang="ts">
import { ref } from "vue";
import { Shield, Wifi, Globe, Terminal, Trash2, Plus, RefreshCw } from '@lucide/vue';

const props = defineProps<{
  isPaired: boolean;
  pairedDeviceName: string;
  localMethod: string;
  remoteMethod: string;
  localActive: boolean;
  remoteActive: boolean;
}>();

const emit = defineEmits<{
  (e: "pairLocally", method: string): void;
  (e: "pairExternally", method: string): void;
  (e: "removeDevice"): void;
  (e: "swapPriority"): void;
  (e: "fixFirewall"): void;
  (e: "navigate", tab: string): void;
}>();

const showPairModal = ref(false);
const showLocalOptions = ref(false);
const showExternalOptions = ref(false);
const selectedMethod = ref("");
const hoveredOption = ref<string | null>(null);

const localMethods = [
  { id: "wifi_direct", label: "Wi-Fi Direct", icon: "📡", desc: "Direct peer-to-peer radio. Fastest, no router needed." },
  { id: "mdns", label: "mDNS Zeroconf", icon: "🔍", desc: "Auto-discovery on local network. QR contains PQC key." },
  { id: "manual_ip", label: "Manual IP / DDNS", icon: "🌐", desc: "Enter IP or hostname manually. SAS verification." }
];

const externalMethods = [
  { id: "wormhole", label: "Magic Wormhole", icon: "🐛", desc: "Relay-based WAN pairing. 3-word code + PQC key in QR." },
  { id: "tor", label: "Tor Onion (arti)", icon: "🧅", desc: "Ephemeral .onion service. Zero-trust, no MITM." }
];

const handleLocalSelect = (method: string) => {
  selectedMethod.value = method;
  showPairModal.value = false;
  emit("pairLocally", method);
};

const handleExternalSelect = (method: string) => {
  selectedMethod.value = method;
  showPairModal.value = false;
  emit("pairExternally", method);
};
</script>

<template>
  <section class="panel">
    <div class="header-row">
      <div>
        <h2 class="section-title">🔗 Connectivity</h2>
        <p class="section-subtitle">Manage peer-to-peer connections with your companion device.</p>
      </div>
    </div>

    <!-- NOT PAIRED: Setup prompt -->
    <div v-if="!isPaired" class="connect-prompt">
      <div class="connect-card" @click="showPairModal = true">
        <div class="connect-card-icon">
          <Shield :size="48" class="text-cyan" />
        </div>
        <h3>Setup a Device</h3>
        <p class="card-desc">Pair your Android companion with this desktop using a local or remote method.</p>
        <button class="btn btn-primary" style="margin-top: 0.75rem;">Get Started</button>
      </div>
    </div>

    <!-- PAIRED: Device info + management -->
    <div v-else class="paired-view">
      <div class="paired-header-card">
        <div class="paired-info">
          <div class="avatar-placeholder">{{ (props.pairedDeviceName || 'D')[0] }}</div>
          <div>
            <h3>{{ props.pairedDeviceName || 'Android Phone' }}</h3>
            <p class="card-desc" style="margin: 0;">
              <span v-if="localActive" class="badge-local">Local: {{ localMethod }}</span>
              <span v-if="remoteActive" class="badge-remote">Remote: {{ remoteMethod }}</span>
              <span v-if="!localActive && !remoteActive" class="badge-offline">Disconnected</span>
            </p>
          </div>
        </div>
        <div class="paired-actions">
          <button class="btn btn-danger-outline btn-sm" @click="emit('removeDevice')">
            <Trash2 :size="14" /> Remove Device
          </button>
        </div>
      </div>

      <div class="method-section">
        <h4>Active Connections</h4>
        <p class="card-desc">Local methods take precedence. Toggle to swap.</p>

        <div class="method-card" v-if="localActive">
          <div class="method-card-header">
            <Wifi :size="18" class="text-cyan" />
            <span><strong>Local:</strong> {{ localMethod }}</span>
            <span class="badge-local">Active</span>
          </div>
          <div class="method-card-actions">
            <button class="btn btn-secondary-outline btn-xs" @click="emit('swapPriority')">
              <RefreshCw :size="12" /> Prefer Remote
            </button>
          </div>
        </div>

        <div class="method-card" v-if="!localActive" style="opacity: 0.5;">
          <div class="method-card-header">
            <Wifi :size="18" />
            <span><strong>Local:</strong> None</span>
            <span class="badge-offline">Inactive</span>
          </div>
          <div class="method-card-actions">
            <button class="btn btn-secondary-outline btn-xs" @click="showPairModal = true">
              <Plus :size="12" /> Add Local Method
            </button>
          </div>
        </div>

        <div class="method-card" v-if="remoteActive">
          <div class="method-card-header">
            <Globe :size="18" class="text-indigo" />
            <span><strong>Remote:</strong> {{ remoteMethod }}</span>
            <span class="badge-remote">Active</span>
          </div>
        </div>

        <div class="method-card" v-if="!remoteActive" style="opacity: 0.5;">
          <div class="method-card-header">
            <Globe :size="18" />
            <span><strong>Remote:</strong> None</span>
            <span class="badge-offline">Inactive</span>
          </div>
          <div class="method-card-actions">
            <button class="btn btn-secondary-outline btn-xs" @click="showPairModal = true">
              <Plus :size="12" /> Add Remote Method
            </button>
          </div>
        </div>
      </div>

      <div class="fix-firewall-section" v-if="!localActive">
        <button class="btn btn-accent btn-sm" @click="emit('fixFirewall')">
          <Terminal :size="14" /> Fix Firewall (Polkit)
        </button>
        <p class="card-desc" style="margin-top: 0.5rem;">Triggers OS password dialog to allow LAN traffic.</p>
      </div>
    </div>

    <!-- Pairing Modal -->
    <div class="modal-overlay" v-if="showPairModal" @click.self="showPairModal = false">
      <div class="modal-content" style="max-width: 500px;">
        <h3 style="text-align: center; margin-bottom: 0.5rem;">Pair a Device</h3>
        <p class="card-desc" style="text-align: center;">Choose how your Android companion connects to this desktop.</p>

        <div v-if="!showLocalOptions && !showExternalOptions" class="pair-choice-grid">
          <div
            class="choice-card"
            :class="{ 'hovered': hoveredOption === 'local' }"
            @mouseenter="hoveredOption = 'local'"
            @mouseleave="hoveredOption = null"
            @click="showLocalOptions = true"
          >
            <div class="choice-icon">🏠</div>
            <h4>Pair Locally</h4>
            <p>Same network. Fast, low latency.</p>
            <div class="choice-methods">
              <span>Wi-Fi Direct</span>
              <span>mDNS</span>
              <span>Manual IP</span>
            </div>
          </div>
          <div
            class="choice-card"
            :class="{ 'hovered': hoveredOption === 'external' }"
            @mouseenter="hoveredOption = 'external'"
            @mouseleave="hoveredOption = null"
            @click="showExternalOptions = true"
          >
            <div class="choice-icon">🌍</div>
            <h4>Pair Externally</h4>
            <p>Over the internet. WAN / relay.</p>
            <div class="choice-methods">
              <span>Magic Wormhole</span>
              <span>Tor Onion</span>
            </div>
          </div>
        </div>

        <div v-if="showLocalOptions" class="method-list">
          <h4 style="margin-bottom: 0.75rem;">📍 Local Pairing Methods</h4>
          <div
            v-for="m in localMethods" :key="m.id"
            class="method-option"
            @click="handleLocalSelect(m.id)"
          >
            <span class="method-icon">{{ m.icon }}</span>
            <div>
              <strong>{{ m.label }}</strong>
              <p class="card-desc">{{ m.desc }}</p>
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" style="margin-top: 0.75rem;" @click="showLocalOptions = false">Back</button>
        </div>

        <div v-if="showExternalOptions" class="method-list">
          <h4 style="margin-bottom: 0.75rem;">🌍 External Pairing Methods</h4>
          <div
            v-for="m in externalMethods" :key="m.id"
            class="method-option"
            @click="handleExternalSelect(m.id)"
          >
            <span class="method-icon">{{ m.icon }}</span>
            <div>
              <strong>{{ m.label }}</strong>
              <p class="card-desc">{{ m.desc }}</p>
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" style="margin-top: 0.75rem;" @click="showExternalOptions = false">Back</button>
        </div>

        <div class="modal-actions" style="margin-top: 1rem;">
          <button class="btn btn-secondary" @click="showPairModal = false; showLocalOptions = false; showExternalOptions = false">Cancel</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.panel { padding: 1.5rem; }
.header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
.section-title { font-size: 1.3rem; font-weight: 800; }
.section-subtitle { font-size: 0.85rem; color: var(--text-secondary); }
.connect-prompt { display: flex; justify-content: center; padding: 3rem 0; }
.connect-card {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 20px;
  padding: 2.5rem; text-align: center; max-width: 380px; cursor: pointer;
  transition: all 0.3s ease;
}
.connect-card:hover { transform: translateY(-3px); border-color: var(--accent-cyan); box-shadow: 0 8px 30px rgba(6,182,212,0.15); }
.connect-card-icon { margin-bottom: 1rem; }
.paired-view { display: flex; flex-direction: column; gap: 1.5rem; }
.paired-header-card {
  background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px;
  padding: 1.5rem; display: flex; justify-content: space-between; align-items: center;
}
.paired-info { display: flex; align-items: center; gap: 1rem; }
.avatar-placeholder {
  width: 48px; height: 48px; border-radius: 50%; background: var(--accent-cyan);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.2rem; font-weight: bold; color: white;
}
.paired-actions { display: flex; gap: 0.5rem; }
.method-section h4 { margin-bottom: 0.25rem; }
.method-card {
  background: var(--bg-dark); border: 1px solid var(--border-color); border-radius: 12px;
  padding: 1rem; margin-bottom: 0.75rem;
}
.method-card-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
.method-card-actions { display: flex; gap: 0.5rem; }
.badge-local { background: rgba(6,182,212,0.15); color: var(--accent-cyan); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
.badge-remote { background: rgba(99,102,241,0.15); color: var(--accent-indigo); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
.badge-offline { background: rgba(239,68,68,0.15); color: #ef4444; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
.text-cyan { color: var(--accent-cyan); }
.text-indigo { color: var(--accent-indigo); }
.fix-firewall-section { margin-top: 0.5rem; }

.pair-choice-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 1.5rem 0; }
.choice-card {
  background: var(--bg-dark); border: 1px solid var(--border-color); border-radius: 16px;
  padding: 1.5rem; text-align: center; cursor: pointer;
  transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}
.choice-card.hovered { transform: translateY(-6px) scale(1.02); border-color: var(--accent-cyan); box-shadow: 0 12px 40px rgba(6,182,212,0.2); }
.choice-icon { font-size: 2.5rem; margin-bottom: 0.75rem; }
.choice-card h4 { margin-bottom: 0.25rem; }
.choice-card p { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.75rem; }
.choice-methods { display: flex; flex-wrap: wrap; gap: 0.25rem; justify-content: center; }
.choice-methods span { font-size: 0.65rem; background: rgba(99,102,241,0.1); color: var(--text-secondary); padding: 0.15rem 0.4rem; border-radius: 4px; }

.method-list { margin: 1rem 0; }
.method-option {
  display: flex; align-items: center; gap: 0.75rem;
  background: var(--bg-dark); border: 1px solid var(--border-color); border-radius: 12px;
  padding: 1rem; margin-bottom: 0.5rem; cursor: pointer;
  transition: all 0.2s ease;
}
.method-option:hover { border-color: var(--accent-cyan); background: rgba(6,182,212,0.05); }
.method-icon { font-size: 1.5rem; }

.modal-overlay {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.8); backdrop-filter: blur(8px);
  display: flex; justify-content: center; align-items: center; z-index: 1000;
}
.modal-content {
  background: var(--bg-card); border: 1px solid var(--border-color);
  border-radius: 16px; width: 90%; max-width: 480px; padding: 1.5rem;
  box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
}
.modal-actions { display: flex; justify-content: center; gap: 0.5rem; }

.btn { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; border: none; cursor: pointer; transition: all 0.2s ease; }
.btn-primary { background: var(--accent-cyan); color: #000; }
.btn-accent { background: var(--accent-indigo); color: white; }
.btn-secondary { background: rgba(148,163,184,0.15); color: var(--text-primary); }
.btn-danger-outline { background: transparent; border: 1px solid #ef4444; color: #ef4444; }
.btn-secondary-outline { background: transparent; border: 1px solid var(--border-color); color: var(--text-secondary); }
.btn-xs { padding: 0.3rem 0.6rem; font-size: 0.75rem; }
.btn-sm { padding: 0.4rem 0.8rem; font-size: 0.8rem; }
.card-desc { font-size: 0.8rem; color: var(--text-secondary); }
</style>
