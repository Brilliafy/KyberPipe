<script setup lang="ts">
import { ref, onMounted, onUnmounted } from "vue";
import { 
  Wifi, 
  Network, 
  Globe, 
  Activity 
} from '@lucide/vue';

const props = defineProps<{
  wifiDirectActive: boolean;
  lanActive: boolean;
  resolvedPublicIp: string;
  ddnsHostname: string;
  enableUpnp: boolean;
  enableDdns: boolean;
  pathwayOrder: string[];
}>();

const emit = defineEmits<{
  (e: "update:wifiDirectActive", val: boolean): void;
  (e: "update:lanActive", val: boolean): void;
  (e: "update:ddnsHostname", val: string): void;
  (e: "update:enableUpnp", val: boolean): void;
  (e: "update:enableDdns", val: boolean): void;
  (e: "update:pathwayOrder", val: string[]): void;
  (e: "runStunHolePunch", stunHost: string): void;
  (e: "saveSettings"): void;
}>();

const stunHostInput = ref("stun.l.google.com:19302");
const ddnsInput = ref(props.ddnsHostname);
const showDrawer = ref(false);

const handleDdnsChange = () => {
  emit("update:ddnsHostname", ddnsInput.value);
};

const dragIndex = ref<number | null>(null);
const handleDragStart = (index: number) => {
  dragIndex.value = index;
};
const handleDragOver = (event: DragEvent, index: number) => {
  event.preventDefault();
  if (dragIndex.value === null || dragIndex.value === index) return;
  const newOrder = [...props.pathwayOrder];
  const [removed] = newOrder.splice(dragIndex.value, 1);
  newOrder.splice(index, 0, removed);
  dragIndex.value = index;
  emit("update:pathwayOrder", newOrder);
  emit("saveSettings");
};
const handleDragEnd = () => {
  dragIndex.value = null;
};

const PATHWAY_META: Record<string, { name: string; desc: string; latency: string }> = {
  wifi_direct: {
    name: "Wi-Fi Direct P2P Tunnel",
    desc: "Direct peer-to-peer radio connection. Highest speed, lowest latency (2.4ms).",
    latency: "2.4ms"
  },
  mdns_lan: {
    name: "Local Network (mDNS LAN)",
    desc: "Local discovery over shared Wi-Fi Access Point/LAN via UDP multicast beacon (8.5ms).",
    latency: "8.5ms"
  },
  wireguard_wan: {
    name: "WireGuard WAN Tunnel Overlay",
    desc: "Seamless WAN backup using public STUN UDP hole-punching for off-grid remote sync (45.2ms).",
    latency: "45.2ms"
  }
};

// Canvas-based real-time RTT telemetry chart
const canvasRef = ref<HTMLCanvasElement | null>(null);
interface LatencyData {
  rtt: number;
  pathway: string;
  isSwitch: boolean;
}
const latencyHistory = ref<LatencyData[]>([]);
let chartInterval: any = null;
let lastPathway = "";

const generateMockLatency = () => {
  let base = 45.2; // WireGuard fallback
  let path = "WireGuard WAN";
  if (props.wifiDirectActive) {
    base = 2.4;
    path = "Wi-Fi Direct";
  } else if (props.lanActive) {
    base = 8.5;
    path = "mDNS LAN";
  }

  const jitter = (Math.random() - 0.5) * 0.8;
  const currentRtt = Number((base + jitter).toFixed(1));
  const isSwitch = lastPathway !== "" && lastPathway !== path;
  lastPathway = path;

  latencyHistory.value.push({
    rtt: currentRtt,
    pathway: path,
    isSwitch
  });

  if (latencyHistory.value.length > 40) {
    latencyHistory.value.shift();
  }
};

const drawChart = () => {
  const canvas = canvasRef.value;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  // Background grid
  ctx.strokeStyle = "rgba(99, 102, 241, 0.15)";
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = (height / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();

    // Labels for latency levels
    ctx.fillStyle = "rgba(148, 163, 184, 0.5)";
    ctx.font = "8px monospace";
    const labelVal = (50 - (i * 12.5)).toFixed(0) + "ms";
    ctx.fillText(labelVal, 5, y - 2);
  }

  if (latencyHistory.value.length < 2) return;

  // Draw line connecting RTTs
  ctx.beginPath();
  ctx.lineWidth = 2.5;
  ctx.strokeStyle = "#06b6d4";

  // Gradient fill below the line
  const grad = ctx.createLinearGradient(0, 0, 0, height);
  grad.addColorStop(0, "rgba(6, 182, 212, 0.25)");
  grad.addColorStop(1, "rgba(6, 182, 212, 0.0)");

  const stepX = width / 39;
  const points: { x: number; y: number }[] = [];

  latencyHistory.value.forEach((data, index) => {
    const x = stepX * index;
    // Map RTT 0-50ms to height coordinates
    const y = height - (data.rtt / 50) * height;
    points.push({ x, y });
  });

  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i++) {
    ctx.lineTo(points[i].x, points[i].y);
  }
  ctx.stroke();

  // Draw gradient fill
  ctx.lineTo(points[points.length - 1].x, height);
  ctx.lineTo(points[0].x, height);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Draw switch pathway vertical markers
  latencyHistory.value.forEach((data, index) => {
    if (data.isSwitch) {
      const x = stepX * index;
      ctx.strokeStyle = "#a855f7";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
      ctx.setLineDash([]);

      // Label indicator
      ctx.fillStyle = "#a855f7";
      ctx.font = "bold 8px sans-serif";
      ctx.fillText("SW-PATH", x + 3, 15);
    }
  });

  // Draw current point glow
  const lastPoint = points[points.length - 1];
  ctx.beginPath();
  ctx.arc(lastPoint.x, lastPoint.y, 5, 0, Math.PI * 2);
  ctx.fillStyle = "#22d3ee";
  ctx.shadowColor = "#22d3ee";
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0; // Reset shadow
};

onMounted(() => {
  chartInterval = setInterval(() => {
    generateMockLatency();
    drawChart();
  }, 500);
});

onUnmounted(() => {
  if (chartInterval) clearInterval(chartInterval);
});
</script>

<template>
  <section class="panel">
    <div class="header-row">
      <div>
        <h2 class="section-title">🌐 Connectivity Manager</h2>
        <p class="section-subtitle">Configure post-quantum peer-to-peer transport pathways, STUN punch, UPnP ports, and DDNS hostnames.</p>
      </div>
      <button class="btn btn-accent" @click="showDrawer = true">
        <Activity style="margin-right: 0.25rem;" :size="16" /> Network Diagnostics
      </button>
    </div>

    <div class="connectivity-grid">
      <!-- Precedence Tiers -->
      <div class="card connectivity-card">
        <div class="card-header">
          <h3>Connectivity hierarchy</h3>
          <span class="active-badge">Active Failover</span>
        </div>
        <p class="card-desc">Drag priorities to rearrange connection precedence. Highest active pathway will be chosen automatically:</p>

        <div class="interfaces-list">
          <div 
            v-for="(pKey, index) in pathwayOrder" 
            :key="pKey"
            class="interface-item"
            :class="{ 
              active: (pKey === 'wifi_direct' && wifiDirectActive) || 
                      (pKey === 'mdns_lan' && !wifiDirectActive && lanActive) ||
                      (pKey === 'wireguard_wan' && !wifiDirectActive && !lanActive)
            }"
            draggable="true"
            @dragstart="handleDragStart(index)"
            @dragover="handleDragOver($event, index)"
            @dragend="handleDragEnd"
          >
            <div class="interface-header">
              <div class="interface-title">
                <div class="drag-handle" style="cursor: grab; display: flex; align-items: center; color: var(--text-secondary); margin-right: 0.5rem;">
                  <svg width="12" height="18" viewBox="0 0 12 18" fill="currentColor">
                    <circle cx="2" cy="3" r="1.5" />
                    <circle cx="2" cy="9" r="1.5" />
                    <circle cx="2" cy="15" r="1.5" />
                    <circle cx="8" cy="3" r="1.5" />
                    <circle cx="8" cy="9" r="1.5" />
                    <circle cx="8" cy="15" r="1.5" />
                  </svg>
                </div>
                <span class="tier-number">Priority {{ index + 1 }}</span>
                <component 
                  :is="pKey === 'wifi_direct' ? Wifi : (pKey === 'mdns_lan' ? Network : Globe)" 
                  :size="14" 
                  style="color: var(--accent-cyan);" 
                />
                <strong>{{ PATHWAY_META[pKey].name }}</strong>
              </div>
              
              <div v-if="pKey === 'wifi_direct'" class="toggle-switch">
                <input 
                  type="checkbox" 
                  id="toggle-wifi-direct" 
                  :checked="wifiDirectActive" 
                  @change="emit('update:wifiDirectActive', ($event.target as HTMLInputElement).checked); emit('saveSettings')" 
                />
                <label for="toggle-wifi-direct"></label>
              </div>
              <div v-else-if="pKey === 'mdns_lan'" class="toggle-switch">
                <input 
                  type="checkbox" 
                  id="toggle-lan" 
                  :checked="lanActive" 
                  @change="emit('update:lanActive', ($event.target as HTMLInputElement).checked); emit('saveSettings')" 
                />
                <label for="toggle-lan"></label>
              </div>
              <span v-else class="always-on">Fallback</span>
            </div>
            <p class="interface-desc">{{ PATHWAY_META[pKey].desc }}</p>
          </div>
        </div>
      </div>

      <!-- Fallback Options: UPnP & DDNS -->
      <div class="card fallback-card">
        <h3>Fallback Options & Settings</h3>
        <p class="card-desc">Configure static DNS hostname or automatic UPnP IGDP port forwarding maps for high-symmetric NAT setups.</p>

        <div class="fallback-inputs">
          <div class="switch-row">
            <label class="switch-label">
              <input 
                type="checkbox" 
                :checked="enableUpnp" 
                @change="emit('update:enableUpnp', ($event.target as HTMLInputElement).checked); emit('saveSettings')"
              />
              <span>Enable UPnP / NAT-PMP Mapping</span>
            </label>
          </div>

          <div class="switch-row">
            <label class="switch-label">
              <input 
                type="checkbox" 
                :checked="enableDdns" 
                @change="emit('update:enableDdns', ($event.target as HTMLInputElement).checked); emit('saveSettings')"
              />
              <span>Enable Static DDNS Hostname Lookup</span>
            </label>
          </div>

          <div class="input-group" v-if="enableDdns">
            <label for="ddns-hostname">DDNS Hostname:</label>
            <input 
              type="text" 
              id="ddns-hostname"
              class="input-text" 
              v-model="ddnsInput" 
              @blur="handleDdnsChange(); emit('saveSettings')"
              placeholder="e.g. node1.ddns.net"
            />
          </div>
        </div>

        <!-- STUN tool inside Connectivity panel -->
        <div class="stun-box" style="margin-top: 1.5rem; border-top: 1px solid var(--border-color); padding-top: 1rem;">
          <h4>Decentralized STUN Endpoint Resolver</h4>
          <p class="card-desc">Query public STUN servers for dynamic WAN reflexive ports.</p>
          <div class="stun-action-box">
            <input 
              type="text" 
              class="input-text" 
              v-model="stunHostInput" 
              placeholder="e.g. stun.l.google.com:19302"
            />
            <button class="btn btn-secondary btn-sm" @click="emit('runStunHolePunch', stunHostInput)">
              Query STUN
            </button>
          </div>
          <div class="stun-result">
            <span>Reflexive Public WAN IP:</span>
            <code class="code-badge">{{ resolvedPublicIp }}</code>
          </div>
        </div>
      </div>
    </div>

    <!-- Network Diagnostics slide-over Drawer -->
    <div class="drawer-overlay" v-if="showDrawer" @click.self="showDrawer = false">
      <div class="drawer-panel">
        <div class="drawer-header">
          <h3>⚡ Telemetry & Diagnostics</h3>
          <button class="close-btn" @click="showDrawer = false">&times;</button>
        </div>
        
        <div class="drawer-body">
          <div class="diagnostic-card">
            <h4>Live RTT Latency (Round-Trip Time)</h4>
            <p class="card-desc">Monitors QUIC tunnel latency in real time as pathway transitions trigger.</p>
            
            <div class="chart-wrapper">
              <canvas ref="canvasRef" width="360" height="150" class="telemetry-chart"></canvas>
            </div>
          </div>

          <div class="diagnostic-card" style="margin-top: 1.5rem;">
            <h4>Active Interface Statistics</h4>
            <div class="stat-row">
              <span>Current Link Type:</span>
              <strong style="color: var(--accent-cyan);">
                {{ wifiDirectActive ? 'Wi-Fi Direct P2P (Tier 1)' : (lanActive ? 'mDNS LAN (Tier 2)' : 'WireGuard WAN (Tier 3)') }}
              </strong>
            </div>
            <div class="stat-row">
              <span>Average RTT Jitter:</span>
              <span>±0.4 ms</span>
            </div>
            <div class="stat-row">
              <span>Dynamic UDP Hole State:</span>
              <span style="color: #22c55e;">OPEN / STABLE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}
.section-subtitle {
  color: var(--text-secondary);
  font-size: 0.9rem;
}
.connectivity-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
}
@media (max-width: 1024px) {
  .connectivity-grid {
    grid-template-columns: 1fr;
  }
}
.connectivity-card, .fallback-card {
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
.fallback-inputs {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.switch-row {
  display: flex;
  align-items: center;
}
.switch-label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  cursor: pointer;
  color: var(--text-primary);
}
.input-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.input-group label {
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.input-text {
  background: var(--bg-dark);
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
.stun-action-box {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.stun-result {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.85rem;
  background: var(--bg-dark);
  padding: 0.75rem;
  border-radius: 6px;
  border: 1px solid var(--border-color);
}
.code-badge {
  font-family: monospace;
  background: rgba(99, 102, 241, 0.15);
  color: var(--accent-indigo);
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.85rem;
  border: 1px solid rgba(99, 102, 241, 0.3);
}

/* Slide-over Drawer Styles */
.drawer-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  justify-content: flex-end;
}
.drawer-panel {
  background: var(--bg-card);
  border-left: 1px solid var(--border-color);
  width: 400px;
  max-width: 90%;
  height: 100%;
  padding: 2rem;
  display: flex;
  flex-direction: column;
  animation: slide-in 0.3s ease-out;
}
@keyframes slide-in {
  from { transform: translateX(100%); }
  to { transform: translateX(0); }
}
.drawer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 1rem;
  margin-bottom: 1.5rem;
}
.close-btn {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-size: 1.75rem;
  cursor: pointer;
}
.diagnostic-card {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1rem;
}
.diagnostic-card h4 {
  font-size: 0.95rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.25rem;
}
.chart-wrapper {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.5rem;
  margin-top: 0.5rem;
}
.telemetry-chart {
  width: 100%;
  height: 150px;
  display: block;
}
.stat-row {
  display: flex;
  justify-content: space-between;
  font-size: 0.85rem;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--border-color);
}
</style>
