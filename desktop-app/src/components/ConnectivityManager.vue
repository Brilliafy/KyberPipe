<script setup lang="ts">
import { ref } from "vue";

const props = defineProps<{
  wifiDirectActive: boolean;
  lanActive: boolean;
  resolvedPublicIp: string;
  ddnsHostname: string;
  enableUpnp: boolean;
  enableDdns: boolean;
}>();

const emit = defineEmits<{
  (e: "update:wifiDirectActive", val: boolean): void;
  (e: "update:lanActive", val: boolean): void;
  (e: "update:ddnsHostname", val: string): void;
  (e: "update:enableUpnp", val: boolean): void;
  (e: "update:enableDdns", val: boolean): void;
  (e: "runStunHolePunch", stunHost: string): void;
  (e: "saveSettings"): void;
}>();

const stunHostInput = ref("stun.l.google.com:19302");
const ddnsInput = ref(props.ddnsHostname);

const handleDdnsChange = () => {
  emit("update:ddnsHostname", ddnsInput.value);
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">🌐 Connectivity Manager</h2>
    <p class="section-subtitle">Configure post-quantum peer-to-peer transport pathways, STUN punch, UPnP ports, and DDNS hostnames.</p>

    <div class="connectivity-grid">
      <!-- Precedence Tiers -->
      <div class="card connectivity-card">
        <div class="card-header">
          <h3>3-Tier Connectivity Hierarchy</h3>
          <span class="active-badge">Active Failover</span>
        </div>
        <p class="card-desc">Toggles simulated local pathways. Best available transport path resolves automatically:</p>

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
  </section>
</template>

<style scoped>
.section-subtitle {
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-bottom: 1.5rem;
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
</style>
