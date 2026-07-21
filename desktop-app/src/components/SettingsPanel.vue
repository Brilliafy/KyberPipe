<script setup lang="ts">
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
}>();

const emit = defineEmits<{
  (e: "update:flightRecorderEnabled", val: boolean): void;
  (e: "update:neuralAnomalyEnabled", val: boolean): void;
  (e: "regenerateKeys"): void;
}>();
</script>

<template>
  <section class="panel">
    <h2 class="section-title">Settings</h2>

    <div class="cards-grid" style="margin-bottom: 2rem;">
      <div class="card" style="padding: 1.5rem;">
        <h3>Sub-Nanosecond Flight Data Recorder</h3>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
          Lock-free sub-nanosecond binary event tracing ring buffer for post-mortem diagnostics.
        </p>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <input 
            type="checkbox" 
            id="check-flight" 
            :checked="flightRecorderEnabled" 
            @change="emit('update:flightRecorderEnabled', ($event.target as HTMLInputElement).checked)" 
          />
          <label for="check-flight">Enable Flight Data Recorder (qlog)</label>
        </div>
      </div>

      <div class="card" style="padding: 1.5rem;">
        <h3>Neuromorphic Anomaly Engine</h3>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">
          Real-time eBPF packet-timing anomaly detection & auto-isolation.
        </p>
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <input 
            type="checkbox" 
            id="check-anomaly" 
            :checked="neuralAnomalyEnabled" 
            @change="emit('update:neuralAnomalyEnabled', ($event.target as HTMLInputElement).checked)" 
          />
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

      <button class="btn btn-primary" @click="emit('regenerateKeys')">
        Regenerate Cryptographic Keys
      </button>
    </div>
  </section>
</template>
