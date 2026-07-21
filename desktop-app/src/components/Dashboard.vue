<script setup lang="ts">
defineProps<{
  sasCode: string;
}>();

const emit = defineEmits<{
  (e: "regenerateKeys"): void;
  (e: "navigate", tab: string): void;
}>();
</script>

<template>
  <section class="panel">
    <h2 class="section-title">System Overview</h2>
    
    <div class="sas-card">
      <div class="sas-header">
        <h3>Out-of-Band Safe Pairing</h3>
        <span class="sas-badge">MITM Verified</span>
      </div>
      <p class="sas-desc">Confirm this 6-digit cryptographic authentication string matches your mobile companion app screen:</p>
      <div class="sas-code-display">{{ sasCode }}</div>
    </div>

    <div class="quick-actions-box" style="margin-top: 2rem;">
      <h3>Quick Actions</h3>
      <div class="button-group">
        <button class="btn btn-primary" @click="emit('regenerateKeys')">
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
  </section>
</template>
