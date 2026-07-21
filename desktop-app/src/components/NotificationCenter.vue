<script setup lang="ts">
import { ref } from "vue";

defineProps<{
  displayNotifications: Array<{
    id: string;
    source: string;
    title: string;
    body: string;
    appPackage: string;
    timestamp: string;
  }>;
  optimisticStatus: string | null;
}>();

const emit = defineEmits<{
  (e: "sendSms", payload: { sender: string; body: string }): void;
  (e: "sendNotif", payload: { title: string; text: string; app: string }): void;
}>();

const smsSender = ref("+1 (555) 019-2831");
const smsBody = ref("Verification code: 894-201");

const notifTitle = ref("Security Alert");
const notifText = ref("ML-KEM-768 Key Exchange initialized successfully.");
const notifApp = ref("com.kyberpipe.client");

const triggerSmsSim = () => {
  if (!smsSender.value || !smsBody.value) return;
  emit("sendSms", { sender: smsSender.value, body: smsBody.value });
};

const triggerNotifSim = () => {
  if (!notifTitle.value || !notifText.value) return;
  emit("sendNotif", { title: notifTitle.value, text: notifText.value, app: notifApp.value });
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">Notifications</h2>

    <div class="cards-grid" style="margin-bottom: 1.5rem;">
      <div class="card">
        <h3>Simulate Outbound SMS</h3>
        <div class="mock-form">
          <input v-model="smsSender" placeholder="Sender Phone" />
          <input v-model="smsBody" placeholder="Message Body" />
          <button class="btn btn-secondary btn-sm" @click="triggerSmsSim">Send Outbound SMS</button>
        </div>
      </div>

      <div class="card">
        <h3>Simulate Native Notification</h3>
        <div v-if="optimisticStatus" class="sas-card" style="background: rgba(34, 197, 94, 0.2); border-color: #22c55e; padding: 0.5rem 1rem; margin-bottom: 0.5rem;">
          Status: {{ optimisticStatus }}
        </div>
        <div class="mock-form">
          <input v-model="notifTitle" placeholder="Notification Title" />
          <input v-model="notifText" placeholder="Notification Body" />
          <button class="btn btn-secondary btn-sm" @click="triggerNotifSim">Mirror Native Notification</button>
        </div>
      </div>
    </div>

    <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">Mirrored Notification Log (Native Linux Desktop Synced)</h3>
    <div class="msg-card-list">
      <div class="msg-card" v-for="(n, i) in displayNotifications" :key="i" style="padding: 1rem; border-radius: 12px; background: rgba(30, 41, 59, 0.6); margin-bottom: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.2);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
          <strong style="color: var(--accent-cyan);">[{{ n.source }}] {{ n.title }}</strong>
          <span class="app-pkg" style="font-size: 0.75rem; opacity: 0.7;">{{ n.timestamp }}</span>
        </div>
        <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">{{ n.body }}</p>
      </div>
    </div>
  </section>
</template>
