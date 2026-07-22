<script setup lang="ts">
import { ref, computed } from "vue";

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
  displayNotifications: UnifiedNotification[];
  optimisticStatus: string | null;
  isConnected: boolean;
}>();

const emit = defineEmits<{
  (e: "sendSms", payload: { sender: string; body: string }): void;
  (e: "sendNotif", payload: { title: string; text: string; app: string }): void;
  (e: "connectDevice"): void;
}>();

const activeSubTab = ref<"all" | "local" | "remote">("all");
const outboundSmsRecipient = ref("");
const outboundSmsBody = ref("");

const mockNotifTitle = ref("");
const mockNotifBody = ref("");
const mockNotifApp = ref("com.android.vending");

const filteredNotifications = computed(() => {
  if (activeSubTab.value === "local") {
    return props.displayNotifications.filter(n => n.type === "local");
  }
  if (activeSubTab.value === "remote") {
    return props.displayNotifications.filter(n => n.type === "remote");
  }
  return props.displayNotifications;
});

const handleSendSms = () => {
  if (!outboundSmsRecipient.value.trim() || !outboundSmsBody.value.trim()) return;
  emit("sendSms", {
    sender: outboundSmsRecipient.value.trim(),
    body: outboundSmsBody.value.trim(),
  });
  outboundSmsBody.value = "";
};

const handleSendNotif = () => {
  if (!mockNotifTitle.value.trim() || !mockNotifBody.value.trim()) return;
  emit("sendNotif", {
    title: mockNotifTitle.value.trim(),
    text: mockNotifBody.value.trim(),
    app: mockNotifApp.value,
  });
  mockNotifTitle.value = "";
  mockNotifBody.value = "";
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">🔔 Notification & SMS Center</h2>
    <p class="section-subtitle">Real-time notification mirroring and remote SMS dispatching through secure ratchets.</p>

    <!-- Sub tabs -->
    <div class="tabs-header">
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'all' }" 
        @click="activeSubTab = 'all'"
      >
        ♾️ Combined Stream
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'local' }" 
        @click="activeSubTab = 'local'"
      >
        💻 This PC
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'remote' }" 
        @click="activeSubTab = 'remote'"
      >
        📱 Android Companion
      </button>
    </div>

    <!-- Empty state for remote notifications when phone is offline -->
    <div 
      class="not-connected-box" 
      v-if="activeSubTab === 'remote' && !isConnected"
    >
      <div class="empty-icon">🔌</div>
      <h3>Companion Phone Offline</h3>
      <p>Connect your Android companion device to view and interact with real-time remote notifications.</p>
      <button class="btn btn-primary" @click="emit('connectDevice')">
        Connect a Device
      </button>
    </div>

    <div v-else class="notifications-layout">
      <!-- Left side: List of notifications -->
      <div class="notifications-list-col">
        <h3>System Notification Logs</h3>
        <div class="empty-list" v-if="filteredNotifications.length === 0">
          <p>No notifications matched this filter.</p>
        </div>
        <div class="msg-card-list" v-else>
          <div 
            v-for="notif in filteredNotifications" 
            :key="notif.id" 
            class="msg-card"
          >
            <div class="entry-meta">
              <span class="source-badge" :class="notif.type">
                {{ notif.type === 'local' ? '💻 Local' : '📱 Remote' }}
              </span>
              <span class="timestamp">{{ notif.timestamp }}</span>
            </div>
            <h4 class="notif-title">{{ notif.title }}</h4>
            <p class="notif-body">{{ notif.body }}</p>
            <span class="app-package-label">{{ notif.appPackage }}</span>
          </div>
        </div>
      </div>

      <!-- Right side: Simulators / Senders -->
      <div class="notifications-actions-col">
        <!-- Outbound SMS Sender -->
        <div class="actions-card">
          <h3>Send Outbound SMS</h3>
          <p class="card-desc">Simulate sending a secure P2P SMS through your connected Android device.</p>
          
          <div class="form-group">
            <label>Recipient Number:</label>
            <input type="text" v-model="outboundSmsRecipient" placeholder="e.g. +1 (555) 019-2834" class="input-text" />
          </div>

          <div class="form-group">
            <label>Message Content:</label>
            <textarea v-model="outboundSmsBody" placeholder="Type SMS message..." class="input-textarea"></textarea>
          </div>

          <button class="btn btn-primary" @click="handleSendSms" :disabled="!isConnected">
            Dispatch SMS
          </button>
          <p v-if="optimisticStatus" class="optimistic-msg">{{ optimisticStatus }}</p>
        </div>

        <!-- Notification Mirroring Simulator -->
        <div class="actions-card">
          <h3>Local Notification Simulator</h3>
          <p class="card-desc">Mirror a new notification event onto this PC to test post-quantum routing.</p>
          
          <div class="form-group">
            <label>Application Package:</label>
            <select v-model="mockNotifApp" class="input-select">
              <option value="com.android.vending">Google Play Store</option>
              <option value="com.whatsapp">WhatsApp Messenger</option>
              <option value="org.thoughtcrime.securesms">Signal Private Messenger</option>
              <option value="com.google.android.apps.messaging">Google Messages</option>
            </select>
          </div>

          <div class="form-group">
            <label>Notification Title:</label>
            <input type="text" v-model="mockNotifTitle" placeholder="e.g. System Update" class="input-text" />
          </div>

          <div class="form-group">
            <label>Notification Body:</label>
            <input type="text" v-model="mockNotifBody" placeholder="e.g. Dynamic ratchet re-key success." class="input-text" />
          </div>

          <button class="btn btn-accent" @click="handleSendNotif">
            Mirror Notification
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
.tabs-header {
  display: flex;
  gap: 1rem;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
  margin-bottom: 1.5rem;
}
.tab-btn {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-weight: 700;
  cursor: pointer;
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-size: 0.95rem;
  transition: all 0.2s ease;
}
.tab-btn.active {
  background: rgba(99, 102, 241, 0.15);
  color: var(--accent-cyan);
}
.tab-btn:hover:not(.active) {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.02);
}
.not-connected-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 3rem 2rem;
  background: rgba(15, 23, 42, 0.2);
  border: 1px solid var(--border-color);
  border-radius: 12px;
}
.empty-icon {
  font-size: 3rem;
  margin-bottom: 1rem;
}
.not-connected-box h3 {
  font-size: 1.2rem;
  font-weight: 800;
  margin-bottom: 0.5rem;
}
.not-connected-box p {
  color: var(--text-secondary);
  font-size: 0.85rem;
  max-width: 350px;
  margin-bottom: 1.5rem;
}
.notifications-layout {
  display: grid;
  grid-template-columns: 1.2fr 0.8fr;
  gap: 1.5rem;
}
@media (max-width: 1024px) {
  .notifications-layout {
    grid-template-columns: 1fr;
  }
}
.notifications-list-col h3 {
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
}
.empty-list {
  text-align: center;
  padding: 3rem;
  color: var(--text-secondary);
  background: rgba(15, 23, 42, 0.1);
  border-radius: 12px;
}
.msg-card {
  padding: 1.25rem;
  border-radius: 12px;
  background: rgba(30, 41, 59, 0.4);
  margin-bottom: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.1);
}
.entry-meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.source-badge {
  font-size: 0.7rem;
  font-weight: bold;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}
.source-badge.local {
  background: rgba(99, 102, 241, 0.2);
  color: #a5b4fc;
}
.source-badge.remote {
  background: rgba(6, 182, 212, 0.2);
  color: #a5f3fc;
}
.timestamp {
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.notif-title {
  font-size: 1rem;
  font-weight: 700;
  color: white;
  margin-bottom: 0.25rem;
}
.notif-body {
  font-size: 0.85rem;
  color: #cbd5e1;
  line-height: 1.4;
  margin-bottom: 0.5rem;
}
.app-package-label {
  font-family: monospace;
  font-size: 0.7rem;
  color: var(--text-secondary);
}
.notifications-actions-col {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}
.actions-card {
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
}
.actions-card h3 {
  font-size: 1.1rem;
  margin-bottom: 0.25rem;
}
.card-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 1rem;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  margin-bottom: 1rem;
}
.form-group label {
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.input-text, .input-select, .input-textarea {
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  padding: 0.5rem;
  border-radius: 6px;
  font-size: 0.85rem;
  outline: none;
}
.input-textarea {
  height: 80px;
  resize: none;
}
.input-text:focus, .input-select:focus, .input-textarea:focus {
  border-color: var(--accent-indigo);
}
.optimistic-msg {
  font-size: 0.8rem;
  color: var(--accent-cyan);
  margin-top: 0.5rem;
}
</style>
