<script setup lang="ts">
import { ref, computed } from "vue";
import { 
  Bell, 
  Layers, 
  Monitor, 
  Smartphone, 
  AlertCircle,
  MessageSquare,
  Check,
  Archive,
  VolumeX
} from '@lucide/vue';
import { invoke } from "@tauri-apps/api/core";

interface UnifiedNotification {
  id: string;
  sbn_key?: string;
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
  (e: "connectDevice"): void;
}>();

const activeSubTab = ref<"all" | "local" | "remote">("all");
const selectedNotif = ref<UnifiedNotification | null>(null);
const replyText = ref("");
const actionStatus = ref("");

const filteredNotifications = computed(() => {
  const list = props.displayNotifications;
  if (activeSubTab.value === "local") {
    return list.filter(n => n.type === "local");
  }
  if (activeSubTab.value === "remote") {
    return list.filter(n => n.type === "remote");
  }
  return list;
});

const isReplyable = computed(() => {
  if (!selectedNotif.value) return false;
  const pkg = selectedNotif.value.appPackage.toLowerCase();
  return pkg.includes("whatsapp") || 
         pkg.includes("securesms") || 
         pkg.includes("messaging") || 
         pkg.includes("telephony.sms") || 
         selectedNotif.value.type === "remote";
});

const selectNotification = (notif: UnifiedNotification) => {
  selectedNotif.value = notif;
  replyText.value = "";
  actionStatus.value = "";
};

const handleSendReply = async () => {
  if (!selectedNotif.value || !replyText.value.trim()) return;
  try {
    actionStatus.value = "Sending reply via secure tunnel...";
    const sbnKey = selectedNotif.value.sbn_key || selectedNotif.value.id;
    await invoke("trigger_notification_action", {
      sbnKey: sbnKey,
      actionIndex: 0,
      actionTitle: `Reply: ${replyText.value.trim()}`
    });
    actionStatus.value = "Reply successfully sent!";
    replyText.value = "";
    setTimeout(() => { actionStatus.value = ""; }, 3000);
  } catch (e) {
    actionStatus.value = `Reply failed: ${e}`;
  }
};

const handleTriggerAction = async (index: number, title: string) => {
  if (!selectedNotif.value) return;
  try {
    actionStatus.value = `Triggering ${title}...`;
    const sbnKey = selectedNotif.value.sbn_key || selectedNotif.value.id;
    await invoke("trigger_notification_action", {
      sbnKey: sbnKey,
      actionIndex: index,
      actionTitle: title
    });
    actionStatus.value = `Action '${title}' executed!`;
    setTimeout(() => { actionStatus.value = ""; }, 3000);
  } catch (e) {
    actionStatus.value = `Action failed: ${e}`;
  }
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title"><Bell style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="24" /> Notification & SMS Center</h2>
    <p class="section-subtitle">Real-time notification mirroring and remote PQC reply actions.</p>

    <!-- Sub tabs -->
    <div class="tabs-header">
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'all' }" 
        @click="activeSubTab = 'all'"
      >
        <Layers style="margin-right: 0.25rem;" :size="14" /> Combined Stream
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'local' }" 
        @click="activeSubTab = 'local'"
      >
        <Monitor style="margin-right: 0.25rem;" :size="14" /> This PC
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'remote' }" 
        @click="activeSubTab = 'remote'"
      >
        <Smartphone style="margin-right: 0.25rem;" :size="14" /> Android Companion
      </button>
    </div>

    <!-- Empty state for remote notifications when phone is offline -->
    <div 
      class="not-connected-box" 
      v-if="activeSubTab === 'remote' && !isConnected"
    >
      <AlertCircle class="empty-icon" :size="48" style="color: var(--accent-indigo);" />
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
          <p>No notifications matched this view.</p>
        </div>
        <div class="msg-card-list" v-else>
          <div 
            v-for="notif in filteredNotifications" 
            :key="notif.id" 
            class="msg-card"
            :class="{ active: selectedNotif?.id === notif.id }"
            @click="selectNotification(notif)"
          >
            <div class="entry-meta">
              <span class="source-badge" :class="notif.type">
                <component :is="notif.type === 'local' ? Monitor : Smartphone" :size="12" style="margin-right: 0.25rem; vertical-align: middle;" />
                {{ notif.type === 'local' ? 'Local' : 'Remote' }}
              </span>
              <span class="timestamp">{{ notif.timestamp }}</span>
            </div>
            <h4 class="notif-title">{{ notif.title }}</h4>
            <p class="notif-body">{{ notif.body }}</p>
            <span class="app-package-label">{{ notif.appPackage }}</span>
          </div>
        </div>
      </div>

      <!-- Right side: Selected notification actions / details -->
      <div class="notifications-actions-col">
        <div class="actions-card" v-if="selectedNotif">
          <h3>Notification Details</h3>
          <p class="card-desc">Execute P2P operations and quick replies directly over the secure link.</p>
          
          <div class="detail-group">
            <span class="detail-label">Source app:</span>
            <span class="detail-value">{{ selectedNotif.appPackage }}</span>
          </div>

          <div class="detail-group">
            <span class="detail-label">Title:</span>
            <span class="detail-value font-bold">{{ selectedNotif.title }}</span>
          </div>

          <div class="detail-group">
            <span class="detail-label">Body:</span>
            <p class="detail-text">{{ selectedNotif.body }}</p>
          </div>

          <!-- Native Reply Integration -->
          <div class="reply-section" v-if="isReplyable">
            <div class="form-group">
              <label>Native Quick Reply:</label>
              <input 
                type="text" 
                v-model="replyText" 
                placeholder="Type your response..." 
                class="input-text" 
                @keyup.enter="handleSendReply"
              />
            </div>
            <button class="btn btn-primary" @click="handleSendReply" :disabled="!replyText.trim() || !isConnected">
              <MessageSquare style="margin-right: 0.25rem;" :size="14" /> Send Reply
            </button>
          </div>

          <!-- Expose actions/buttons -->
          <div class="actions-buttons-list" v-if="selectedNotif.type === 'remote'">
            <label class="action-list-label">Available Remote Actions:</label>
            <div class="buttons-grid">
              <button class="btn btn-secondary-outline btn-sm" @click="handleTriggerAction(1, 'Mark as Read')" :disabled="!isConnected">
                <Check :size="12" style="margin-right:0.25rem" /> Mark as Read
              </button>
              <button class="btn btn-secondary-outline btn-sm" @click="handleTriggerAction(2, 'Archive')" :disabled="!isConnected">
                <Archive :size="12" style="margin-right:0.25rem" /> Archive
              </button>
              <button class="btn btn-secondary-outline btn-sm" @click="handleTriggerAction(3, 'Mute')" :disabled="!isConnected">
                <VolumeX :size="12" style="margin-right:0.25rem" /> Mute App
              </button>
            </div>
          </div>

          <p v-if="actionStatus" class="action-status-msg">{{ actionStatus }}</p>
        </div>

        <div class="actions-card empty-details" v-else>
          <AlertCircle :size="36" class="empty-details-icon" />
          <h4>No Notification Selected</h4>
          <p>Click any item in the list to view diagnostic parameters, quick replies, and P2P native actions.</p>
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
  display: flex;
  align-items: center;
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
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 12px;
}
.empty-icon {
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
  grid-template-columns: 1.15fr 0.85fr;
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
  background: var(--bg-dark);
  border-radius: 12px;
}
.msg-card {
  padding: 1.25rem;
  border-radius: 12px;
  background: var(--bg-card);
  margin-bottom: 0.75rem;
  border: 1px solid var(--border-color);
  cursor: pointer;
  transition: all 0.2s ease;
}
.msg-card:hover {
  border-color: var(--accent-cyan);
  background: rgba(255, 255, 255, 0.02);
}
.msg-card.active {
  border-color: var(--accent-cyan);
  background: rgba(6, 182, 212, 0.05);
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
  display: flex;
  align-items: center;
}
.source-badge.local {
  background: rgba(99, 102, 241, 0.2);
  color: var(--accent-indigo);
}
.source-badge.remote {
  background: rgba(6, 182, 212, 0.2);
  color: var(--accent-cyan);
}
.timestamp {
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.notif-title {
  font-size: 1rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.25rem;
}
.notif-body {
  font-size: 0.85rem;
  color: var(--text-primary);
  line-height: 1.4;
  margin-bottom: 0.5rem;
}
.app-package-label {
  font-family: monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.notifications-actions-col {
  display: flex;
  flex-direction: column;
}
.actions-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
  min-height: 300px;
  display: flex;
  flex-direction: column;
}
.actions-card h3 {
  font-size: 1.1rem;
  margin-bottom: 0.25rem;
}
.card-desc {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
}
.detail-group {
  margin-bottom: 0.85rem;
}
.detail-label {
  display: block;
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-bottom: 0.15rem;
}
.detail-value {
  font-size: 0.85rem;
  color: var(--text-primary);
  font-family: monospace;
}
.detail-value.font-bold {
  font-family: inherit;
  font-weight: 700;
}
.detail-text {
  font-size: 0.85rem;
  color: var(--text-primary);
  line-height: 1.4;
}
.reply-section {
  margin-top: 1.25rem;
  border-top: 1px solid var(--border-color);
  padding-top: 1rem;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  margin-bottom: 0.75rem;
}
.form-group label {
  font-size: 0.8rem;
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
  border-color: var(--accent-cyan);
}
.action-list-label {
  display: block;
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-top: 1rem;
  margin-bottom: 0.5rem;
}
.buttons-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.btn-sm {
  font-size: 0.75rem !important;
  padding: 0.35rem 0.65rem !important;
}
.action-status-msg {
  font-size: 0.8rem;
  color: var(--accent-cyan);
  margin-top: 1rem;
}
.empty-details {
  align-items: center;
  justify-content: center;
  text-align: center;
  color: var(--text-secondary);
}
.empty-details-icon {
  margin-bottom: 0.75rem;
  color: var(--text-secondary);
}
.empty-details h4 {
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.35rem;
}
.empty-details p {
  font-size: 0.8rem;
  max-width: 240px;
}
</style>
