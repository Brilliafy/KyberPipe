<script setup lang="ts">
import { ref, computed } from "vue";
import { 
  Clipboard, 
  Layers, 
  Monitor, 
  Smartphone, 
  Plus, 
  Copy, 
  Edit2, 
  Trash2, 
  Save, 
  X, 
  AlertCircle 
} from '@lucide/vue';

interface ClipboardRecord {
  id: string;
  text: string;
  source: "pc" | "phone";
  timestamp: number;
}

const props = defineProps<{
  clipboardItems: ClipboardRecord[];
  lastSyncStatus: string;
  isConnected: boolean;
}>();

const emit = defineEmits<{
  (e: "add", text: string): void;
  (e: "copy", text: string): void;
  (e: "remove", id: string): void;
  (e: "saveEdit", payload: { id: string; text: string }): void;
  (e: "connectDevice"): void;
}>();

const activeSubTab = ref<"all" | "pc" | "phone">("all");
const newText = ref("");
const editId = ref<string | null>(null);
const editText = ref("");

const filteredItems = computed(() => {
  if (activeSubTab.value === "pc") {
    return props.clipboardItems.filter(item => item.source === "pc");
  }
  if (activeSubTab.value === "phone") {
    return props.clipboardItems.filter(item => item.source === "phone");
  }
  return props.clipboardItems;
});

const handleAdd = () => {
  if (!newText.value.trim()) return;
  emit("add", newText.value.trim());
  newText.value = "";
};

const startEdit = (id: string, currentVal: string) => {
  editId.value = id;
  editText.value = currentVal;
};

const handleSave = (id: string) => {
  if (!editText.value.trim()) return;
  emit("saveEdit", { id, text: editText.value.trim() });
  editId.value = null;
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title"><Clipboard style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="24" /> Secure Clipboard Sync</h2>
    <p class="section-subtitle">Real-time MIME clipboard sharing over encrypted post-quantum channels.</p>

    <!-- Sub tabs -->
    <div class="tabs-header">
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'all' }" 
        @click="activeSubTab = 'all'"
      >
        <Layers style="margin-right: 0.25rem;" :size="14" /> Combined History
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'pc' }" 
        @click="activeSubTab = 'pc'"
      >
        <Monitor style="margin-right: 0.25rem;" :size="14" /> This PC
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'phone' }" 
        @click="activeSubTab = 'phone'"
      >
        <Smartphone style="margin-right: 0.25rem;" :size="14" /> Android Companion
      </button>
    </div>

    <!-- Empty / Not Connected screen for Phone tab -->
    <div 
      class="not-connected-box" 
      v-if="activeSubTab === 'phone' && !isConnected"
    >
      <AlertCircle class="empty-icon" :size="48" style="color: var(--accent-indigo);" />
      <h3>Companion Phone Offline</h3>
      <p>Please pair and connect your Android companion node to view remote clipboard events.</p>
      <button class="btn btn-primary" @click="emit('connectDevice')">
        Connect a Device
      </button>
    </div>

    <div v-else>
      <!-- Sync new payload -->
      <div class="editor-section">
        <h3>Sync New Clipboard Payload</h3>
        <div class="input-row">
          <input type="text" v-model="newText" placeholder="Type or paste payload content..." @keyup.enter="handleAdd" />
          <button class="btn btn-primary" @click="handleAdd">
            <Plus style="margin-right: 0.25rem;" :size="16" /> Sync Content
          </button>
        </div>
        <p class="status-msg" v-if="lastSyncStatus">{{ lastSyncStatus }}</p>
      </div>

      <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">Clipboard Entries</h3>
      
      <!-- Empty state when list is empty -->
      <div class="empty-list" v-if="filteredItems.length === 0">
        <p>No clipboard history available in this view.</p>
      </div>

      <div class="msg-card-list" v-else>
        <div 
          v-for="item in filteredItems" 
          :key="item.id" 
          class="msg-card"
        >
          <div v-if="editId === item.id">
            <input type="text" v-model="editText" class="edit-input" @keyup.enter="handleSave(item.id)" />
            <button class="btn btn-primary btn-sm" @click="handleSave(item.id)">
              <Save style="margin-right: 0.25rem;" :size="12" /> Save
            </button>
            <button class="btn btn-secondary btn-sm" style="margin-left: 0.5rem;" @click="editId = null">
              <X style="margin-right: 0.25rem;" :size="12" /> Cancel
            </button>
          </div>
          <div v-else>
            <div class="entry-meta">
              <span class="source-badge" :class="item.source">
                <component :is="item.source === 'pc' ? Monitor : Smartphone" :size="12" style="margin-right: 0.25rem; vertical-align: middle;" />
                {{ item.source === 'pc' ? 'PC' : 'Android' }}
              </span>
              <span class="timestamp">{{ new Date(item.timestamp).toLocaleTimeString() }}</span>
            </div>
            <p class="clipboard-text">{{ item.text }}</p>
            <div class="card-actions">
              <button class="btn btn-primary btn-sm" @click="emit('copy', item.text)">
                <Copy style="margin-right: 0.25rem;" :size="12" /> Copy
              </button>
              <button class="btn btn-secondary btn-sm" @click="startEdit(item.id, item.text)">
                <Edit2 style="margin-right: 0.25rem;" :size="12" /> Edit
              </button>
              <button class="btn-delete btn-sm" @click="emit('remove', item.id)">
                <Trash2 style="margin-right: 0.25rem;" :size="12" /> Delete
              </button>
            </div>
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
  background: rgba(15, 23, 42, 0.2);
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
.editor-section {
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
  margin-bottom: 1.5rem;
}
.editor-section h3 {
  font-size: 1rem;
  margin-bottom: 0.5rem;
}
.input-row {
  display: flex;
  gap: 0.75rem;
}
.input-row input {
  flex: 1;
  background: #0f172a;
  color: white;
  border: 1px solid var(--border-color);
  padding: 0.6rem 1rem;
  border-radius: 8px;
  font-size: 0.9rem;
}
.status-msg {
  margin-top: 0.5rem;
  color: var(--accent-cyan);
  font-size: 0.8rem;
}
.empty-list {
  text-align: center;
  padding: 2rem;
  color: var(--text-secondary);
  background: rgba(15, 23, 42, 0.1);
  border-radius: 8px;
}
.msg-card {
  padding: 1rem;
  border-radius: 12px;
  background: rgba(30, 41, 59, 0.4);
  margin-bottom: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.1);
}
.edit-input {
  width: 100%;
  padding: 0.5rem;
  border-radius: 6px;
  background: #0f172a;
  color: white;
  border: 1px solid var(--border-color);
  margin-bottom: 0.5rem;
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
.source-badge.pc {
  background: rgba(99, 102, 241, 0.2);
  color: #a5b4fc;
}
.source-badge.phone {
  background: rgba(6, 182, 212, 0.2);
  color: #a5f3fc;
}
.timestamp {
  font-size: 0.75rem;
  color: var(--text-secondary);
}
.clipboard-text {
  font-size: 0.95rem;
  color: #cbd5e1;
  word-break: break-all;
  white-space: pre-wrap;
}
.card-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}
.btn-delete {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.2);
  padding: 0.4rem 0.8rem;
  border-radius: 8px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s ease;
  font-size: 0.8rem;
  display: flex;
  align-items: center;
}
.btn-delete:hover {
  background: #ef4444;
  color: white;
}
</style>
