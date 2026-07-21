<script setup lang="ts">
import { ref } from "vue";

defineProps<{
  clipboardItems: string[];
  lastSyncStatus: string;
}>();

const emit = defineEmits<{
  (e: "add", text: string): void;
  (e: "copy", text: string): void;
  (e: "remove", index: number): void;
  (e: "saveEdit", payload: { index: number; text: string }): void;
}>();

const newText = ref("");
const editIndex = ref<number | null>(null);
const editText = ref("");

const handleAdd = () => {
  if (!newText.value.trim()) return;
  emit("add", newText.value.trim());
  newText.value = "";
};

const startEdit = (index: number, currentVal: string) => {
  editIndex.value = index;
  editText.value = currentVal;
};

const handleSave = (index: number) => {
  if (!editText.value.trim()) return;
  emit("saveEdit", { index, text: editText.value.trim() });
  editIndex.value = null;
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">Clipboard Manager</h2>

    <div class="editor-section">
      <h3>Sync New Clipboard Payload</h3>
      <div class="input-row">
        <input type="text" v-model="newText" placeholder="Type or paste payload content..." @keyup.enter="handleAdd" />
        <button class="btn btn-primary" @click="handleAdd">
          Add Clipboard Item
        </button>
      </div>
      <p class="status-msg" v-if="lastSyncStatus" style="margin-top: 0.5rem; color: var(--accent-cyan);">{{ lastSyncStatus }}</p>
    </div>

    <h3 style="margin-top: 1.5rem; margin-bottom: 0.5rem;">Active Sync Items</h3>
    <div class="msg-card-list">
      <div v-for="(item, index) in clipboardItems" :key="index" class="msg-card" style="padding: 1rem; border-radius: 12px; background: rgba(30, 41, 59, 0.6); margin-bottom: 0.5rem; border: 1px solid rgba(148, 163, 184, 0.2);">
        <div v-if="editIndex === index">
          <input type="text" v-model="editText" style="width: 100%; padding: 0.5rem; border-radius: 6px; background: #0f172a; color: white; border: 1px solid var(--border-color); margin-bottom: 0.5rem;" @keyup.enter="handleSave(index)" />
          <button class="btn btn-primary btn-sm" @click="handleSave(index)">Save</button>
          <button class="btn btn-secondary btn-sm" style="margin-left: 0.5rem;" @click="editIndex = null">Cancel</button>
        </div>
        <div v-else>
          <p style="margin: 0; font-size: 0.95rem; color: #cbd5e1; word-break: break-all;">{{ item }}</p>
          <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
            <button class="btn btn-primary btn-sm" @click="emit('copy', item)">Copy</button>
            <button class="btn btn-secondary btn-sm" @click="startEdit(index, item)">Edit</button>
            <button class="btn btn-panic btn-sm" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border-color: rgba(239, 68, 68, 0.4);" @click="emit('remove', index)">Delete</button>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
