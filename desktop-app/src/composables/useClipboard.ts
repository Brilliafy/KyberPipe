import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

export interface ClipboardRecord {
  id: string;
  text: string;
  source: "pc" | "phone";
  timestamp: number;
}

export function useClipboard() {
  const clipboardItems = ref<ClipboardRecord[]>([]);
  const lastSyncStatus = ref("");

  const pollClipboard = async () => {
    try {
      const text = await invoke<string>("read_real_clipboard");
      if (text && text.trim() !== "") {
        const exists = clipboardItems.value.some(item => item.text === text);
        if (!exists) {
          clipboardItems.value.unshift({
            id: "clip_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
            text,
            source: "pc",
            timestamp: Date.now()
          });
          await invoke("sync_clipboard", { text });
        }
      }
    } catch (_) {}
  };

  const handleAddClipboard = async (text: string) => {
    clipboardItems.value.unshift({
      id: "clip_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
      text,
      source: "pc",
      timestamp: Date.now()
    });
    try {
      await invoke("write_real_clipboard", { text });
      await invoke("sync_clipboard", { text });
      lastSyncStatus.value = "Synced item locally & pushed remote";
    } catch (e) {
      lastSyncStatus.value = "Sync warning: " + e;
    }
  };

  const handleCopyClipboard = async (text: string) => {
    try {
      await invoke("write_real_clipboard", { text });
      lastSyncStatus.value = "Copied to desktop clipboard";
    } catch (e) {
      lastSyncStatus.value = "Copy failed: " + e;
    }
  };

  const handleRemoveClipboard = (id: string) => {
    clipboardItems.value = clipboardItems.value.filter(item => item.id !== id);
    lastSyncStatus.value = "Item removed";
  };

  const handleSaveEditClipboard = async (payload: { id: string; text: string }) => {
    const idx = clipboardItems.value.findIndex(item => item.id === payload.id);
    if (idx !== -1) {
      clipboardItems.value[idx].text = payload.text;
      try {
        await invoke("write_real_clipboard", { text: payload.text });
        await invoke("sync_clipboard", { text: payload.text });
        lastSyncStatus.value = "Updated and synced item";
      } catch (e) {
        lastSyncStatus.value = "Update warning: " + e;
      }
    }
  };

  return {
    clipboardItems,
    lastSyncStatus,
    pollClipboard,
    handleAddClipboard,
    handleCopyClipboard,
    handleRemoveClipboard,
    handleSaveEditClipboard,
  };
}
