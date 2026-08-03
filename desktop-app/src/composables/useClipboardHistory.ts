import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

export interface ClipboardRecord {
  id: string;
  text: string;
  source: "pc" | "phone";
  timestamp: number;
}

/** Minimum spacing between gesture-triggered clipboard reads (ms). */
const POLL_THROTTLE_MS = 1500;

/** User gestures that count as "the user is actively using the app". */
const GESTURE_EVENTS = ["mousemove", "keydown", "pointerdown"] as const;

/**
 * Clipboard history state + record helpers.
 *
 * F6-renderer (audit KYP-2026-02): `read_real_clipboard` now requires a
 * single-use user-gesture privilege token, so the old unconditional 1.5 s
 * timer is gone. Polling is driven by document gesture listeners throttled to
 * at most one read per 1.5 s; each read requests a fresh token and passes it
 * along. A rejected token (Err) is silently skipped — the app simply
 * continues without refreshing clipboard history that tick.
 */
export function useClipboardHistory(deps?: { onSynced?: () => void }) {
  const clipboardItems = ref<ClipboardRecord[]>([]);
  const lastSyncStatus = ref("");

  let lastPollAt = 0;
  let polling = false;

  const makeRecord = (text: string): ClipboardRecord => ({
    id: "clip_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9),
    text,
    source: "pc",
    timestamp: Date.now(),
  });

  const pollClipboard = async () => {
    if (polling) return;
    polling = true;
    try {
      const token = await invoke<string>("request_privilege_token", {
        action: "read_real_clipboard",
      });
      const text = await invoke<string>("read_real_clipboard", { token });
      if (text && text.trim() !== "") {
        const exists = clipboardItems.value.some((item) => item.text === text);
        if (!exists) {
          clipboardItems.value.unshift(makeRecord(text));
          await invoke("sync_clipboard", { text });
        }
      }
    } catch {
      // Token rejection or clipboard read failure (empty/binary content):
      // silently skip this tick.
    } finally {
      polling = false;
    }
  };

  const onGesture = () => {
    const now = Date.now();
    if (now - lastPollAt < POLL_THROTTLE_MS) return;
    lastPollAt = now;
    void pollClipboard();
  };

  const startClipboardSync = () => {
    stopClipboardSync();
    for (const evt of GESTURE_EVENTS) {
      document.addEventListener(evt, onGesture, { passive: true });
    }
  };

  const stopClipboardSync = () => {
    for (const evt of GESTURE_EVENTS) {
      document.removeEventListener(evt, onGesture);
    }
  };

  const addRecord = async (text: string) => {
    clipboardItems.value.unshift(makeRecord(text));
    try {
      await invoke("write_real_clipboard", { text });
      await invoke("sync_clipboard", { text });
      lastSyncStatus.value = "Synced item locally & pushed remote";
      deps?.onSynced?.();
    } catch (e) {
      lastSyncStatus.value = "Sync warning: " + e;
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await invoke("write_real_clipboard", { text });
      lastSyncStatus.value = "Copied to desktop clipboard";
    } catch (e) {
      lastSyncStatus.value = "Copy failed: " + e;
    }
  };

  const removeRecord = (id: string) => {
    clipboardItems.value = clipboardItems.value.filter((item) => item.id !== id);
    lastSyncStatus.value = "Item removed";
  };

  const updateRecord = async (payload: { id: string; text: string }) => {
    const idx = clipboardItems.value.findIndex((item) => item.id === payload.id);
    if (idx === -1) return;
    clipboardItems.value[idx].text = payload.text;
    try {
      await invoke("write_real_clipboard", { text: payload.text });
      await invoke("sync_clipboard", { text: payload.text });
      lastSyncStatus.value = "Updated and synced item";
      deps?.onSynced?.();
    } catch (e) {
      lastSyncStatus.value = "Update warning: " + e;
    }
  };

  return {
    clipboardItems,
    lastSyncStatus,
    pollClipboard,
    startClipboardSync,
    stopClipboardSync,
    addRecord,
    copyToClipboard,
    removeRecord,
    updateRecord,
  };
}
