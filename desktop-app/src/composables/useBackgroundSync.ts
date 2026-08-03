import { type ComputedRef, type Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

export interface BackgroundSyncDeps {
  isPaired: Ref<boolean>;
  deviceName: Ref<string>;
  devicePicture: Ref<string>;
  pairedDeviceName: Ref<string>;
  pairedDevicePicture: Ref<string>;
  isConnected: ComputedRef<boolean>;
  triggerConnectionAttempt: () => Promise<void>;
  fetchMediaState: () => Promise<void>;
  pollPairingStatus: () => Promise<void>;
  showSasVerification: Ref<boolean>;
}

const SETTINGS_TICK_MS = 2000;

/**
 * Single settings/status reconciliation poller (2 s tick).
 *
 * F21 (audit KYP-2026-02): this is the ONLY settings-interval timer left in
 * the app. It folds in the old "custom poller" from App.vue — reads
 * get_settings, auto-retries the connection while paired-but-disconnected,
 * refreshes media state, and reconciles the SAS dialog against the backend
 * while it is open. Clipboard polling is gesture-driven (F6-renderer) and SAS
 * state comes from backend events, so no other timer is needed.
 */
export function useBackgroundSync(deps: BackgroundSyncDeps) {
  let settingsPoller: ReturnType<typeof setInterval> | null = null;

  const syncTick = async () => {
    try {
      const settings = await invoke<Record<string, unknown>>("get_settings");
      deps.isPaired.value = (settings.is_paired as boolean) || false;
      deps.deviceName.value = (settings.device_name as string) || "Linux Workstation";
      deps.devicePicture.value = (settings.device_picture as string) || "";
      deps.pairedDeviceName.value = (settings.paired_device_name as string) || "";
      deps.pairedDevicePicture.value = (settings.paired_device_picture as string) || "";

      if (deps.isPaired.value && !deps.isConnected.value) {
        deps.triggerConnectionAttempt();
      }

      await deps.fetchMediaState();

      // Reconcile pairing state against the BACKEND (audit finding #7): the
      // old flow only trusted local state, which drifted from the backend.
      if (deps.showSasVerification.value) {
        deps.pollPairingStatus();
      }
    } catch (e) {
      console.error("Poll status error:", e);
    }
  };

  const startBackgroundSync = () => {
    stopBackgroundSync();
    settingsPoller = setInterval(syncTick, SETTINGS_TICK_MS);
  };

  const stopBackgroundSync = () => {
    if (settingsPoller !== null) {
      clearInterval(settingsPoller);
      settingsPoller = null;
    }
  };

  return {
    syncTick,
    startBackgroundSync,
    stopBackgroundSync,
  };
}
