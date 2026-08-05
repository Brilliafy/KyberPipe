import { ref, type Ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

interface PairingDialogDeps {
  isPaired: Ref<boolean>;
  checkConnectionState: () => Promise<void>;
}

/**
 * SAS pairing modal state + backend pairing event listeners.
 *
 * F21 (audit KYP-2026-02): the old 1.5 s SAS poller is gone. The modal is
 * surfaced through the `pairing::sas-ready` / `pairing::complete` /
 * `pairing::timeout` events pushed from Rust (audit finding #13), so the UI
 * cannot drift from backend state. `pollPairingStatus` remains for the
 * settings-tick reconciliation while the modal is open.
 */
export function usePairingDialogs(deps: PairingDialogDeps) {
  const showSasVerification = ref(false);
  const sasWords = ref<string[]>(["", "", "", ""]);
  const sasCode = ref("");
  // SAS code the user types from the phone's display (audit finding #7).
  const sasInput = ref("");

  let unlistenSasReady: (() => void) | null = null;
  let unlistenPairingComplete: (() => void) | null = null;
  let unlistenPairingTimeout: (() => void) | null = null;

  /// Poll the backend for a pending SAS and surface the modal. The SAS is
  /// displayed on the PHONE; the user must TYPE it here (audit finding #7 —
  /// the old flow rubber-stamped the desktop's own code).
  const pollPairingStatus = async () => {
    try {
      const status = await invoke<any>("get_pairing_status");
      if (!status) return;
      if (status.is_paired) {
        // If the backend completed pairing (or we just confirmed it), close
        // the modal and let the dashboard reconcile via get_settings.
        if (showSasVerification.value) {
          showSasVerification.value = false;
        }
        return;
      }
      if (status.pending && status.sas_code) {
        sasCode.value = status.sas_code;
        sasWords.value = (status.sas_code.match(/.{1,2}/g) || []).slice(0, 4);
        showSasVerification.value = true;
      }
    } catch (e) {
      // Backend command may not exist yet in dev — ignore.
      console.warn("get_pairing_status failed:", e);
    }
  };

  const startSasListeners = async () => {
    if (unlistenSasReady) return; // already registered
    const { listen } = await import("@tauri-apps/api/event");
    unlistenSasReady = await listen("pairing::sas-ready", () => {
      pollPairingStatus();
    });
    unlistenPairingComplete = await listen("pairing::complete", () => {
      showSasVerification.value = false;
      deps.isPaired.value = true;
      deps.checkConnectionState();
    });
    unlistenPairingTimeout = await listen("pairing::timeout", () => {
      showSasVerification.value = false;
      sasInput.value = "";
    });
  };

  const stopSasListeners = () => {
    if (unlistenSasReady) {
      unlistenSasReady();
      unlistenSasReady = null;
    }
    if (unlistenPairingComplete) {
      unlistenPairingComplete();
      unlistenPairingComplete = null;
    }
    if (unlistenPairingTimeout) {
      unlistenPairingTimeout();
      unlistenPairingTimeout = null;
    }
  };

  return {
    showSasVerification,
    sasCode,
    sasInput,
    pollPairingStatus,
    startSasListeners,
    stopSasListeners,
  };
}
