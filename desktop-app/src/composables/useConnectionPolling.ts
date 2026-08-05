import { ref, computed, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { useHeartbeat } from './useHeartbeat';

export function useConnectionPolling() {
  // Connection state
  const connectionStatus = ref("DISCONNECTED");
  const connectionMethod = ref("None");
  const connectionColor = ref("red");
  const isConnected = computed(() => connectionColor.value === "green");

  // Firewall modal
  const showFirewallModal = ref(false);

  // Retry attempt counter
  const attemptCount = ref(0);

  // AUDIT F7: the periodic status refresh now subscribes to the SHARED
  // renderer heartbeat (useHeartbeat) instead of owning a private 2 s
  // interval. The background settings sync and the latency reset subscribe to
  // the same ticker, so their IPC calls and ref writes are ALIGNED in one
  // macrotask instead of racing with arbitrary phase offsets (the
  // yellow/green flicker source). startPolling/stopPolling keep their public
  // shape for existing callers but are now subscribe/unsubscribe handles.
  let unsubscribe: (() => void) | null = null;

  /**
   * Fetch the latest connection status from the backend and update refs.
   */
  const checkConnectionState = async () => {
    try {
      const res = await invoke<any>("get_connection_status_full");
      connectionStatus.value = res.status;
      connectionMethod.value = res.method;
      connectionColor.value = res.color;
    } catch (e) {
      console.error(e);
    }
  };

  /**
   * Initiate a connection attempt: set status to WAITING FOR COMPANION
   * (yellow) unless already connected, then refresh state.
   *
   * NOTE: The original App.vue variant also checks pairing state and calls
   * refreshLogs(). Callers composing with usePairing/useSettings should
   * wrap this with their own pairing guard and log refresh.
   */
  const triggerConnectionAttempt = async () => {
    if (isConnected.value) return;

    // Audit finding #13: guard the invoke so a rejection (command unavailable
    // in dev, backend busy) cannot become an unhandled promise rejection.
    try {
      await invoke("set_connection_status_full", {
        status: "WAITING FOR COMPANION",
        method: "None",
        color: "yellow",
      });
    } catch (e) {
      console.error("Connection attempt failed:", e);
      return;
    }
    await checkConnectionState();
  };

  /**
   * Reset the attempt counter and trigger a fresh connection attempt.
   */
  const handleManualRetry = () => {
    attemptCount.value = 0;
    // Fire-and-forget with error containment (audit finding #13).
    triggerConnectionAttempt().catch((e) =>
      console.error("Manual retry failed:", e)
    );
  };

  /**
   * Subscribe the status refresh to the shared heartbeat (AUDIT F7).
   * Safe to call multiple times — unsubscribes any existing handle first.
   */
  const startPolling = () => {
    stopPolling();
    unsubscribe = useHeartbeat(checkConnectionState);
  };

  /**
   * Unsubscribe the status refresh from the shared heartbeat.
   */
  const stopPolling = () => {
    if (unsubscribe !== null) {
      unsubscribe();
      unsubscribe = null;
    }
  };

  // Auto-start polling on mount. Cleanup is handled by the heartbeat's own
  // onUnmounted (the shared ticker stops when the last subscriber leaves), so
  // no separate onUnmounted teardown is needed here.
  onMounted(async () => {
    await checkConnectionState();
    startPolling();
  });

  return {
    connectionStatus,
    connectionMethod,
    connectionColor,
    isConnected,
    showFirewallModal,
    attemptCount,
    checkConnectionState,
    triggerConnectionAttempt,
    handleManualRetry,
    startPolling,
    stopPolling,
  };
}
