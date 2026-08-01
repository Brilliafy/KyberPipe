import { ref, computed, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

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

  // Poller handle
  let connPoller: ReturnType<typeof setInterval> | null = null;

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

    await invoke("set_connection_status_full", {
      status: "WAITING FOR COMPANION",
      method: "None",
      color: "yellow"
    });
    await checkConnectionState();
  };

  /**
   * Reset the attempt counter and trigger a fresh connection attempt.
   */
  const handleManualRetry = () => {
    attemptCount.value = 0;
    triggerConnectionAttempt();
  };

  /**
   * Start the periodic connection-status poller (2 s interval).
   * Safe to call multiple times – stops any existing poller first.
   */
  const startPolling = () => {
    stopPolling();
    connPoller = setInterval(checkConnectionState, 2000);
  };

  /**
   * Stop the periodic poller if running.
   */
  const stopPolling = () => {
    if (connPoller !== null) {
      clearInterval(connPoller);
      connPoller = null;
    }
  };

  // Auto-start polling on mount, clean up on unmount
  onMounted(async () => {
    await checkConnectionState();
    startPolling();
  });

  onUnmounted(() => {
    stopPolling();
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
