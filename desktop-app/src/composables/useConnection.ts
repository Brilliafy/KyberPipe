import { ref, computed } from "vue";
import { invoke } from "@tauri-apps/api/core";

export interface SystemInfo {
  is_flatpak: boolean;
  platform: string;
  app_version: string;
  pqc_algorithm: string;
}

export interface KeyPair {
  x25519_pk_hex: string;
  mlkem_pk_hex: string;
}

export interface MediaAction {
  title: string;
  index: number;
}

export interface MediaState {
  title: string;
  artist: string;
  album_art: string;
  is_playing: boolean;
  actions: MediaAction[];
}

export function useConnection() {
  const connectionStatus = ref("DISCONNECTED");
  const connectionMethod = ref("None");
  const connectionColor = ref("red");
  const isConnected = computed(() => connectionColor.value === "green");
  const currentLatency = ref(0);

  const keyPair = ref<KeyPair | null>(null);
  const pairingConfigJson = ref("");

  const sasCode = ref("");
  const sasWords = ref(["", "", "", ""]);

  const showSasVerification = ref(false);
  const showPairingQr = ref(false);
  const showManualIpDialog = ref(false);

  const pairingQrData = ref("");
  const pairingQrUrl = ref("");

  const localMethod = ref("");
  const remoteMethod = ref("");
  const localActive = ref(false);
  const remoteActive = ref(false);
  const localPriority = ref(true);

  const deviceName = ref("My Linux Workstation");
  const devicePicture = ref("");
  const pairedDeviceName = ref("");
  const pairedDevicePicture = ref("");
  const isPaired = ref(false);
  const ddnsHostname = ref("");
  const enableUpnp = ref(false);
  const enableDdns = ref(false);
  const fileAccessGrantedDesktop = ref(false);
  const fileAccessGrantedPhone = ref(false);
  const pathwayOrder = ref<string[]>(["mdns_lan", "wireguard_wan"]);
  const themeMode = ref("auto");

  const mediaState = ref<MediaState | null>(null);
  const neuralAnomalyEnabled = ref(false);
  const flightRecorderEnabled = ref(false);
  const beaconDiscoveryEnabled = ref(false);

  const latencyColor = computed(() => {
    const ms = currentLatency.value;
    if (ms < 50) return '#22c55e';
    if (ms < 100) return '#84cc16';
    if (ms < 200) return '#facc15';
    if (ms < 500) return '#f97316';
    return '#ef4444';
  });

  const fetchMediaState = async () => {
    if (!isPaired.value) return;
    try {
      mediaState.value = await invoke<MediaState>("get_media_state");
    } catch (e) {
      console.error("Failed to fetch media state:", e);
    }
  };

  const handleMediaAction = async (actionIndex: number) => {
    try {
      // AUDIT P4-1(c)/P5-2: Tier-2 — requires a fresh native user-gesture
      // token (the command drives a remote side effect on the phone).
      const confirmed = window.confirm(
        "Trigger this media action on the paired phone?"
      );
      if (!confirmed) return;
      const token = await invoke<string>("request_privilege_token", {
        action: "trigger_desktop_media_action",
      });
      await invoke("trigger_desktop_media_action", { actionIndex, token });
    } catch (e) {
      console.error("Failed to trigger media action:", e);
    }
  };

  const loadSettings = async () => {
    try {
      const s = await invoke<any>("get_settings");
      deviceName.value = s.device_name || "My Linux Workstation";
      devicePicture.value = s.device_picture || "";
      pairedDeviceName.value = s.paired_device_name || "";
      pairedDevicePicture.value = s.paired_device_picture || "";
      ddnsHostname.value = s.ddns_hostname || "";
      enableUpnp.value = s.enable_upnp || false;
      enableDdns.value = s.enable_ddns || false;
      isPaired.value = s.is_paired || false;
      fileAccessGrantedDesktop.value = s.file_access_granted_desktop || false;
      fileAccessGrantedPhone.value = s.file_access_granted_phone || false;
      themeMode.value = s.theme_mode || "auto";
      pathwayOrder.value = s.pathway_order || ["mdns_lan", "wireguard_wan"];
      beaconDiscoveryEnabled.value = s.beacon_discovery_enabled || false;
    } catch (e) {
      console.error("Load settings error:", e);
    }
  };

  const saveSettings = async () => {
    try {
      await invoke("save_settings", {
        deviceName: deviceName.value,
        devicePicture: devicePicture.value,
        pairedDeviceName: pairedDeviceName.value,
        pairedDevicePicture: pairedDevicePicture.value,
        ddnsHostname: ddnsHostname.value,
        enableUpnp: enableUpnp.value,
        enableDdns: enableDdns.value,
        themeMode: themeMode.value,
        pathwayOrder: pathwayOrder.value,
        wireguardActive: true,
        beaconDiscoveryEnabled: beaconDiscoveryEnabled.value,
      });
    } catch (e) {
      console.error("Save settings error:", e);
    }
  };

  const checkConnectionState = async () => {
    try {
      const res = await invoke<any>("get_connection_status_full");
      connectionStatus.value = res.status;
      connectionMethod.value = res.method;
      connectionColor.value = res.color;
    } catch (e) {
      console.error(e);
      connectionStatus.value = "UNKNOWN";
      connectionColor.value = "red";
    }
  };

  const handleGenerateKeyPair = async () => {
    try {
      keyPair.value = await invoke<KeyPair>("generate_keypair");
    } catch (e) {
      console.error("Key generation error: ", e);
    }
  };

const handleDeleteConnection = async () => {
    // The renderer surfaces a user-gesture confirmation, then requests the
    // single-use privilege token so the destructive backend command is gated
    // like every other destructive action (audit finding #9).
    const confirmed = window.confirm(
      "Delete this connection? This clears the session key, ratchet state, and all pairing data on this desktop."
    );
    if (!confirmed) return;
    // Audit finding #13: NO optimistic state mutation before the backend
    // confirms — a rejected token request or a failed delete must not leave
    // the UI claiming "deleted" while the backend kept the pairing (or vice
    // versa). All local state flips happen only after the destructive command
    // succeeds.
    let token: string;
    try {
      token = await invoke<string>("request_privilege_token", {
        action: "delete_connection",
      });
    } catch (e) {
      console.error("Privilege token request failed:", e);
      alert("Delete failed: could not obtain a confirmation token.");
      return;
    }
    try {
      await invoke("delete_connection", { token });
      await invoke("set_connection_status_full", {
        status: "DISCONNECTED",
        method: "None",
        color: "red",
      });
      // Backend confirmed — now reconcile the mirror state.
      isPaired.value = false;
      pairedDeviceName.value = "";
      pairedDevicePicture.value = "";
      localMethod.value = "";
      remoteMethod.value = "";
      localActive.value = false;
      remoteActive.value = false;
    } catch (e) {
      console.error("Delete connection failed:", e);
      alert("Delete failed: " + e);
    }
  };

  const loadPairingConfig = async () => {
    if (!keyPair.value) return;
    try {
      // Audit F9 (regression): `get_pairing_config` is token-gated (KYP-2026-02
      // #6 hardening) but the renderer never passed a token, so every call
      // errored and the error was swallowed. Mint a fresh token for this exact
      // action and pass it through.
      const token = await invoke<string>("request_privilege_token", {
        action: "get_pairing_config",
      });
      const config = await invoke<any>("get_pairing_config", {
        hostPkHex: keyPair.value.mlkem_pk_hex,
        wireguardPkHex: keyPair.value.x25519_pk_hex,
        token,
      });
      pairingConfigJson.value = JSON.stringify(config);
    } catch (e) {
      console.error(e);
    }
  };

  return {
    connectionStatus, connectionMethod, connectionColor, isConnected,
    currentLatency, latencyColor,
    keyPair, pairingConfigJson,
    sasCode, sasWords,
    showSasVerification, showPairingQr, showManualIpDialog,
    pairingQrData, pairingQrUrl,
    localMethod, remoteMethod, localActive, remoteActive, localPriority,
    deviceName, devicePicture, pairedDeviceName, pairedDevicePicture,
    isPaired, ddnsHostname, enableUpnp, enableDdns,
    fileAccessGrantedDesktop, fileAccessGrantedPhone,
    pathwayOrder, themeMode,
    mediaState, neuralAnomalyEnabled, flightRecorderEnabled,
    beaconDiscoveryEnabled,
    fetchMediaState, handleMediaAction, loadSettings, saveSettings,
    checkConnectionState, handleGenerateKeyPair, handleDeleteConnection,
    loadPairingConfig,
  };
}
