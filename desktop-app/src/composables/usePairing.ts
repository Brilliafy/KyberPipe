import { ref, type Ref, type ComputedRef } from "vue";
import { invoke } from "@tauri-apps/api/core";
import QRCode from "qrcode";
import type { KeyPair /* exported from useConnection */ } from "./useConnection";

export interface FirewallStatus {
  firewalld_active: boolean;
  ufw_active: boolean;
  port_open: boolean;
  commands: string[];
}

interface PairingDeps {
  keyPair: Ref<KeyPair | null>;
  isPaired: Ref<boolean>;
  pairedDeviceName: Ref<string>;
  pairedDevicePicture: Ref<string>;
  deviceName: Ref<string>;
  devicePicture: Ref<string>;
  localMethod: Ref<string>;
  remoteMethod: Ref<string>;
  localActive: Ref<boolean>;
  remoteActive: Ref<boolean>;
  pairingConfigJson: Ref<string>;
  pairingQrData: Ref<string>;
  pairingQrUrl: Ref<string>;
  showPairingQr: Ref<boolean>;
  showManualIpDialog: Ref<boolean>;
  showSasVerification: Ref<boolean>;
  sasWords: Ref<string[]>;
  sasCode: Ref<string>;
  isConnected: ComputedRef<boolean>;
  connectionStatus: Ref<string>;
  connectionMethod: Ref<string>;
  connectionColor: Ref<string>;

  saveSettings: () => Promise<void>;
  handleGenerateKeyPair: () => Promise<void>;
  handleDeleteConnection: () => Promise<void>;
  loadPairingConfig: () => Promise<void>;
  checkConnectionState: () => Promise<void>;
  refreshLogs: () => Promise<void>;
}

export function usePairing(deps: PairingDeps) {
  const {
    keyPair,
    isPaired,
    deviceName,
    localMethod,
    remoteMethod,
    localActive,
    remoteActive,
    pairingQrData,
    pairingQrUrl,
    showPairingQr,
    showManualIpDialog,
    showSasVerification,
    sasWords,
    sasCode,
    saveSettings,
    checkConnectionState,
    refreshLogs,
  } = deps;

  // Manual IP input state
  const manualIpInput = ref("");
  const manualPortInput = ref("9876");

  /// Fetch the QR pairing nonce issued by the backend (audit finding #5) and the
  /// server certificate hash (audit finding #15). The renderer must embed BOTH
  /// in every pairing QR payload: the phone echoes the nonce so the server's
  /// blind-race check passes, and pins the QR-bound cert hash so a bootstrap
  /// MITM cannot become the permanent trusted identity.
  const fetchQrBindingFields = async (): Promise<Record<string, string>> => {
    let nonce = "";
    let serverCertHash = "";
    try {
      nonce = (await invoke<string>("get_pairing_nonce")) || "";
    } catch (e) {
      console.warn("get_pairing_nonce failed:", e);
    }
    try {
      serverCertHash = (await invoke<string>("get_server_cert_hash")) || "";
    } catch (e) {
      console.warn("get_server_cert_hash failed:", e);
    }
    return {
      pairing_nonce_hex: nonce,
      server_cert_hash: serverCertHash,
    };
  };

  /// Merge the QR binding fields into a payload object, dropping empty entries.
  const withQrBinding = (
    payload: Record<string, unknown>,
    binding: Record<string, string>,
  ): Record<string, unknown> => {
    const merged: Record<string, unknown> = { ...payload };
    if (binding.pairing_nonce_hex) merged.pairing_nonce_hex = binding.pairing_nonce_hex;
    if (binding.server_cert_hash) merged.server_cert_hash = binding.server_cert_hash;
    return merged;
  };

  /// Render a QR payload with the binding fields already merged.
  const buildPairingQr = async (payload: Record<string, unknown>) => {
    const binding = await fetchQrBindingFields();
    pairingQrData.value = JSON.stringify(withQrBinding(payload, binding));
    pairingQrUrl.value = await QRCode.toDataURL(pairingQrData.value, {
      margin: 2,
      scale: 6,
      errorCorrectionLevel: "L",
    });
    showPairingQr.value = true;
  };

  // Firewall state
  const showFirewallModal = ref(false);
  const firewallStatus = ref<FirewallStatus | null>(null);
  const firewallBusy = ref(false);
  const firewallResult = ref("");

  // Connection attempt tracking
  const attemptCount = ref(0);

  // --- Handlers ---

  // "Complete Pairing" is removed as a local fake-pair path (audit finding
  // #7): pairing can only complete through the real SAS confirmation command
  // with a code the user typed from the phone. This function now merely
  // surfaces the current backend pairing state.
  const handleCompletePairing = async () => {
    try {
      const status = await invoke<any>("get_pairing_status");
      if (status && status.pending && status.sas_code) {
        sasCode.value = status.sas_code;
        showSasVerification.value = true;
      }
      await checkConnectionState();
    } catch (e) {
      console.error("Failed to read pairing status:", e);
    }
  };

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

  const confirmSas = async (enteredSas: string) => {
    const code = (enteredSas ?? "").trim();
    if (code.length === 0) {
      alert("Enter the SAS code shown on your phone before confirming.");
      return;
    }
    try {
      await invoke("confirm_pairing_sas", {
        verifiedSas: code,
        pairedName: "Android Companion"
      });
      localActive.value = true;
      localMethod.value = "manual_ip";
      isPaired.value = true;
      await saveSettings();
    } catch (e) {
      console.error("SAS Confirmation failed:", e);
      alert("SAS verification failed: " + e);
    }
    showSasVerification.value = false;
  };

  const rejectSas = () => {
    showSasVerification.value = false;
    sasCode.value = "";
  };

  const handlePairLocally = async (method: string) => {
    localMethod.value = method;
    localActive.value = true;
    if (method === "wifi_direct") {
      try {
        const p2pInfo = await invoke<any>("create_p2p_group");
        await buildPairingQr({
          method: "p2p",
          ssid: p2pInfo.ssid,
          pass: p2pInfo.passphrase,
          p2p_ip: p2pInfo.ip,
          wifi_direct_mac: p2pInfo.mac,
          pqc_pub: keyPair.value?.mlkem_pk_hex || "",
          x25519_pub: keyPair.value?.x25519_pk_hex || "",
        });
      } catch (e) {
        console.error("P2P group creation failed:", e);
      }
    } else if (method === "mdns") {
      await buildPairingQr({
        method: "mdns",
        service: "_kyberpipe._tcp.local",
        name: deviceName.value,
        pqc_pub: keyPair.value?.mlkem_pk_hex || "",
        x25519_pub: keyPair.value?.x25519_pk_hex || "",
      });
    } else if (method === "manual_ip") {
      showManualIpDialog.value = true;
    }
  };

  const handlePairExternally = async (method: string) => {
    remoteMethod.value = method;
    remoteActive.value = true;
    if (method === "wormhole") {
      try {
        const code = await invoke<string>("generate_wormhole_code");
        await buildPairingQr({
          method: "wormhole",
          code: code,
          pqc_pub: keyPair.value?.mlkem_pk_hex || "",
          x25519_pub: keyPair.value?.x25519_pk_hex || "",
        });
      } catch (e) {
        console.error("Wormhole code generation failed:", e);
      }
    } else if (method === "tor") {
      try {
        const onion = await invoke<any>("create_tor_onion");
        if (onion.onion_address) {
          await buildPairingQr({
            method: "tor",
            onion: onion.onion_address,
            auth_key: onion.auth_key,
            pqc_pub: keyPair.value?.mlkem_pk_hex || "",
            x25519_pub: keyPair.value?.x25519_pk_hex || "",
          });
        }
      } catch (e) {
        console.error("Tor onion creation failed:", e);
      }
    }
  };

  const submitManualPairing = async () => {
    const ip = manualIpInput.value.trim();
    if (!ip) return;
    await buildPairingQr({
      method: "manual_ip",
      host: ip,
      port: parseInt(manualPortInput.value) || 9876,
      pqc_pub: keyPair.value?.mlkem_pk_hex || "",
      x25519_pub: keyPair.value?.x25519_pk_hex || "",
    });
    showManualIpDialog.value = false;
  };


  const triggerConnectionAttempt = async () => {
    if (!isPaired.value) {
      await invoke("set_connection_status_full", {
        status: "DISCONNECTED (No paired device)",
        method: "None",
        color: "red",
      });
      await checkConnectionState();
      return;
    }

    const res = await invoke<any>("get_connection_status_full");
    if (res.color === "green") {
      return; // Already connected
    }

    await invoke("set_connection_status_full", {
      status: "WAITING FOR COMPANION",
      method: "None",
      color: "yellow",
    });
    await checkConnectionState();
    await refreshLogs();
  };

  const handleManualRetry = () => {
    attemptCount.value = 0;
    triggerConnectionAttempt();
  };

  const checkFirewall = async () => {
    try {
      const res = await invoke<any>("check_firewall");
      firewallStatus.value = res;
    } catch (e) {
      console.error("Firewall check failed:", e);
    }
  };

  const requestFirewallOpen = async () => {
    firewallBusy.value = true;
    firewallResult.value = "";
    try {
      const result = await invoke<string>("request_firewall_open");
      if (result) {
        firewallResult.value = result;
        setTimeout(() => {
          showFirewallModal.value = false;
        }, 2000);
      } else {
        firewallResult.value =
          "Could not open firewall automatically. Use the commands below.";
      }
    } catch (e) {
      firewallResult.value = "Failed: " + e;
    }
    firewallBusy.value = false;
  };

  const handleFixFirewall = async () => {
    try {
      await invoke<string>("request_firewall_open");
    } catch (e) {
      console.error("Firewall fix failed:", e);
    }
  };

  return {
    // Pairing-specific refs
    manualIpInput,
    manualPortInput,
    showFirewallModal,
    firewallStatus,
    firewallBusy,
    firewallResult,
    attemptCount,

    // Handlers
    handleCompletePairing,
    handlePairLocally,
    handlePairExternally,
    submitManualPairing,
    confirmSas,
    rejectSas,
    pollPairingStatus,
    triggerConnectionAttempt,
    handleManualRetry,
    checkFirewall,
    requestFirewallOpen,
    handleFixFirewall,
  };
}
