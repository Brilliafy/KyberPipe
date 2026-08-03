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
  ///
  /// AUDIT FINDING #15: an empty cert hash is NOT acceptable — pairing without
  /// a QR-bound pin lets a LAN MITM terminate the bootstrap TLS, forward the
  /// KEM, and hold every session key while the SAS still matches. Any failure
  /// (command error OR empty result) THROWS, so the QR is never built without
  /// the pin and the pairing fails loudly instead of silently.
  const fetchQrBindingFields = async (): Promise<Record<string, string>> => {
    let nonce = "";
    try {
      // Audit F9 (regression): `get_pairing_nonce` is token-gated — the
      // hardening (KYP-2026-02 #6) added a mandatory user-gesture token, but
      // the renderer never minted one, so EVERY QR pairing attempt failed with
      // "Pairing nonce mismatch". Mint a fresh token for this exact action
      // first, then pass it through (mirrors the useClipboardHistory F6
      // pattern).
      const token = await invoke<string>("request_privilege_token", {
        action: "get_pairing_nonce",
      });
      nonce = (await invoke<string>("get_pairing_nonce", { token })) || "";
    } catch (e) {
      console.warn("get_pairing_nonce failed:", e);
    }
    let serverCertHash = "";
    try {
      serverCertHash = (await invoke<string>("get_server_cert_hash")) || "";
    } catch (e) {
      console.error("get_server_cert_hash failed:", e);
    }
    if (!serverCertHash) {
      throw new Error(
        "Pairing aborted: no QR-bound server certificate hash available — " +
          "cannot build a MITM-safe pairing QR. Restart the desktop app and retry."
      );
    }
    // Audit F9: the QR MUST carry a nonce or the server rejects the pairing.
    if (!nonce) {
      throw new Error(
        "Pairing aborted: no QR pairing nonce was issued by the backend — " +
          "cannot build a valid pairing QR."
      );
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
    if (method === "wormhole") {
      // Audit finding KYP-2026-02 (F6): generate_wormhole_code now returns a
      // typed FeatureUnavailable error — the renderer no longer calls it and
      // must not fake a QR. Surface the honest state instead of pretending
      // success (ConnectivityManager also disables this pairing option).
      alert(
        "Magic Wormhole pairing is unavailable in this build (feature not compiled in). Use Tor Onion or a local pairing method instead."
      );
      return;
    }
    remoteMethod.value = method;
    remoteActive.value = true;
    if (method === "tor") {
      try {
        // Tier-2 destructive command — single-use user-gesture token
        // (audit finding #20).
        const token = await invoke<string>("request_privilege_token", {
          action: "create_tor_onion",
        });
        const onion = await invoke<any>("create_tor_onion", { token });
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
    // Audit finding #13: any failure (e.g. no cert hash for the QR) must not
    // leave half-updated UI state or an unhandled rejection — surface it and
    // keep the dialog open so the user can retry.
    try {
      await buildPairingQr({
        method: "manual_ip",
        host: ip,
        port: parseInt(manualPortInput.value) || 9876,
        pqc_pub: keyPair.value?.mlkem_pk_hex || "",
        x25519_pub: keyPair.value?.x25519_pk_hex || "",
      });
      showManualIpDialog.value = false;
    } catch (e) {
      console.error("Manual pairing QR build failed:", e);
      alert("Pairing QR could not be built: " + e);
    }
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

    // Audit finding #13: guard every invoke so a rejection (keyring locked,
    // command unavailable in dev) cannot produce an unhandled promise
    // rejection or leave the UI half-updated.
    let res: any = null;
    try {
      res = await invoke<any>("get_connection_status_full");
    } catch (e) {
      console.error("get_connection_status_full failed:", e);
      return;
    }
    if (res?.color === "green") {
      return; // Already connected
    }

    try {
      await invoke("set_connection_status_full", {
        status: "WAITING FOR COMPANION",
        method: "None",
        color: "yellow",
      });
    } catch (e) {
      console.error("set_connection_status_full failed:", e);
      return;
    }
    await checkConnectionState();
    await refreshLogs();
  };

  const handleManualRetry = () => {
    attemptCount.value = 0;
    // Audit finding #13: fire-and-forget with error containment — a rejected
    // trigger must not produce an unhandled promise rejection.
    triggerConnectionAttempt().catch((e) =>
      console.error("Manual retry failed:", e)
    );
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
      // Tier-2 destructive command — single-use user-gesture token
      // (audit finding #20).
      const token = await invoke<string>("request_privilege_token", {
        action: "request_firewall_open",
      });
      const result = await invoke<string>("request_firewall_open", { token });
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
      const token = await invoke<string>("request_privilege_token", {
        action: "request_firewall_open",
      });
      await invoke<string>("request_firewall_open", { token });
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
    triggerConnectionAttempt,
    handleManualRetry,
    checkFirewall,
    requestFirewallOpen,
    handleFixFirewall,
  };
}
