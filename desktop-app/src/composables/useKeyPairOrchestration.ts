import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

export interface KeyPair {
  x25519_pk_hex: string;
  mlkem_pk_hex: string;
}

export interface KeyPairOrchestrationDeps {
  refreshLogs: () => Promise<void>;
}

/**
 * Feature-level orchestration hook for the identity keypair + pairing-config
 * surface (AUDIT F18 — extracted from the App.vue composition root). Owns the
 * generated hybrid keypair, the pairing-config JSON (what the pairing QR /
 * deep link embeds), and the token-gated `get_pairing_config` fetch.
 */
export function useKeyPairOrchestration(deps: KeyPairOrchestrationDeps) {
  const keyPair = ref<KeyPair | null>(null);
  const pairingConfigJson = ref("");

  const loadPairingConfig = async () => {
    if (!keyPair.value) return;
    try {
      // AUDIT F9: `get_pairing_config` is token-gated (KYP-2026-02 #6
      // hardening) — the renderer MUST mint a single-use token for this exact
      // action and pass it through, or every call fails and the pairing config
      // is silently dropped.
      const token = await invoke<string>("request_privilege_token", {
        action: "get_pairing_config",
      });
      const config = await invoke<Record<string, unknown>>("get_pairing_config", {
        hostPkHex: keyPair.value.mlkem_pk_hex,
        wireguardPkHex: keyPair.value.x25519_pk_hex,
        token,
      });
      pairingConfigJson.value = JSON.stringify(config);
      await deps.refreshLogs();
    } catch (e) {
      console.error(e);
    }
  };

  const handleGenerateKeyPair = async () => {
    try {
      keyPair.value = await invoke<KeyPair>("generate_keypair");
      await deps.refreshLogs();
      await loadPairingConfig();
    } catch (e) {
      console.error("Key generation error: ", e);
    }
  };

  return {
    keyPair,
    pairingConfigJson,
    handleGenerateKeyPair,
    loadPairingConfig,
  };
}
