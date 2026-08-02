import { ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'

export interface ScriptResult {
  success: boolean
  output: string
  logs: string[]
}

export function useAutomation(refreshLogs: () => Promise<void>) {
  const currentLux = ref(250.0)
  const scriptResult = ref<ScriptResult | null>(null)

  const handleRunScript = async (
    code: string,
    isSandboxed: boolean,
    feedSourceCommand: string,
    onCompletionCode?: string
  ) => {
    try {
      // Tier-2 destructive command (arbitrary JS) — request the single-use
      // user-gesture token (audit finding #20: per-tier enforcement).
      const token = await invoke<string>("request_privilege_token", {
        action: "execute_boa_script",
      });
      const res = await invoke<ScriptResult>("execute_boa_script", {
        scriptCode: code,
        isSandboxed: isSandboxed,
        lux: Number(currentLux.value),
        feedSourceCommand: feedSourceCommand,
        token,
      });
      scriptResult.value = res
      await refreshLogs()

      if (res.success && onCompletionCode && onCompletionCode.trim()) {
        const token2 = await invoke<string>("request_privilege_token", {
          action: "execute_boa_script",
        });
        await invoke("execute_boa_script", {
          scriptCode: onCompletionCode,
          isSandboxed: false,
          lux: Number(currentLux.value),
          feedSourceCommand: "",
          token: token2,
        })
        await refreshLogs()
      }
    } catch (e) {
      console.error("Execution failed: ", e)
    }
  }

  return {
    currentLux,
    scriptResult,
    handleRunScript,
  }
}
