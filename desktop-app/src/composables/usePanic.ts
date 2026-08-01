import { invoke } from '@tauri-apps/api/core'

export function usePanic(
  refreshLogs: () => Promise<void>,
  checkConnectionState: () => Promise<void>
) {
  const triggerSelfDestruct = async () => {
    if (
      confirm(
        'CRITICAL WARNING: This will zeroize all active cryptographic ratchets and purge hardware keys. Proceed with Emergency Panic Destruction?'
      )
    ) {
      try {
        // Destructive commands are gated behind a single-use, expiring token
        // issued after this user gesture (audit finding #13).
        const token = await invoke<string>('request_privilege_token', {
          action: 'trigger_panic_self_destruct',
        })
        await invoke('trigger_panic_self_destruct', { token })
        await refreshLogs()
        await checkConnectionState()
      } catch (e) {
        console.error(e)
      }
    }
  }

  return { triggerSelfDestruct }
}
