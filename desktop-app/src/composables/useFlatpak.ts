import { ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'

export interface SystemInfo {
  is_flatpak: boolean
  platform: string
  app_version: string
  pqc_algorithm: string
}

export function useFlatpak() {
  const showFlatpakModal = ref(false)
  const flatpakCopyStatus = ref('')
  const systemInfo = ref<SystemInfo | null>(null)

  const verifyFlatpakPermissions = async () => {
    try {
      const sysInfo = await invoke<SystemInfo>('get_system_info')
      systemInfo.value = sysInfo
      if (sysInfo.is_flatpak) {
        const granted = await invoke<boolean>('check_flatpak_permissions')
        if (!granted) {
          showFlatpakModal.value = true
        }
      }
    } catch (e) {
      console.error('Flatpak verify error:', e)
    }
  }

  const copyFlatpakCommand = async () => {
    try {
      await navigator.clipboard.writeText(
        'flatpak override --user --share=network --socket=wayland --socket=fallback-x11 --socket=pulseaudio --talk-name=org.freedesktop.portal.Desktop io.github.brilliafy.kyberpipe'
      )
      flatpakCopyStatus.value = 'Override command copied!'
      setTimeout(() => { flatpakCopyStatus.value = '' }, 2500)
    } catch (e) {
      console.error(e)
    }
  }

  const handleFlatpakVerifyProceed = async () => {
    const sysInfo = systemInfo.value
    if (sysInfo?.is_flatpak) {
      const granted = await invoke<boolean>('check_flatpak_permissions')
      if (granted) {
        showFlatpakModal.value = false
      } else {
        flatpakCopyStatus.value = 'Permissions still not granted. Run the command above and click Verify.'
        setTimeout(() => { flatpakCopyStatus.value = '' }, 3000)
      }
    }
  }

  return {
    showFlatpakModal,
    flatpakCopyStatus,
    systemInfo,
    verifyFlatpakPermissions,
    copyFlatpakCommand,
    handleFlatpakVerifyProceed,
  }
}
