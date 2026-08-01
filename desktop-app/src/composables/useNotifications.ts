import { ref, computed, watch, onMounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { debounce } from './utils'

export interface UnifiedNotification {
  id: string
  source: string
  title: string
  body: string
  appPackage: string
  timestamp: string
  type: 'local' | 'remote'
  updatedAt?: number
}

export function useNotifications() {
  const notifList = ref<UnifiedNotification[]>([])
  const optimisticStatus = ref<string | null>(null)
  const autoPurgeDays = ref(7)

  const displayNotifications = computed<UnifiedNotification[]>(() => {
    return [...notifList.value].sort((a, b) => {
      const ta = a.updatedAt || new Date(a.timestamp).getTime()
      const tb = b.updatedAt || new Date(b.timestamp).getTime()
      return tb - ta
    })
  })

  const persistNotifications = debounce(() => {
    try {
      localStorage.setItem('kyberpipe_notifications', JSON.stringify(notifList.value))
    } catch {}
  }, 1000)

  watch(notifList, persistNotifications, { deep: true })

  const loadPersistedNotifications = () => {
    try {
      const raw = localStorage.getItem('kyberpipe_notifications')
      if (raw) {
        const parsed = JSON.parse(raw) as UnifiedNotification[]
        notifList.value = parsed
      }
    } catch {}
  }

  const purgeOldNotifications = (days: number) => {
    const cutoff = Date.now() - days * 86400000
    notifList.value = notifList.value.filter(n => {
      const t = n.updatedAt || new Date(n.timestamp).getTime()
      return t > cutoff
    })
    persistNotifications()
  }

  const notifySyncChannel = (notif: UnifiedNotification) => {
    try {
      invoke('push_notification_packet', {
        title: notif.title || '',
        text: notif.body || '',
        appPackage: notif.appPackage || '',
        timestamp: Date.now(),
      })
    } catch {}
  }

  const removeNotification = (id: string) => {
    const notif = notifList.value.find(n => n.id === id)
    notifList.value = notifList.value.filter(n => n.id !== id)
    if (notif) notifySyncChannel(notif)
  }

  onMounted(() => {
    loadPersistedNotifications()
    purgeOldNotifications(autoPurgeDays.value)
    setInterval(() => purgeOldNotifications(autoPurgeDays.value), 3600000)
  })

  return {
    notifList,
    optimisticStatus,
    autoPurgeDays,
    displayNotifications,
    loadPersistedNotifications,
    purgeOldNotifications,
    persistNotifications,
    removeNotification,
    notifySyncChannel,
  }
}
