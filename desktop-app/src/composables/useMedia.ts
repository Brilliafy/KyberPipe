import { ref, computed, type Ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { Play, Pause, SkipForward, SkipBack, Music } from '@lucide/vue';

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

export function useMedia(isPaired: Ref<boolean>) {
  const mediaState = ref<MediaState | null>(null);
  const currentLatency = ref(0);

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
      const state = await invoke<MediaState>("get_media_state");
      mediaState.value = state;
    } catch (e) {
      console.error("Failed to fetch media state:", e);
    }
  };

  const handleMediaAction = async (actionIndex: number) => {
    try {
      // AUDIT P4-1(c)/P5-2: the media-action command was reclassified Tier-1 →
      // Tier-2 — it drives a REMOTE side effect on the phone (fires a foreign
      // PendingIntent), so it now requires the same fresh native user-gesture
      // token every other remote-action command does. The renderer surfaces a
      // confirmation, then mints the single-use token; the backend command
      // consumes it.
      const confirmed = window.confirm(
        "Trigger this media action on the paired phone? This fires the action on the phone's media app."
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

  const getMediaIcon = (title: string) => {
    const t = title.toLowerCase();
    if (t.includes("play")) return Play;
    if (t.includes("pause")) return Pause;
    if (t.includes("next") || t.includes("forward") || t.includes("skip")) return SkipForward;
    if (t.includes("prev") || t.includes("back")) return SkipBack;
    return Music;
  };

  return {
    mediaState,
    currentLatency,
    latencyColor,
    fetchMediaState,
    handleMediaAction,
    getMediaIcon,
  };
}
