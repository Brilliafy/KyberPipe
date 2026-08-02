import { ref, computed, watch, onMounted, onUnmounted } from "vue";
import { invoke } from "@tauri-apps/api/core";

export function useSettings() {
  // Settings / Storage
  const deviceName = ref("My Linux Workstation");
  const devicePicture = ref("");
  const pairedDeviceName = ref("");
  const pairedDevicePicture = ref("");
  const ddnsHostname = ref("");
  const enableUpnp = ref(false);
  const enableDdns = ref(false);
  const isPaired = ref(false);
  const fileAccessGrantedDesktop = ref(false);
  const fileAccessGrantedPhone = ref(false);
  const pathwayOrder = ref<string[]>(["wifi_direct", "mdns_lan", "wireguard_wan"]);
  const themeMode = ref("auto");
  // Audit finding #20 (opt-in discovery): LAN beacons default OFF and are only
  // emitted when the user explicitly enables this toggle.
  const beaconDiscoveryEnabled = ref(false);

  const isSystemDark = ref(window.matchMedia("(prefers-color-scheme: dark)").matches);

  const currentThemeClass = computed(() => {
    if (themeMode.value === "light") return "theme-daylight";
    if (themeMode.value === "dark") return ""; // Default dark theme
    return isSystemDark.value ? "" : "theme-daylight";
  });

  watch(currentThemeClass, (newClass) => {
    document.documentElement.className = newClass;
  }, { immediate: true });

  let mediaQueryListener: ((e: MediaQueryListEvent) => void) | null = null;

  onMounted(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    mediaQueryListener = (e: MediaQueryListEvent) => {
      isSystemDark.value = e.matches;
    };
    media.addEventListener("change", mediaQueryListener);
  });

  onUnmounted(() => {
    if (mediaQueryListener) {
      window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", mediaQueryListener);
    }
  });

  const loadSettings = async () => {
    try {
      const settings = await invoke<any>("get_settings");
      deviceName.value = settings.device_name || "My Linux Workstation";
      devicePicture.value = settings.device_picture || "";
      pairedDeviceName.value = settings.paired_device_name || "";
      pairedDevicePicture.value = settings.paired_device_picture || "";
      ddnsHostname.value = settings.ddns_hostname || "";
      enableUpnp.value = settings.enable_upnp || false;
      enableDdns.value = settings.enable_ddns || false;
      isPaired.value = settings.is_paired || false;
      fileAccessGrantedDesktop.value = settings.file_access_granted_desktop || false;
      fileAccessGrantedPhone.value = settings.file_access_granted_phone || false;
      themeMode.value = settings.theme_mode || "auto";
      pathwayOrder.value = settings.pathway_order || ["wifi_direct", "mdns_lan", "wireguard_wan"];
      beaconDiscoveryEnabled.value = settings.beacon_discovery_enabled || false;
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

  return {
    deviceName,
    devicePicture,
    pairedDeviceName,
    pairedDevicePicture,
    ddnsHostname,
    enableUpnp,
    enableDdns,
    isPaired,
    fileAccessGrantedDesktop,
    fileAccessGrantedPhone,
    pathwayOrder,
    themeMode,
    beaconDiscoveryEnabled,
    loadSettings,
    saveSettings,
    isSystemDark,
    currentThemeClass,
  };
}
