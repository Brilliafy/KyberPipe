import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

/**
 * Feature-level orchestration hook for the diagnostic LOG + crash-log surface
 * (AUDIT F18 — extracted from the App.vue composition root). Owns the logs
 * array, the crash-log read, the export/download helpers and the latest-crash
 * fetch — everything the "logs" tab and the sidebar crash banner need, with no
 * IPC scattered in the component.
 */
export function useLogs() {
  const logs = ref<string[]>([]);
  const crashLog = ref<string | null>(null);

  const refreshLogs = async () => {
    try {
      logs.value = await invoke<string[]>("get_app_logs");
    } catch (e) {
      console.error(e);
    }
  };

  const checkCrashLog = async () => {
    try {
      crashLog.value = await invoke<string | null>("get_latest_crash_log");
    } catch (e) {
      console.error("Failed to check crash log:", e);
    }
  };

  const copyStacktrace = async () => {
    if (crashLog.value) {
      try {
        await navigator.clipboard.writeText(crashLog.value);
        alert("Anonymized stacktrace copied to clipboard!");
      } catch (err) {
        console.error("Failed to copy stacktrace:", err);
      }
    }
  };

  const exportDiagnosticLogs = () => {
    const text = logs.value.join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "diagnostic_logs.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCrashLog = () => {
    if (crashLog.value) {
      const blob = new Blob([crashLog.value], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "anonymous_crash_log.txt";
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return {
    logs,
    crashLog,
    refreshLogs,
    checkCrashLog,
    copyStacktrace,
    exportDiagnosticLogs,
    exportCrashLog,
  };
}
