import { ref } from "vue";
import { invoke } from "@tauri-apps/api/core";

export function useTelemetry(refreshLogs: () => Promise<void>) {
  const flightRecorderEnabled = ref(false);
  const neuralAnomalyEnabled = ref(false);

  const handleToggleFlightRecorder = async (val: boolean) => {
    flightRecorderEnabled.value = val;
    try {
      await invoke("toggle_flight_recorder", { enabled: val });
      await refreshLogs();
    } catch (e) {
      console.error(e);
    }
  };

  const handleToggleNeuralAnomaly = async (val: boolean) => {
    neuralAnomalyEnabled.value = val;
    try {
      await invoke("toggle_neural_anomaly_engine", { enabled: val });
      await refreshLogs();
    } catch (e) {
      console.error(e);
    }
  };

  return {
    flightRecorderEnabled,
    neuralAnomalyEnabled,
    handleToggleFlightRecorder,
    handleToggleNeuralAnomaly,
  };
}
