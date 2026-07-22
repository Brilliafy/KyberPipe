<script setup lang="ts">
import { ref } from "vue";
import { 
  Play, 
  Plus, 
  Trash2, 
  Sliders
} from '@lucide/vue';

interface AutomationScript {
  id: string;
  name: string;
  triggerCondition: string;
  code: string;
  isSandboxed: boolean;
  feedSourceCommand: string;
  onCompletionCode: string;
}

defineProps<{
  currentLux: number;
  scriptResult: {
    success: boolean;
    output: string;
    logs: string[];
  } | null;
}>();

const emit = defineEmits<{
  (e: "update:currentLux", val: number): void;
  (e: "runScript", code: string, isSandboxed: boolean, feedSourceCommand: string, onCompletionCode?: string): void;
}>();

const showSimulationPanel = ref(false);

const scripts = ref<AutomationScript[]>([
  {
    id: "low-light",
    name: "Safe Sandboxed Light Guard",
    triggerCondition: "getAmbientLight() < 20.0",
    code: `const light = getAmbientLight();\nlog("Safeguarding night vision: " + light + " lux.");\n// Return state value for the completion action block to check\nlight < 20.0 ? "DARK_MODE_TRIGGER" : "NORMAL_LIGHT";`,
    isSandboxed: true,
    feedSourceCommand: "",
    onCompletionCode: `notify-send "KyberPipe" "Environment is dark! Throttling display brightness."`
  },
  {
    id: "battery-drain",
    name: "Battery Drain Protection",
    triggerCondition: "parseInt(getFeedData()) < 20",
    code: `const battery = parseInt(getFeedData());\nlog("Battery level retrieved: " + battery + "%");\nbattery < 20 ? "BATTERY_CRITICAL" : "OK";`,
    isSandboxed: true,
    feedSourceCommand: "cat /sys/class/power_supply/BAT0/capacity 2>/dev/null || echo 18",
    onCompletionCode: `notify-send -u critical "KyberPipe Battery Alert" "Android Sync throttled to save power."`
  },
  {
    id: "cpu-diagnostic",
    name: "System Status Diagnostics Dispatch",
    triggerCondition: "CPU temperature check",
    code: `# Unsandboxed Bash Command script\nTEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 45000)\nCPU_TEMP=$((TEMP / 1000))\necho "CPU temperature is \${CPU_TEMP}°C"\nif [ $CPU_TEMP -gt 75 ]; then\n  echo "HOT"\nelse\n  echo "COOL"\nfi`,
    isSandboxed: false,
    feedSourceCommand: "",
    onCompletionCode: `notify-send "Thermal Check Complete" "CPU state OK."`
  }
]);

const selectedIndex = ref(0);
const newScriptName = ref("");
const newScriptTrigger = ref("");
const newScriptCode = ref("");

const createScript = () => {
  if (!newScriptName.value.trim()) return;
  scripts.value.push({
    id: `script_${Date.now()}`,
    name: newScriptName.value.trim(),
    triggerCondition: newScriptTrigger.value.trim() || "true",
    code: newScriptCode.value || "// Custom handler code here",
    isSandboxed: true,
    feedSourceCommand: "",
    onCompletionCode: ""
  });
  selectedIndex.value = scripts.value.length - 1;
  newScriptName.value = "";
  newScriptTrigger.value = "";
  newScriptCode.value = "";
};

const deleteScript = (index: number) => {
  scripts.value.splice(index, 1);
  if (selectedIndex.value >= scripts.value.length) {
    selectedIndex.value = Math.max(0, scripts.value.length - 1);
  }
};

const testExecution = () => {
  const script = scripts.value[selectedIndex.value];
  if (!script) return;
  emit("runScript", script.code, script.isSandboxed, script.feedSourceCommand, script.onCompletionCode);
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">
      <Sliders style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="24" /> 
      Automation Event Handlers
    </h2>
    <p class="section-subtitle">Define custom rules to run scripts sandboxed in a JS engine or locally on the host machine.</p>

    <div class="automations-layout">
      <!-- Left sidebar list of scripts -->
      <div class="scripts-sidebar">
        <h3>Event Handlers</h3>
        <div class="sidebar-list">
          <div v-for="(s, idx) in scripts" :key="s.id" 
               class="script-item"
               :class="{ active: selectedIndex === idx }"
               @click="selectedIndex = idx">
            <div class="script-meta-row">
              <span class="script-title">{{ s.name }}</span>
              <span class="sandbox-badge" :class="{ sandboxed: s.isSandboxed }">
                {{ s.isSandboxed ? 'JS Sandbox' : 'Unsandboxed' }}
              </span>
            </div>
            <div class="script-trigger-text">Trigger: {{ s.triggerCondition }}</div>
            <button class="delete-btn" @click.stop="deleteScript(idx)">
              <Trash2 :size="12" /> Remove
            </button>
          </div>
        </div>

        <div class="create-script-form">
          <h4>Create Custom Handler</h4>
          <input v-model="newScriptName" placeholder="Handler Name (e.g. Memory Guard)" class="input-text" />
          <input v-model="newScriptTrigger" placeholder="Trigger Rule Description" class="input-text" />
          <button class="btn btn-secondary btn-sm" @click="createScript">
            <Plus :size="12" style="margin-right:0.15rem" /> Add Script
          </button>
        </div>
      </div>

      <!-- Right main script editor -->
      <div class="editor-main">
        <div v-if="scripts[selectedIndex]" class="editor-card">
          <div class="editor-header">
            <h3>Editing Handler: {{ scripts[selectedIndex].name }}</h3>
            <div class="sandbox-toggle-row">
              <label class="switch-row">
                <input type="checkbox" v-model="scripts[selectedIndex].isSandboxed" />
                <span>Run inside isolated JS VM sandbox</span>
              </label>
            </div>
          </div>

          <div class="form-grid">
            <div class="form-group">
              <label>Trigger Rule:</label>
              <input v-model="scripts[selectedIndex].triggerCondition" class="input-text-full" />
            </div>

            <!-- Feed Source Command -->
            <div class="form-group">
              <label>
                Input Feed Source Command (CLI command executed on host to supply <code>feedData</code>):
              </label>
              <input 
                v-model="scripts[selectedIndex].feedSourceCommand" 
                placeholder="e.g. cat /sys/class/power_supply/BAT0/capacity" 
                class="input-text-full" 
              />
              <span class="field-hint">Runs on host and provides input value accessible via <code>getFeedData()</code>.</span>
            </div>
          </div>

          <div class="form-group code-group">
            <label>Script Code Block:</label>
            <textarea v-model="scripts[selectedIndex].code" rows="12" class="code-editor"></textarea>
          </div>

          <!-- Optional On-Completion action block -->
          <div class="form-group completion-group">
            <label>
              On-Completion Action Command (Executes unsandboxed command on host if script succeeds):
            </label>
            <input 
              v-model="scripts[selectedIndex].onCompletionCode" 
              placeholder="e.g. notify-send 'KyberPipe' 'Action Triggered'" 
              class="input-text-full" 
            />
            <span class="field-hint">Triggers automatically on completion if returned value is non-empty.</span>
          </div>

          <div class="editor-actions">
            <button class="btn btn-primary" @click="testExecution">
              <Play :size="14" style="margin-right:0.25rem" /> Run / Test Handler
            </button>
            <button class="btn btn-secondary" @click="showSimulationPanel = !showSimulationPanel">
              {{ showSimulationPanel ? 'Hide Simulator' : 'Show Sensor Simulator' }}
            </button>
          </div>
        </div>

        <!-- Simulation Submenu Section -->
        <div v-if="showSimulationPanel" class="simulator-card">
          <h4>Simulated Light Environment Testbed</h4>
          <div class="lux-controls">
            <label>Simulated Level: <strong>{{ currentLux }} lux</strong></label>
            <input type="range" min="0" max="500" step="0.5" :value="currentLux" @input="emit('update:currentLux', Number(($event.target as HTMLInputElement).value))" class="lux-slider" />
          </div>
        </div>

        <!-- Results Block -->
        <div class="result-box" v-if="scriptResult">
          <div class="result-header">
            <h4>Execution Result</h4>
            <span class="status-indicator" :class="{ success: scriptResult.success }">
              {{ scriptResult.success ? 'Success' : 'Failed' }}
            </span>
          </div>
          <pre class="console-output">{{ scriptResult.output || 'None (No return value)' }}</pre>
          <div v-if="scriptResult.logs && scriptResult.logs.length > 0" class="console-logs-wrapper">
            <h5>Logs:</h5>
            <div class="console-logs-list">
              <div v-for="(l, i) in scriptResult.logs" :key="i" class="log-line">
                {{ l }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.automations-layout {
  display: flex;
  gap: 1.5rem;
  margin-top: 1rem;
}
@media (max-width: 1024px) {
  .automations-layout {
    flex-direction: column;
  }
  .scripts-sidebar {
    width: 100% !important;
  }
}
.scripts-sidebar {
  width: 280px;
  border-right: 1px solid var(--border-color);
  padding-right: 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.sidebar-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.script-item {
  padding: 0.85rem;
  border-radius: 8px;
  cursor: pointer;
  border: 1px solid var(--border-color);
  background: var(--bg-card);
  transition: all 0.2s ease;
}
.script-item:hover {
  border-color: var(--accent-cyan);
}
.script-item.active {
  border-color: var(--accent-cyan);
  background: rgba(6, 182, 212, 0.05);
}
.script-meta-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.25rem;
  gap: 0.5rem;
}
.script-title {
  font-weight: 700;
  font-size: 0.85rem;
}
.sandbox-badge {
  font-size: 0.65rem;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  white-space: nowrap;
}
.sandbox-badge.sandboxed {
  background: rgba(6, 182, 212, 0.15);
  color: var(--accent-cyan);
}
.script-trigger-text {
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-bottom: 0.5rem;
}
.delete-btn {
  background: transparent;
  border: none;
  color: #ef4444;
  font-size: 0.75rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
.create-script-form {
  margin-top: 1.5rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.create-script-form h4 {
  font-size: 0.85rem;
  margin-bottom: 0.25rem;
}
.input-text {
  padding: 0.5rem;
  background: var(--bg-dark);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.8rem;
  outline: none;
}
.input-text:focus {
  border-color: var(--accent-cyan);
}
.editor-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.editor-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.5rem;
  border-radius: 12px;
}
.editor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.25rem;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.editor-header h3 {
  margin: 0;
  font-size: 1.1rem;
}
.switch-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  cursor: pointer;
}
.form-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-bottom: 1rem;
}
.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.form-group label {
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.input-text-full {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: var(--bg-dark);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.85rem;
  outline: none;
}
.input-text-full:focus {
  border-color: var(--accent-cyan);
}
.field-hint {
  font-size: 0.7rem;
  color: var(--text-secondary);
}
.code-editor {
  width: 100%;
  background: var(--bg-dark);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.75rem;
  font-family: monospace;
  font-size: 0.85rem;
  resize: vertical;
}
.code-editor:focus {
  border-color: var(--accent-cyan);
  outline: none;
}
.editor-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.25rem;
}
.simulator-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
  border-radius: 12px;
}
.simulator-card h4 {
  font-size: 0.9rem;
  margin-bottom: 0.5rem;
}
.lux-controls {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.lux-controls label {
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.lux-slider {
  width: 100%;
}
.result-box {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  padding: 1.25rem;
  border-radius: 12px;
}
.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.5rem;
  margin-bottom: 0.75rem;
}
.result-header h4 {
  margin: 0;
  font-size: 0.9rem;
}
.status-indicator {
  font-size: 0.75rem;
  font-weight: 700;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}
.status-indicator.success {
  background: rgba(16, 185, 129, 0.15);
  color: #10b981;
}
.console-output {
  background: rgba(0, 0, 0, 0.3);
  padding: 0.75rem;
  border-radius: 6px;
  font-family: monospace;
  font-size: 0.8rem;
  color: #38bdf8;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0 0 1rem 0;
  border: 1px solid rgba(255, 255, 255, 0.03);
}
.console-logs-wrapper h5 {
  font-size: 0.8rem;
  margin-bottom: 0.35rem;
}
.console-logs-list {
  background: rgba(0, 0, 0, 0.3);
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  border: 1px solid rgba(255, 255, 255, 0.03);
  max-height: 120dp;
  overflow-y: auto;
}
.log-line {
  font-family: monospace;
  font-size: 0.75rem;
  color: #a855f7;
}
</style>
