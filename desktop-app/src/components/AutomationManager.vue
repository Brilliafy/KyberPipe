<script setup lang="ts">
import { ref } from "vue";

interface AutomationScript {
  id: string;
  name: string;
  triggerCondition: string;
  code: string;
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
  (e: "runScript", code: string): void;
}>();

const showSimulationPanel = ref(false);

const scripts = ref<AutomationScript[]>([
  {
    id: "low-light",
    name: "Low Light Handler",
    triggerCondition: "getAmbientLight() < 15.0",
    code: `const light = getAmbientLight();\nlog("Low light detected: " + light + " lux. Safeguarding night vision.");`
  },
  {
    id: "high-light",
    name: "High Light Handler",
    triggerCondition: "getAmbientLight() > 300.0",
    code: `const light = getAmbientLight();\nlog("Nominal daylight environment: " + light + " lux.");`
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
    code: newScriptCode.value || "// Custom handler code here"
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
  emit("runScript", script.code);
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title">Automation Event Handlers</h2>

    <div style="display: flex; gap: 1.5rem; margin-top: 1rem;">
      <!-- Left sidebar list of scripts -->
      <div style="width: 280px; border-right: 1px solid var(--border-color); padding-right: 1.5rem; display: flex; flex-direction: column; gap: 0.5rem;">
        <h3>Event Handlers</h3>
        <div v-for="(s, idx) in scripts" :key="s.id" 
             :style="{ 
               padding: '0.75rem', 
               borderRadius: '8px', 
               cursor: 'pointer',
               border: '1px solid ' + (selectedIndex === idx ? 'var(--accent-cyan)' : 'var(--border-color)'),
               background: selectedIndex === idx ? 'rgba(99, 102, 241, 0.1)' : 'transparent'
             }"
             @click="selectedIndex = idx">
          <div style="font-weight: 700;">{{ s.name }}</div>
          <div style="font-size: 0.8rem; color: var(--text-secondary);">Trigger: {{ s.triggerCondition }}</div>
          <button class="btn btn-panic btn-sm" style="margin-top: 0.5rem; font-size: 0.75rem; background: rgba(239, 68, 68, 0.1); color: #ef4444;" @click.stop="deleteScript(idx)">
            Remove
          </button>
        </div>

        <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 0.5rem;">
          <h4>Create New Handler</h4>
          <input v-model="newScriptName" placeholder="Handler Name" style="padding: 0.4rem; background: var(--bg-dark); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px;" />
          <input v-model="newScriptTrigger" placeholder="Trigger Condition" style="padding: 0.4rem; background: var(--bg-dark); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px;" />
          <button class="btn btn-secondary btn-sm" @click="createScript">Create</button>
        </div>
      </div>

      <!-- Right main script editor -->
      <div style="flex: 1; display: flex; flex-direction: column; gap: 1rem;">
        <div v-if="scripts[selectedIndex]">
          <h3>Editing Handler: {{ scripts[selectedIndex].name }}</h3>
          <div style="margin-bottom: 0.5rem;">
            <label style="font-size: 0.85rem; color: var(--text-secondary);">Trigger Condition Rule:</label>
            <input v-model="scripts[selectedIndex].triggerCondition" style="width: 100%; padding: 0.5rem; border-radius: 6px; background: var(--bg-dark); color: var(--text-primary); border: 1px solid var(--border-color); margin-top: 0.25rem;" />
          </div>

          <div>
            <label style="font-size: 0.85rem; color: var(--text-secondary);">JavaScript Code Block:</label>
            <textarea v-model="scripts[selectedIndex].code" rows="10" class="code-editor" style="width: 100%; margin-top: 0.25rem;"></textarea>
          </div>

          <div style="display: flex; gap: 0.5rem; margin-top: 1rem;">
            <button class="btn btn-primary" @click="testExecution">Run / Test Handler</button>
            <button class="btn btn-secondary" @click="showSimulationPanel = !showSimulationPanel">
              {{ showSimulationPanel ? 'Hide Simulation Panel' : 'Show Simulation & Test Panel' }}
            </button>
          </div>
        </div>

        <!-- Simulation Submenu Section -->
        <div v-if="showSimulationPanel" style="background: var(--bg-dark); padding: 1.25rem; border-radius: 12px; border: 1px solid var(--border-color); margin-top: 1rem;">
          <h4>Simulated Light Environment Testbed</h4>
          <div class="lux-controls" style="margin-top: 0.5rem;">
            <label style="font-size: 0.85rem; color: var(--text-secondary);">Simulated Level: <strong>{{ currentLux }} lux</strong></label>
            <input type="range" min="0" max="500" step="0.5" :value="currentLux" @input="emit('update:currentLux', Number(($event.target as HTMLInputElement).value))" style="width: 100%; margin-top: 0.25rem;" />
          </div>
        </div>

        <!-- Results Block -->
        <div class="result-box" v-if="scriptResult" style="margin-top: 1rem;">
          <h4>Execution Result (Success: {{ scriptResult.success }})</h4>
          <pre class="console-output">{{ scriptResult.output }}</pre>
          <div v-if="scriptResult.logs.length > 0">
            <h5>Logs:</h5>
            <ul>
              <li v-for="(l, i) in scriptResult.logs" :key="i">{{ l }}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
