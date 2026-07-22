<script setup lang="ts">
import { 
  BarChart2, 
  Globe, 
  FolderOpen, 
  Clipboard, 
  Bell, 
  Cpu, 
  Terminal, 
  Bolt 
} from '@lucide/vue';

defineProps<{
  currentTab: string;
  systemInfo: {
    is_flatpak: boolean;
    platform: string;
    app_version: string;
    pqc_algorithm: String;
  } | null;
}>();

const emit = defineEmits<{
  (e: "update:currentTab", tab: string): void;
}>();
</script>

<template>
  <aside class="sidebar">
    <div class="brand">
      <div class="logo-container">
        <svg class="logo-svg" viewBox="0 0 100 100" width="36" height="36" fill="none" xmlns="http://www.w3.org/2000/svg">
          <!-- Calligraphic Double-lined Z -->
          <path d="M 20,28 C 30,28 35,22 45,28 C 55,34 65,22 75,28" stroke="var(--accent-cyan)" stroke-width="4.5" stroke-linecap="round"/>
          <path d="M 20,33 C 30,33 35,27 45,33 C 55,39 65,27 75,33" stroke="var(--accent-cyan)" stroke-width="1.5" stroke-linecap="round"/>
          
          <path d="M 70,28 C 60,45 40,60 30,72" stroke="var(--accent-cyan)" stroke-width="4.5" stroke-linecap="round"/>
          <path d="M 74,28 C 64,45 44,60 34,72" stroke="var(--accent-cyan)" stroke-width="1.5" stroke-linecap="round"/>
          
          <path d="M 22,72 C 32,78 45,68 55,72" stroke="var(--accent-cyan)" stroke-width="4.5" stroke-linecap="round"/>
          <path d="M 22,67 C 32,73 45,63 55,67" stroke="var(--accent-cyan)" stroke-width="1.5" stroke-linecap="round"/>
          
          <!-- Subscript script-like q -->
          <circle cx="70" cy="74" r="8" stroke="var(--text-primary)" stroke-width="3" stroke-linecap="round"/>
          <path d="M 78,74 C 78,82 78,85 78,88 C 78,92 72,94 68,94" stroke="var(--text-primary)" stroke-width="3" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="brand-text">
        <h2>KyberPipe</h2>
        <span class="subtext">POST-QUANTUM CONNECTIVITY PIPELINE</span>
      </div>
    </div>

    <nav class="nav-menu">
      <button
        :class="{ active: currentTab === 'dashboard' }"
        @click="emit('update:currentTab', 'dashboard')"
      >
        <BarChart2 class="nav-icon" :size="18" /> Overview
      </button>
      <button
        :class="{ active: currentTab === 'connectivity' }"
        @click="emit('update:currentTab', 'connectivity')"
      >
        <Globe class="nav-icon" :size="18" /> Connection Manager
      </button>
      <button
        :class="{ active: currentTab === 'files' }"
        @click="emit('update:currentTab', 'files')"
      >
        <FolderOpen class="nav-icon" :size="18" /> File Manager
      </button>
      <button
        :class="{ active: currentTab === 'clipboard' }"
        @click="emit('update:currentTab', 'clipboard')"
      >
        <Clipboard class="nav-icon" :size="18" /> Clipboard Manager
      </button>
      <button
        :class="{ active: currentTab === 'notifications' }"
        @click="emit('update:currentTab', 'notifications')"
      >
        <Bell class="nav-icon" :size="18" /> Notifications
      </button>
      <button
        :class="{ active: currentTab === 'light' }"
        @click="emit('update:currentTab', 'light')"
      >
        <Cpu class="nav-icon" :size="18" /> Automation
      </button>
      <button
        :class="{ active: currentTab === 'logs' }"
        @click="emit('update:currentTab', 'logs')"
      >
        <Terminal class="nav-icon" :size="18" /> System Logs
      </button>
      <button
        :class="{ active: currentTab === 'settings' }"
        @click="emit('update:currentTab', 'settings')"
      >
        <Bolt class="nav-icon" :size="18" /> Settings
      </button>
    </nav>

    <div class="sidebar-footer" v-if="systemInfo">
      <div class="version">Version {{ systemInfo.app_version }}</div>
    </div>
  </aside>
</template>

<style scoped>
.nav-icon {
  margin-right: 0.5rem;
  color: var(--text-secondary);
  transition: color 0.2s ease;
}
button:hover .nav-icon, button.active .nav-icon {
  color: var(--accent-cyan);
}
</style>
