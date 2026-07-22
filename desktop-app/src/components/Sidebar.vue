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
        <img src="../assets/logo.png" alt="KyberPipe Logo" class="logo-img" />
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
.logo-container {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
}
.logo-img {
  width: 42px;
  height: 42px;
  object-fit: cover;
  display: block;
  border-radius: 0;
}
.nav-icon {
  margin-right: 0.5rem;
  color: var(--text-secondary);
  transition: color 0.2s ease;
}
button:hover .nav-icon, button.active .nav-icon {
  color: var(--accent-cyan);
}
</style>
