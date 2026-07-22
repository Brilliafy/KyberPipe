<script setup lang="ts">
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
      <div class="logo-badge">KP</div>
      <div class="brand-text">
        <h2>KYBERPIPE</h2>
        <span class="subtext">POST-QUANTUM ENGINE</span>
      </div>
    </div>

    <nav class="nav-menu">
      <button
        :class="{ active: currentTab === 'dashboard' }"
        @click="emit('update:currentTab', 'dashboard')"
      >
        <span>📊</span> Overview
      </button>
      <button
        :class="{ active: currentTab === 'connectivity' }"
        @click="emit('update:currentTab', 'connectivity')"
      >
        <span>🌐</span> Connection Manager
      </button>
      <button
        :class="{ active: currentTab === 'files' }"
        @click="emit('update:currentTab', 'files')"
      >
        <span>📁</span> File Manager
      </button>
      <button
        :class="{ active: currentTab === 'clipboard' }"
        @click="emit('update:currentTab', 'clipboard')"
      >
        <span>📋</span> Clipboard Manager
      </button>
      <button
        :class="{ active: currentTab === 'notifications' }"
        @click="emit('update:currentTab', 'notifications')"
      >
        <span>🔔</span> Notifications
      </button>
      <button
        :class="{ active: currentTab === 'light' }"
        @click="emit('update:currentTab', 'light')"
      >
        <span>⚡</span> Automation
      </button>
      <button
        :class="{ active: currentTab === 'logs' }"
        @click="emit('update:currentTab', 'logs')"
      >
        <span>📟</span> System Logs
      </button>
      <button
        :class="{ active: currentTab === 'settings' }"
        @click="emit('update:currentTab', 'settings')"
      >
        <span>⚙️</span> Settings
      </button>
    </nav>

    <div class="sidebar-footer" v-if="systemInfo">
      <div class="version">Version {{ systemInfo.app_version }}</div>
    </div>
  </aside>
</template>
