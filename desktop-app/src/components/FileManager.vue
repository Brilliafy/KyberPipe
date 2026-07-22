<script setup lang="ts">
import { ref, onMounted, watch, onUnmounted } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { 
  FolderOpen, 
  Monitor, 
  Smartphone, 
  Lock, 
  AlertCircle, 
  Folder, 
  FileText, 
  Download,
  MoreVertical,
  Trash2,
  Edit3,
  ExternalLink
} from '@lucide/vue';

const props = defineProps<{
  fileAccessGrantedDesktop: boolean;
  fileAccessGrantedPhone: boolean;
  isConnected: boolean;
}>();

const emit = defineEmits<{
  (e: "updateSettings"): void;
}>();

const activeSubTab = ref<"pc" | "phone">("pc");
interface LocalFileItem {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
}
const fileList = ref<LocalFileItem[]>([]);
const errorText = ref("");

const loadFiles = async () => {
  errorText.value = "";
  fileList.value = [];
  try {
    const isPhoneVal = activeSubTab.value === "phone";
    if (isPhoneVal && !props.isConnected) {
      errorText.value = "Phone is not connected. Please pair and connect your companion device first.";
      return;
    }
    const res = await invoke<LocalFileItem[]>("list_mock_files", { isPhone: isPhoneVal });
    fileList.value = res;
  } catch (err: any) {
    errorText.value = String(err);
  }
};

const handleGrantAccess = async (isDesktop: boolean) => {
  try {
    await invoke("grant_file_access", { isDesktop, granted: true });
    emit("updateSettings");
    setTimeout(loadFiles, 200);
  } catch (err) {
    console.error(err);
  }
};

const windowAlert = (msg: string) => {
  window.alert(msg);
};

watch([activeSubTab, () => props.fileAccessGrantedDesktop, () => props.fileAccessGrantedPhone, () => props.isConnected], () => {
  loadFiles();
});

const openMenuFile = ref<string | null>(null);

const toggleMenu = (path: string, event: Event) => {
  event.stopPropagation();
  openMenuFile.value = openMenuFile.value === path ? null : path;
};

const handleOpenLocal = async (path: string) => {
  try {
    await invoke("open_local_file", { path });
  } catch (err) {
    alert("Error opening file: " + err);
  }
};

const promptRename = (file: LocalFileItem) => {
  const newName = prompt("Rename " + file.name + " to:", file.name);
  if (newName && newName !== file.name) {
    file.name = newName;
  }
};

const promptDelete = (file: LocalFileItem) => {
  if (confirm("Are you sure you want to delete " + file.name + "?")) {
    fileList.value = fileList.value.filter(f => f.path !== file.path);
  }
};

const clickListener = () => {
  openMenuFile.value = null;
};

onMounted(() => {
  loadFiles();
  window.addEventListener("click", clickListener);
});

onUnmounted(() => {
  window.removeEventListener("click", clickListener);
});

const formatSize = (bytes: number) => {
  if (bytes === 0) return "--";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
};
</script>

<template>
  <section class="panel">
    <h2 class="section-title"><FolderOpen style="display:inline-block; vertical-align:middle; margin-right:0.25rem;" :size="24" /> Cross-Device File Explorer</h2>
    <p class="section-subtitle">Securely transfer and browse file systems between your Linux PC and Android Companion device.</p>

    <!-- Sub tabs for PC vs Phone -->
    <div class="tabs-header">
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'pc' }" 
        @click="activeSubTab = 'pc'"
      >
        <Monitor style="margin-right: 0.25rem;" :size="14" /> This PC Files
      </button>
      <button 
        class="tab-btn" 
        :class="{ active: activeSubTab === 'phone' }" 
        @click="activeSubTab = 'phone'"
      >
        <Smartphone style="margin-right: 0.25rem;" :size="14" /> Android Phone Files
      </button>
    </div>

    <!-- Main browser display -->
    <div class="browser-container">
      <!-- Access Blocked UI -->
      <div 
        class="access-denied-box" 
        v-if="(activeSubTab === 'pc' && !fileAccessGrantedDesktop) || (activeSubTab === 'phone' && !fileAccessGrantedPhone && isConnected)"
      >
        <Lock class="lock-icon" :size="48" style="color: var(--accent-indigo);" />
        <h3>Access Authorization Required</h3>
        <p>For security, cross-device file browsing requires explicit pairing consent from this host.</p>
        <button 
          class="btn btn-primary" 
          @click="handleGrantAccess(activeSubTab === 'pc')"
        >
          Grant File Access Permission
        </button>
      </div>

      <!-- General Errors (Disconnected, etc) -->
      <div class="access-denied-box" v-else-if="errorText">
        <AlertCircle class="lock-icon" :size="48" style="color: var(--accent-indigo);" />
        <h3>Browsing Unavailable</h3>
        <p>{{ errorText }}</p>
      </div>

      <!-- File Browser Table -->
      <div class="file-table-wrapper" v-else>
        <div class="current-path-bar">
          <span>Current Path:</span>
          <code>{{ activeSubTab === 'pc' ? '/home/Aelfwif/Downloads/kyberpipe' : '/sdcard' }}</code>
        </div>

        <table class="file-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Size</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="file in fileList" :key="file.path">
              <td class="file-name-cell">
                <component :is="file.is_dir ? Folder : FileText" :size="16" class="file-icon" style="color: var(--accent-cyan);" />
                <span>{{ file.name }}</span>
              </td>
              <td>{{ file.is_dir ? 'Directory' : 'File' }}</td>
              <td>{{ formatSize(file.size) }}</td>
              <td style="position: relative;">
                <button
                  class="btn btn-secondary btn-sm"
                  @click="handleOpenLocal(file.path)"
                  style="padding: 0.25rem 0.5rem; margin-right: 0.25rem;"
                  title="Open"
                >
                  <ExternalLink :size="14" />
                </button>
                <button 
                  class="btn btn-secondary btn-sm"
                  @click="toggleMenu(file.path, $event)"
                  style="padding: 0.25rem 0.5rem;"
                  title="More actions"
                >
                  <MoreVertical :size="14" />
                </button>
                <!-- Context Menu Dropdown -->
                <div 
                  v-if="openMenuFile === file.path" 
                  class="file-context-menu"
                  @click.stop
                >
                  <button 
                    class="menu-item" 
                    @click="handleOpenLocal(file.path); openMenuFile = null"
                  >
                    <ExternalLink :size="12" /> Open
                  </button>
                  <button 
                    class="menu-item" 
                    @click="windowAlert('Initiating secure peer-to-peer download...'); openMenuFile = null"
                  >
                    <Download :size="12" /> Download
                  </button>
                  <button 
                    class="menu-item" 
                    @click="promptRename(file); openMenuFile = null"
                  >
                    <Edit3 :size="12" /> Rename
                  </button>
                  <button 
                    class="menu-item danger" 
                    @click="promptDelete(file); openMenuFile = null"
                  >
                    <Trash2 :size="12" /> Delete
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<style scoped>
.section-subtitle {
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-bottom: 1.5rem;
}
.tabs-header {
  display: flex;
  gap: 1rem;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
  margin-bottom: 1.5rem;
}
.tab-btn {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-weight: 700;
  cursor: pointer;
  padding: 0.5rem 1rem;
  border-radius: 8px;
  font-size: 0.95rem;
  transition: all 0.2s ease;
  display: flex;
  align-items: center;
}
.tab-btn.active {
  background: rgba(99, 102, 241, 0.15);
  color: var(--accent-cyan);
}
.tab-btn:hover:not(.active) {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.02);
}
.browser-container {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  min-height: 350px;
  display: flex;
  flex-direction: column;
}
.access-denied-box {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  text-align: center;
  padding: 2rem;
}
.lock-icon {
  margin-bottom: 0.5rem;
}
.access-denied-box h3 {
  font-size: 1.25rem;
  font-weight: 800;
}
.access-denied-box p {
  color: var(--text-secondary);
  font-size: 0.85rem;
  max-width: 400px;
  margin-bottom: 0.5rem;
}
.current-path-bar {
  background: var(--bg-dark);
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid var(--border-color);
  font-size: 0.85rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.current-path-bar code {
  color: var(--accent-cyan);
  font-family: monospace;
}
.file-table-wrapper {
  overflow-x: auto;
}
.file-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.85rem;
}
.file-table th {
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-secondary);
  font-weight: 700;
}
.file-table td {
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.02);
  color: var(--text-primary);
  vertical-align: middle;
}
.file-name-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
}
.file-icon {
  flex-shrink: 0;
}
.file-context-menu {
  position: absolute;
  right: 1.25rem;
  top: 2.2rem;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
  z-index: 100;
  display: flex;
  flex-direction: column;
  min-width: 120px;
  overflow: hidden;
  padding: 0.25rem 0;
}
.menu-item {
  background: transparent;
  border: none;
  color: #f1f5f9;
  text-align: left;
  padding: 0.5rem 1rem;
  font-size: 0.8rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  width: 100%;
  transition: background 0.15s;
}
.menu-item:hover {
  background: #334155;
}
.menu-item.danger {
  color: #ef4444;
}
.menu-item.danger:hover {
  background: rgba(239, 68, 68, 0.15);
}
</style>
