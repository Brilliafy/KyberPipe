# KyberPipe Desktop Portal

The desktop application for KyberPipe serves as the primary coordination portal. It is built using **Tauri** and **Vue 3** (with TypeScript and Vite).

## 🖥️ Core Interfaces

*   **Dashboard**: Shows system metrics, connection paths (Wi-Fi Direct, LAN, WAN), and active key metrics.
*   **Connectivity Manager**: Handles network connections, STUN hole punching, dynamic IP addresses, and has a Network Diagnostics Drawer with live latency charting.
*   **Local System Log Stream**: Renders active diagnostic entries, and contains buttons to copy anonymized crash stacktraces or export logs as text files.
*   **Sandbox Automation**: Configures JavaScript script triggers executing inside a lightweight Boa interpreter based on ambient sensor events.

---

## 🛠️ Development Setup

Ensure you have **Node.js (v18+)** and **pnpm** installed.

### 1. Install Dependencies
```bash
pnpm install
```

### 2. Run Development Server
```bash
pnpm tauri dev
```

### 3. Build Production Bundle
```bash
pnpm tauri build
```

---

## 🎨 Theme Control
Theme changes (Light, Dark, and OLED black) update the document root classes dynamically. Headings, cards, inputs, and terminals adapt semantic variables (`var(--bg-dark)`, `var(--bg-card)`, etc.) for a clean visual appearance.
