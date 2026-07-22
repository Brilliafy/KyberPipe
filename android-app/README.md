# KyberPipe Android Companion App

The Android companion application for KyberPipe handles local synchronization events, provides secure clipboard and notifications relays, and interfaces with the desktop client.

## 📱 Features

*   **Zero-Trust Exception Handler**: Installs a custom `UncaughtExceptionHandler` that captures panics, scrubs identifying fields (phone numbers, emails, IP addresses, build fingerprints, model names), and saves anonymous crash logs locally.
*   **Permissions Dashboard**: Standard permissions check and launch triggers for Notification Listeners and SMS permissions.
*   **Sensors Interfacing**: Ambient Light sensor hook to dynamically stream lux values to the sandbox environment.
*   **PQC Handshake**: Verifies PC host identity keys, executes the KEM encapsulation step, and derives cryptographic SAS codes.

---

## 🛠️ Build and Deploy

### Local Build
Generate the debug APK using Gradle:
```bash
./gradlew assembleDebug
```
The output package will be created at:
`app/build/outputs/apk/debug/app-debug.apk`

### ADB Deployment
Deploy directly to a connected device or emulator:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 🔒 Anonymous Crash & Diagnostics Window
Access the logs card inside the Settings tab to manage data locally:
1.  **Copy Stacktrace**: Copies the latest anonymized crash trace to the clipboard.
2.  **Export Logs**: Exports current in-memory diagnostic logs via the Android Share sheet.
3.  **Export Anon Crash**: Exports the saved crash log via the Android Share sheet.
