# Dark Tunnel VPN Config Unlocker

**Dark Tunnel VPN Config Unlocker** is a complete, production-grade Android application for inspecting VPN configuration files, unlocking authorized `AES-256-GCM` / `AES-256-CBC` encrypted containers, decoding multi-layer payloads, auditing user-authorized password hints, generating validated SSH/WebSocket/TLS/VLESS configurations, editing configs with syntax highlighting, and establishing verified Android `VpnService` tunnels.

---

## Visual Overview & Screenshots

| Hero Banner | App Icon |
| :---: | :---: |
| ![Dark Tunnel Hero Banner](app/src/main/res/drawable/img_hero_tunnel.jpg) | ![Dark Tunnel App Icon](app/src/main/res/drawable/img_launcher_icon.jpg) |

---

## Key Features

### 1. Config File Importer & Immutable Backup Engine
- **Supported Formats**: `.dark`, `.hat`, `.ehi`, `.nm`, `.hc`, `.json`, `.ovpn`, `.conf`, `.txt`.
- **Automatic Immutable Backup**: Every imported file is backed up to `filesDir/config_backups/` before processing so the original file is never modified or lost.
- **Cryptographic & Structural Inspection**: Displays file name, size, format extension, SHA-256 digest, Shannon Entropy gauge (`0.00–8.00 bits/byte`), GZIP headers (`0x1F8B`), binary magic signatures (`DTV1`, `HAT1`, `EHI1`, `NM01`, `HC01`), and JSON container envelopes.

### 2. Config Unlocker
- **Real Cryptographic Decryption**: Supports `AES-256-GCM` and `AES-256-CBC` with `PBKDF2WithHmacSHA256` key derivation (`10,000` iterations) and SHA-256 plaintext verification.
- **No Fake Success**: Displays the actual cryptographic result. Wrong passwords trigger real `AEADBadTagException` or `BadPaddingException` error reports, and corrupted files are explicitly flagged.

### 3. Config Decoder
- **Multi-Layer Decoding**: Decodes Base64 (RFC-4648 & URL-Safe), Hexadecimal (Base16), URL Percent-Encoding, and standard VPN URI schemes (`vmess://`, `vless://`, `trojan://`, `ss://`, `darktunnel://`).
- **Encoding vs. Encryption Boundary**: Refuses to treat encrypted containers as simple encodings and guides the user to the Config Unlocker when a decryption key is required.
- **Export & Editor Integration**: Copy, Save As (via Android SAF), or open directly in the Config Code Editor.

### 4. Authorized Password Recovery
- **Local Key Verification**: Tests user-supplied password candidates, saved user password hints (stored locally in Room), and authorized custom wordlists against PBKDF2/AES-256 containers.
- **Transparent Limitations**: Clearly explains that strong `AES-256-GCM` encryption cannot be bypassed if the password is not present in the user's authorized hints or candidate list.

### 5. VPN Config Generator
- **Supported Protocols**:
  - `SSH_DIRECT` (TCP Port 22)
  - `SSH_TLS_SNI` (TLS Port 443 with Server Name Indication)
  - `SSH_WS_HTTP` (HTTP Port 80 WebSocket Upgrade Payload)
  - `SSH_WS_TLS` (WSS Port 443 WebSocket over TLS)
  - `V2RAY_VLESS_WS_TLS` (Structured VLESS JSON)
- **Validation & Live Endpoint Check**: Validates RFC-1123 hostnames, IPv4 addresses, TCP ports (`1–65535`), SNI hostnames, and WebSocket paths (`/...`). Clearly distinguishes `UNTESTED_GENERATED_TEMPLATE` configurations from `TESTED_CONNECTABLE_ENDPOINT` configurations verified via a live socket handshake.

### 6. Config Editor
- **Syntax Highlighting**: Highlights JSON keys, string literals, numbers/booleans, and HTTP Upgrade payload tokens (`[crlf]`, `GET`, `Upgrade`, `websocket`).
- **Full Editing Workflow**: Includes Find & Replace, JSON validation & formatting, scratch config creation, revert to original snapshot, saving edited copies separately, and locking configs into encrypted `.dark` containers.

### 7. VPN Connection Module (`DarkTunnelVpnService`)
- **Real Android `VpnService` Implementation**: Requests Android VPN permission via `VpnService.prepare()`, performs a pre-flight TCP/TLS/SNI socket handshake against the user's configured server, and establishes a real `tun0` (`ParcelFileDescriptor`) interface only after the server handshake succeeds.
- **Live Telemetry**: Displays connection status, handshake latency (`ms`), elapsed duration (`HH:MM:SS`), and real UID upload/download traffic counters via Android `TrafficStats`.

---

## Installation Instructions

### Installing from GitHub Releases or Workflow Artifacts
1. Navigate to the **Releases** page (`v1.0.0`) or the **Actions** tab (`Android CI, APK Artifact & GitHub Release Publisher`) of your `dark-tunnel-vpn-config-unlocker` repository.
2. Download `dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk` (or `dark-tunnel-vpn-config-unlocker-v1.0.0-release.apk` if release signing secrets were configured).
3. Transfer the APK to your Android device (Android 7.0 / API 24 or higher) and open it to install, or install via ADB:
   ```bash
   adb install -r dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk
   ```

---

## Local Build Instructions

### Prerequisites
- **JDK**: Java 17+ (targets Java 11 bytecode)
- **Android SDK**: `compileSdk 36`, `minSdk 24`, `targetSdk 36`

### Build & Test Commands
```bash
# 1. Run all Unit and Robolectric Acceptance Tests
gradle :app:testDebugUnitTest

# 2. Build the Debug APK
gradle :app:assembleDebug
# Output: app/build/outputs/apk/debug/app-debug.apk

# 3. Build a Signed Release APK (when keystore credentials are set in environment variables)
export KEYSTORE_PATH="/path/to/your-release-key.jks"
export STORE_PASSWORD="your_keystore_password"
export KEY_PASSWORD="your_key_password"
gradle :app:assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

---

## Publishing to GitHub & Triggering `v1.0.0` Release

This repository is pre-configured with Git (`main` branch, tag `v1.0.0`), `.gitignore` secret protection, `RELEASE_NOTES.md`, and `.github/workflows/android-build.yml`.

### Method A: One-Click Push from Google AI Studio UI
1. Click the **Settings / Export / GitHub** icon in the top toolbar of Google AI Studio.
2. Select **Push to GitHub** and authorize your GitHub account if prompted.
3. Enter the repository name: **`dark-tunnel-vpn-config-unlocker`**.
4. Once pushed, GitHub Actions will automatically build the project, run the Robolectric test suite, and upload `dark-tunnel-vpn-config-unlocker-apk` as a downloadable artifact.

### Method B: Push Repository & `v1.0.0` Release Tag via Git CLI
If you export the project ZIP or push from your terminal:
```bash
# 1. Create a new empty repository named 'dark-tunnel-vpn-config-unlocker' on GitHub:
#    https://github.com/new

# 2. Point the remote to your GitHub repository and push both the 'main' branch and 'v1.0.0' tag:
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/dark-tunnel-vpn-config-unlocker.git
git push -u origin main
git push origin v1.0.0
```
Pushing the `v1.0.0` tag automatically triggers the `Publish GitHub Release on Version Tag (v*.*.*)` step in `.github/workflows/android-build.yml`, creating a public GitHub Release titled **`Dark Tunnel VPN Config Unlocker (v1.0.0)`** with `dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk` and its `.sha256` checksum attached for direct download at:
- **Repository URL**: `https://github.com/<YOUR_GITHUB_USERNAME>/dark-tunnel-vpn-config-unlocker`
- **Direct Release APK Download URL**: `https://github.com/<YOUR_GITHUB_USERNAME>/dark-tunnel-vpn-config-unlocker/releases/download/v1.0.0/dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk`

---

## License

Licensed under the [MIT License](LICENSE).
