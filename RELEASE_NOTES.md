# Dark Tunnel VPN Config Unlocker — Release v1.0.0

**Release Title:** Dark Tunnel VPN Config Unlocker  
**Version:** `v1.0.0`  
**Package ID:** `com.aistudio.darktunnelunlocker.vpxkqz`  
**Minimum Android SDK:** Android 7.0 (API 24)  
**Target / Compile Android SDK:** Android 16 (API 36)

---

## What's Included in v1.0.0

1. **Config File Importer & Immutable Backup Engine**
   - Supports `.dark`, `.hat`, `.ehi`, `.nm`, `.hc`, `.json`, `.ovpn`, `.conf`, and `.txt` VPN configuration files via Android Storage Access Framework (SAF).
   - Automatically saves an untouched backup copy in `filesDir/config_backups/` before analysis, unlocking, or editing.
   - Computes SHA-256 file digests, Shannon Entropy (`0.00–8.00 bits/byte`), GZIP compression headers (`0x1F8B`), and binary container signatures (`DTV1`, `HAT1`, `EHI1`, `NM01`, `HC01`).

2. **Authentic Cryptographic Config Unlocker**
   - Decrypts compatible containers using `AES-256-GCM` and `AES-256-CBC` with `PBKDF2WithHmacSHA256` key derivation and SHA-256 plaintext checksum verification.
   - Never displays fake success messages—invalid keys report real `AEADBadTagException` / `BadPaddingException` diagnostics, and corrupted files are explicitly identified.

3. **Multi-Layer Config Decoder**
   - Iteratively decodes Base64 (RFC-4648 & URL-Safe), Hexadecimal (Base16), URL Percent-Encoding, and standard VPN URI schemes (`vmess://`, `vless://`, `trojan://`, `ss://`, `darktunnel://`).
   - Enforces a strict boundary between encoding and encryption, alerting the user when an encrypted container requires a decryption key.

4. **Authorized Password Recovery**
   - Tests user-supplied password candidates, saved user password hints (persisted in a local Room database), and authorized custom wordlists against PBKDF2/AES-256 containers.
   - Clearly explains mathematical limitations when strong `AES-256-GCM` encryption is used with an unknown password.

5. **VPN Config Generator**
   - Generates structured configurations for **SSH Direct**, **SSH over TLS (SNI)**, **SSH over WebSocket (HTTP Payload)**, **SSH over WebSocket + TLS (WSS)**, and **VLESS + WebSocket + TLS JSON**.
   - Validates hostnames, IPv4 addresses, TCP ports (`1–65535`), SNI hostnames, and WebSocket paths.
   - Clearly distinguishes `UNTESTED_GENERATED_TEMPLATE` files from `TESTED_CONNECTABLE_ENDPOINT` profiles verified via live TCP/TLS socket handshakes.

6. **Syntax-Highlighted Config Code Editor**
   - Custom `VisualTransformation` highlights JSON keys, string values, numbers/booleans, and HTTP Upgrade payload tokens (`[crlf]`, `GET`, `Upgrade`, `websocket`).
   - Supports Find & Replace, JSON formatting, scratch config creation, revert to original snapshot, separate copy saving, and AES-256-GCM `.dark` container locking.

7. **Real Android `VpnService` Connection Module (`DarkTunnelVpnService`)**
   - Requests Android VPN authorization via `VpnService.prepare()`, verifies remote server reachability via a real TCP/TLS/SNI handshake, and establishes a real `tun0` (`ParcelFileDescriptor`) interface with live elapsed time and `TrafficStats` upload/download byte telemetry.

---

## APK Installation Instructions

1. Download **`dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk`** (or the signed release APK if configured) from the **Assets** section below.
2. Verify the SHA-256 checksum against the `.sha256` file if desired:
   ```bash
   sha256sum -c dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk.sha256
   ```
3. On your Android device (Android 7.0+):
   - Open the downloaded `.apk` file from your Files or Downloads app.
   - If prompted, enable **Install unknown apps** for your browser or file manager.
   - Tap **Install** and launch **Dark Tunnel Unlocker**.
4. Or install via `adb` from a computer:
   ```bash
   adb install -r dark-tunnel-vpn-config-unlocker-v1.0.0-debug.apk
   ```
