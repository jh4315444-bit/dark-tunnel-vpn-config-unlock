package com.example.crypto

import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets

enum class TunnelProtocol(val displayName: String, val defaultPort: Int, val requiresSni: Boolean, val requiresWs: Boolean) {
    SSH_DIRECT("SSH Direct Tunnel", 22, false, false),
    SSH_TLS_SNI("SSH over TLS (SNI)", 443, true, false),
    SSH_WS_HTTP("SSH over WebSocket (HTTP Payload)", 80, false, true),
    SSH_WS_TLS("SSH over WebSocket + TLS (WSS)", 443, true, true),
    V2RAY_VLESS_WS_TLS("VLESS + WebSocket + TLS JSON", 443, true, true)
}

data class GeneratorInput(
    val profileName: String,
    val protocol: TunnelProtocol,
    val serverHost: String,
    val serverPortText: String,
    val username: String,
    val passwordOrUuid: String,
    val sniHost: String,
    val wsPath: String,
    val customHttpPayload: String,
    val primaryDns: String = "1.1.1.1",
    val secondaryDns: String = "8.8.8.8",
    val lockWithPassword: String = ""
)

data class ValidationResult(
    val isValid: Boolean,
    val errors: List<String>
)

data class GeneratedConfigBundle(
    val profileName: String,
    val protocol: TunnelProtocol,
    val readableJson: String,
    val darkTunnelUri: String,
    val encryptedDarkBytes: ByteArray?,
    val isVerifiedServer: Boolean
)

object ConfigGeneratorEngine {

    private val HOSTNAME_REGEX = Regex("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$")
    private val IPV4_REGEX = Regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$")

    fun validateInput(input: GeneratorInput): ValidationResult {
        val errors = mutableListOf<String>()
        if (input.profileName.isBlank()) {
            errors.add("Profile name is required.")
        }
        val host = input.serverHost.trim()
        if (host.isEmpty()) {
            errors.add("Server address (Hostname or IPv4) is required. Do not use blank servers.")
        } else if (!HOSTNAME_REGEX.matches(host) && !IPV4_REGEX.matches(host) && host != "localhost") {
            errors.add("Server address '$host' is not a valid RFC-1123 hostname or IPv4 address.")
        }

        val port = input.serverPortText.trim().toIntOrNull()
        if (port == null || port !in 1..65535) {
            errors.add("Port must be a valid TCP port number between 1 and 65535.")
        }

        if (input.username.isBlank()) {
            errors.add("Username (or UUID for VLESS) is required.")
        }

        if (input.protocol.requiresSni) {
            val sni = input.sniHost.trim()
            if (sni.isEmpty()) {
                errors.add("TLS SNI (Server Name Indication) hostname is required for ${input.protocol.displayName}.")
            } else if (!HOSTNAME_REGEX.matches(sni)) {
                errors.add("SNI hostname '$sni' is invalid.")
            }
        }

        if (input.protocol.requiresWs) {
            val path = input.wsPath.trim()
            if (path.isEmpty() || !path.startsWith("/")) {
                errors.add("WebSocket path must start with '/' (e.g., '/ws' or '/tunnel').")
            }
        }

        return ValidationResult(isValid = errors.isEmpty(), errors = errors)
    }

    fun generateDefaultHttpPayload(host: String, sni: String, wsPath: String): String {
        val targetHost = sni.ifBlank { host }
        val normalizedPath = wsPath.ifBlank { "/ws" }
        return "GET $normalizedPath HTTP/1.1[crlf]Host: $targetHost[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: DarkTunnelWorkbench/1.0[crlf][crlf]"
    }

    fun generateConfig(input: GeneratorInput, isVerifiedReachable: Boolean = false): GeneratedConfigBundle {
        val port = input.serverPortText.trim().toIntOrNull() ?: input.protocol.defaultPort
        val payload = input.customHttpPayload.ifBlank {
            if (input.protocol.requiresWs) {
                generateDefaultHttpPayload(input.serverHost.trim(), input.sniHost.trim(), input.wsPath.trim())
            } else {
                ""
            }
        }

        val root = JSONObject().apply {
            put("configVersion", "1.0")
            put("name", input.profileName.trim())
            put("protocol", input.protocol.name)
            put("protocolDisplay", input.protocol.displayName)
            put(
                "verificationStatus",
                if (isVerifiedReachable) "TESTED_CONNECTABLE_ENDPOINT" else "UNTESTED_GENERATED_TEMPLATE"
            )
            put("serverHost", input.serverHost.trim())
            put("serverPort", port)
            put("username", input.username.trim())
            if (input.passwordOrUuid.isNotBlank()) {
                put("authSecret", input.passwordOrUuid)
            }
            put(
                "tls",
                JSONObject().apply {
                    put("enabled", input.protocol.requiresSni)
                    put("sni", input.sniHost.trim())
                    put("alpn", "h2,http/1.1")
                }
            )
            put(
                "websocket",
                JSONObject().apply {
                    put("enabled", input.protocol.requiresWs)
                    put("path", input.wsPath.trim().ifBlank { "/" })
                    put("httpPayload", payload)
                }
            )
            put(
                "dns",
                JSONObject().apply {
                    put("primary", input.primaryDns)
                    put("secondary", input.secondaryDns)
                }
            )
            put("generatedAtIso", java.time.Instant.now().toString())
        }

        val prettyJson = root.toString(2)
        val encodedUri = "darktunnel://" + Base64.encodeToString(
            prettyJson.toByteArray(StandardCharsets.UTF_8),
            Base64.NO_WRAP
        ) + "#" + java.net.URLEncoder.encode(input.profileName.trim(), "UTF-8")

        val encryptedBytes = if (input.lockWithPassword.isNotBlank()) {
            ConfigCryptoEngine.createEncryptedContainer(
                plaintextConfig = prettyJson,
                password = input.lockWithPassword,
                formatExtension = "dark"
            )
        } else {
            null
        }

        return GeneratedConfigBundle(
            profileName = input.profileName.trim(),
            protocol = input.protocol,
            readableJson = prettyJson,
            darkTunnelUri = encodedUri,
            encryptedDarkBytes = encryptedBytes,
            isVerifiedServer = isVerifiedReachable
        )
    }

    /**
     * Provides documented, transparent sample payloads for user testing of the Unlocker, Decoder, and Recovery modules.
     * Explicitly marks any host inside sample files as a user-replaceable RFC-2606 example domain (example.com)
     * so it is never mistaken for a fake free-internet server.
     */
    fun buildAuthorizedSampleEncryptedDarkFile(samplePassword: String = "DarkTunnel#2026"): ByteArray {
        val sampleJson = JSONObject().apply {
            put("configVersion", "1.0")
            put("name", "Authorized Diagnostic Sample (.dark)")
            put("protocol", TunnelProtocol.SSH_WS_TLS.name)
            put("verificationStatus", "SAMPLE_DIAGNOSTIC_CONFIG_REPLACE_SERVER")
            put("serverHost", "example.com")
            put("serverPort", 443)
            put("username", "authorized_audit_user")
            put("tls", JSONObject().apply {
                put("enabled", true)
                put("sni", "example.com")
            })
            put("websocket", JSONObject().apply {
                put("enabled", true)
                put("path", "/ws-tunnel")
                put("httpPayload", "GET /ws-tunnel HTTP/1.1[crlf]Host: example.com[crlf]Upgrade: websocket[crlf][crlf]")
            })
            put("note", "Unlocked successfully! Replace example.com with your own authorized SSH/TLS server to establish a live tunnel.")
        }.toString(2)

        return ConfigCryptoEngine.createEncryptedContainer(
            plaintextConfig = sampleJson,
            password = samplePassword,
            formatExtension = "dark",
            cipherMode = "AES-256-GCM",
            passwordHintNote = "Default diagnostic test key: DarkTunnel#2026"
        )
    }

    fun buildAuthorizedSampleEncodedPayload(): String {
        val inner = JSONObject().apply {
            put("v", "2")
            put("ps", "Diagnostic-WS-TLS-Profile")
            put("add", "example.com")
            put("port", "443")
            put("id", "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
            put("net", "ws")
            put("type", "none")
            put("host", "example.com")
            put("path", "/v2ray-ws")
            put("tls", "tls")
            put("sni", "example.com")
        }.toString()
        val b64 = Base64.encodeToString(inner.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
        return "vmess://$b64"
    }
}
