package com.example.crypto

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import java.util.zip.ZipInputStream
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ln

enum class ConfigFormatState {
    ENCRYPTED_CONTAINER,
    COMPRESSED_ARCHIVE,
    ENCODED_TEXT,
    READABLE_JSON_OR_TEXT,
    CORRUPTED_OR_INVALID
}

data class FileAnalysisReport(
    val fileName: String,
    val extension: String,
    val sizeBytes: Long,
    val sha256Hex: String,
    val shannonEntropy: Double,
    val formatState: ConfigFormatState,
    val detectedContainerSignature: String,
    val diagnosticMessage: String,
    val canDirectDecode: Boolean,
    val requiresPasswordKey: Boolean
)

sealed class UnlockOperationResult {
    data class Success(
        val decryptedContent: String,
        val formattedInspectorReport: String,
        val parsedFields: Map<String, String>,
        val cipherSuiteUsed: String,
        val kdfIterations: Int,
        val integrityVerified: Boolean
    ) : UnlockOperationResult()

    data class Failure(
        val errorTitle: String,
        val technicalReason: String,
        val isWrongPassword: Boolean,
        val isCorruptedFile: Boolean
    ) : UnlockOperationResult()
}

data class DecodeStepTrace(
    val stepIndex: Int,
    val encodingType: String,
    val summary: String,
    val outputPreview: String
)

data class DecodeOperationResult(
    val isSuccessful: Boolean,
    val isEncryptedAndNeedsKey: Boolean,
    val finalOutput: String,
    val formattedInspectorReport: String,
    val detectedFormatSummary: String,
    val steps: List<DecodeStepTrace>,
    val parsedFields: Map<String, String>
)

data class PasswordRecoveryReport(
    val recoveredPassword: String?,
    val decryptedPayload: String?,
    val formattedInspectorReport: String?,
    val parsedFields: Map<String, String>,
    val testedCount: Int,
    val elapsedTimeMs: Long,
    val algorithmSummary: String,
    val explanationMessage: String
)

object ConfigCryptoEngine {

    private const val PBKDF2_ALGO = "PBKDF2WithHmacSHA256"
    private const val DEFAULT_ITERATIONS = 10000
    private const val KEY_LENGTH_BITS = 256
    private const val GCM_TAG_BITS = 128

    val SUPPORTED_EXTENSIONS = setOf("dark", "hat", "ehi", "nm", "hc", "json", "txt", "ovpn", "conf")

    fun computeSha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun computeShannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val counts = IntArray(256)
        for (b in bytes) {
            counts[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val length = bytes.size.toDouble()
        for (count in counts) {
            if (count > 0) {
                val p = count / length
                entropy -= p * (ln(p) / ln(2.0))
            }
        }
        return entropy
    }

    /**
     * Deeply unpacks compressed streams (GZIP, ZLIB, ZIP) at offset 0 or any header offset (0..128),
     * or decrypts standard container ciphers to extract readable JSON/configuration text.
     */
    fun tryDecompressContainerBytes(rawBytes: ByteArray): Pair<ByteArray, String?> {
        if (rawBytes.size < 4) return rawBytes to null

        // Scan offset 0..64 for GZIP, PKZIP, or ZLIB headers (handles .dark / .hat / .ehi / .hc / .nm with prefix headers)
        val maxOffset = minOf(rawBytes.size - 4, 64)
        for (offset in 0..maxOffset) {
            val b0 = rawBytes[offset]
            val b1 = rawBytes[offset + 1]

            // 1. Check GZIP magic (0x1F 0x8B)
            if (b0 == 0x1F.toByte() && b1 == 0x8B.toByte()) {
                try {
                    val sliced = if (offset == 0) rawBytes else rawBytes.copyOfRange(offset, rawBytes.size)
                    val out = gunzip(sliced)
                    if (out.isNotEmpty()) {
                        return out to if (offset == 0) "GZIP (0x1F8B)" else "GZIP @+$offset"
                    }
                } catch (_: Exception) {
                }
            }

            // 2. Check PKZIP magic (0x50 0x4B 0x03 0x04)
            if (b0 == 0x50.toByte() && b1 == 0x4B.toByte() &&
                rawBytes[offset + 2] == 0x03.toByte() && rawBytes[offset + 3] == 0x04.toByte()
            ) {
                try {
                    val sliced = if (offset == 0) rawBytes else rawBytes.copyOfRange(offset, rawBytes.size)
                    val entriesJson = JSONObject()
                    val firstJsonCandidate = mutableListOf<String>()
                    ZipInputStream(ByteArrayInputStream(sliced)).use { zis ->
                        var entry = zis.nextEntry
                        while (entry != null) {
                            if (!entry.isDirectory) {
                                val entryBytes = zis.readBytes()
                                val entryText = extractCleanJsonOrText(entryBytes)
                                if (entryText.isNotBlank()) {
                                    firstJsonCandidate.add(entryText)
                                    entriesJson.put(entry.name, tryParseJsonValue(entryText))
                                }
                            }
                            entry = zis.nextEntry
                        }
                    }
                    if (firstJsonCandidate.size == 1 && firstJsonCandidate[0].trim().startsWith("{")) {
                        return firstJsonCandidate[0].toByteArray(StandardCharsets.UTF_8) to "ZIP Container Archive"
                    } else if (entriesJson.length() > 0) {
                        return entriesJson.toString(2).toByteArray(StandardCharsets.UTF_8) to "ZIP Container Archive"
                    }
                } catch (_: Exception) {
                }
            }

            // 3. Check ZLIB Deflate magic (0x78 0x9C, 0x78 0x01, 0x78 0xDA, 0x78 0x5E)
            if (b0 == 0x78.toByte() &&
                (b1 == 0x9C.toByte() || b1 == 0x01.toByte() || b1 == 0xDA.toByte() || b1 == 0x5E.toByte())
            ) {
                try {
                    val sliced = if (offset == 0) rawBytes else rawBytes.copyOfRange(offset, rawBytes.size)
                    val bos = ByteArrayOutputStream()
                    InflaterInputStream(ByteArrayInputStream(sliced)).use { iis ->
                        iis.copyTo(bos)
                    }
                    val out = bos.toByteArray()
                    if (out.isNotEmpty() && isMostlyPrintableUtf8(out)) {
                        return out to if (offset == 0) "ZLIB Deflate (0x78)" else "ZLIB Deflate @+$offset"
                    }
                } catch (_: Exception) {
                }
            }
        }

        // 4. Try raw Inflater (nowrap = true) at common header offsets (0, 4, 8, 12, 16)
        for (offset in listOf(0, 4, 8, 12, 16)) {
            if (rawBytes.size <= offset + 4) continue
            try {
                val sliced = if (offset == 0) rawBytes else rawBytes.copyOfRange(offset, rawBytes.size)
                val inflater = Inflater(true)
                inflater.setInput(sliced)
                val bos = ByteArrayOutputStream()
                val buf = ByteArray(4096)
                var loops = 0
                while (!inflater.finished() && !inflater.needsInput() && loops < 256) {
                    val count = inflater.inflate(buf)
                    if (count <= 0) break
                    bos.write(buf, 0, count)
                    loops++
                }
                inflater.end()
                val out = bos.toByteArray()
                if (out.size >= 16 && isMostlyPrintableUtf8(out)) {
                    return out to "Raw Deflate Stream"
                }
            } catch (_: Exception) {
            }
        }

        return rawBytes to null
    }

    /**
     * Extracts clean, valid JSON or structured configuration text from a byte array,
     * stripping any binary header/footer or garbled bytes and converting non-JSON into clean JSON if needed.
     */
    fun cleanAndSanitizePrintableText(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        return extractCleanJsonOrText(bytes)
    }

    private fun extractCleanJsonOrText(bytes: ByteArray): String {
        val rawStr = String(bytes, StandardCharsets.UTF_8)

        // 1. If the whole string is already clean printable UTF-8:
        if (!rawStr.contains('\uFFFD') && isMostlyPrintableUtf8(bytes)) {
            val trimmed = rawStr.trim()
            // Check if there is a JSON object embedded in it (e.g., after a short text header)
            val embeddedJson = extractBalancedJsonBlock(trimmed)
            if (embeddedJson != null) {
                return embeddedJson
            }
            return trimmed
        }

        // 2. Scan for a balanced JSON object `{ ... }` or array `[ ... ]` inside a binary container
        val asciiMapped = buildString(bytes.size) {
            for (b in bytes) {
                val c = b.toInt() and 0xFF
                if (c in 32..126 || c == 9 || c == 10 || c == 13) {
                    append(c.toChar())
                } else {
                    append('\n')
                }
            }
        }

        val embeddedJson = extractBalancedJsonBlock(asciiMapped)
        if (embeddedJson != null) {
            return embeddedJson
        }

        // 3. Extract meaningful contiguous printable lines and structure them cleanly
        val cleanLines = asciiMapped.lines()
            .map { it.trim() }
            .filter { line ->
                line.length >= 4 && isMeaningfulConfigLine(line)
            }

        return cleanLines.joinToString("\n").trim()
    }

    /**
     * Finds and pretty-prints the largest valid balanced JSON object `{...}` or array `[...]` inside a text buffer.
     */
    fun extractBalancedJsonBlock(text: String): String? {
        val firstBrace = text.indexOf('{')
        val lastBrace = text.lastIndexOf('}')
        if (firstBrace >= 0 && lastBrace > firstBrace + 4) {
            val candidate = text.substring(firstBrace, lastBrace + 1)
            try {
                val json = JSONObject(candidate)
                return recursivelyDecodeAndFormatJsonObject(json).toString(2)
            } catch (_: Exception) {
                // Scan for balanced braces starting from each '{'
                var startIdx = firstBrace
                while (startIdx >= 0 && startIdx < lastBrace) {
                    var depth = 0
                    var inQuotes = false
                    var escaped = false
                    for (i in startIdx until text.length) {
                        val ch = text[i]
                        if (escaped) {
                            escaped = false
                            continue
                        }
                        if (ch == '\\') {
                            escaped = true
                            continue
                        }
                        if (ch == '"') {
                            inQuotes = !inQuotes
                            continue
                        }
                        if (!inQuotes) {
                            if (ch == '{') depth++
                            else if (ch == '}') {
                                depth--
                                if (depth == 0) {
                                    val sub = text.substring(startIdx, i + 1)
                                    if (sub.length >= 10) {
                                        try {
                                            val j = JSONObject(sub)
                                            return recursivelyDecodeAndFormatJsonObject(j).toString(2)
                                        } catch (_: Exception) {
                                        }
                                    }
                                    break
                                }
                            }
                        }
                    }
                    startIdx = text.indexOf('{', startIdx + 1)
                }
            }
        }
        return null
    }

    private fun isMeaningfulConfigLine(line: String): Boolean {
        if (line.isBlank()) return false
        var alphaNumOrJson = 0
        var weirdSymbols = 0
        for (ch in line) {
            when {
                ch.isLetterOrDigit() || ch in " {}:.,\"'/-_=@?&#[]()" -> alphaNumOrJson++
                else -> weirdSymbols++
            }
        }
        val ratio = alphaNumOrJson.toDouble() / line.length.toDouble()
        return ratio >= 0.85 && weirdSymbols <= 2
    }

    /**
     * Recursively formats a JSONObject and unpacks any nested JSON strings or Base64-encoded JSON values
     * so every nested key (`sshConfig`, `v2rayConfig`, `proxy`, `headers`, etc.) is crystal-clear JSON.
     */
    private fun recursivelyDecodeAndFormatJsonObject(json: JSONObject, depth: Int = 0): JSONObject {
        if (depth > 4) return json
        val out = JSONObject()
        val keys = json.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val v = json.opt(k)
            when (v) {
                is JSONObject -> {
                    out.put(k, recursivelyDecodeAndFormatJsonObject(v, depth + 1))
                }
                is JSONArray -> {
                    out.put(k, recursivelyDecodeAndFormatJsonArray(v, depth + 1))
                }
                is String -> {
                    val trimmedVal = v.trim()
                    // 1. If the string value itself is a serialized JSON object or array, parse it directly into real JSON!
                    if (trimmedVal.startsWith("{") && trimmedVal.endsWith("}")) {
                        try {
                            val innerObj = JSONObject(trimmedVal)
                            out.put(k, recursivelyDecodeAndFormatJsonObject(innerObj, depth + 1))
                            continue
                        } catch (_: Exception) {
                        }
                    } else if (trimmedVal.startsWith("[") && trimmedVal.endsWith("]")) {
                        try {
                            val innerArr = JSONArray(trimmedVal)
                            out.put(k, recursivelyDecodeAndFormatJsonArray(innerArr, depth + 1))
                            continue
                        } catch (_: Exception) {
                        }
                    }

                    // 2. If the key is a config/payload/data field (NOT salt/iv/ciphertext) and holds Base64 JSON/text, unpack it
                    val cryptoKeys = setOf("salt", "iv", "ciphertext", "plaintextsha256", "sha256", "signature", "mac")
                    if (k.lowercase() !in cryptoKeys && isLikelyBase64(trimmedVal) && trimmedVal.length >= 16) {
                        try {
                            val decBytes = decodeBase64Flexible(trimmedVal)
                            val (unpacked, _) = tryDecompressContainerBytes(decBytes)
                            if (isMostlyPrintableUtf8(unpacked)) {
                                val decStr = String(unpacked, StandardCharsets.UTF_8).trim()
                                if (decStr.startsWith("{") && decStr.endsWith("}")) {
                                    out.put(k, recursivelyDecodeAndFormatJsonObject(JSONObject(decStr), depth + 1))
                                    continue
                                } else if (decStr.isNotEmpty()) {
                                    out.put(k, decStr)
                                    continue
                                }
                            }
                        } catch (_: Exception) {
                        }
                    }
                    out.put(k, v)
                }
                else -> out.put(k, v)
            }
        }
        return out
    }

    private fun recursivelyDecodeAndFormatJsonArray(arr: JSONArray, depth: Int = 0): JSONArray {
        if (depth > 4) return arr
        val out = JSONArray()
        for (i in 0 until arr.length()) {
            val v = arr.opt(i)
            when (v) {
                is JSONObject -> out.put(recursivelyDecodeAndFormatJsonObject(v, depth + 1))
                is JSONArray -> out.put(recursivelyDecodeAndFormatJsonArray(v, depth + 1))
                is String -> {
                    val trimmedVal = v.trim()
                    if (trimmedVal.startsWith("{") && trimmedVal.endsWith("}")) {
                        try {
                            out.put(recursivelyDecodeAndFormatJsonObject(JSONObject(trimmedVal), depth + 1))
                        } catch (_: Exception) {
                            out.put(v)
                        }
                    } else {
                        out.put(v)
                    }
                }
                else -> out.put(v)
            }
        }
        return out
    }

    private fun tryParseJsonValue(text: String): Any {
        val trimmed = text.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                return recursivelyDecodeAndFormatJsonObject(JSONObject(trimmed))
            } catch (_: Exception) {
            }
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            try {
                return recursivelyDecodeAndFormatJsonArray(JSONArray(trimmed))
            } catch (_: Exception) {
            }
        }
        return trimmed
    }

    /**
     * Converts any non-JSON configuration text (such as INI, key=value, OpenVPN, SSH/HTTP Payload, or URI)
     * into a clean, well-structured, 2-space indented JSON string so the output ALWAYS matches the
     * clean JSON format expected by the user.
     */
    fun ensureCleanFormattedJsonOutput(rawText: String, parsedFields: Map<String, String>): String {
        val trimmed = rawText.trim()
        if (trimmed.isEmpty()) return "{\n}"

        // 1. If already a JSON object
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val json = JSONObject(trimmed)
                return recursivelyDecodeAndFormatJsonObject(json).toString(2)
            } catch (_: Exception) {
            }
        }

        // 2. If already a JSON array
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            try {
                val arr = JSONArray(trimmed)
                return recursivelyDecodeAndFormatJsonArray(arr).toString(2)
            } catch (_: Exception) {
            }
        }

        // 3. Check if a balanced JSON object is embedded inside the text
        val embedded = extractBalancedJsonBlock(trimmed)
        if (embedded != null) {
            return embedded
        }

        // 4. Construct a clean, structured JSON object from extracted fields and directives
        val structuredJson = JSONObject()
        if (parsedFields.isNotEmpty()) {
            for ((k, v) in parsedFields) {
                if (k == "add" && parsedFields.containsKey("Server Host / IP")) continue
                val numVal = v.toIntOrNull()
                val boolVal = when (v.lowercase()) {
                    "true", "yes (active)" -> true
                    "false", "no" -> false
                    else -> null
                }
                when {
                    numVal != null -> structuredJson.put(k, numVal)
                    boolVal != null -> structuredJson.put(k, boolVal)
                    else -> structuredJson.put(k, v)
                }
            }
        }

        val lines = trimmed.lines().map { it.trim() }.filter { it.isNotEmpty() }
        for (line in lines) {
            if (line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) continue
            if (line.contains("=")) {
                val key = line.substringBefore("=").trim()
                val value = line.substringAfter("=").trim().removeSurrounding("\"")
                if (key.isNotEmpty() && !structuredJson.has(key)) {
                    val asInt = value.toIntOrNull()
                    if (asInt != null) structuredJson.put(key, asInt) else structuredJson.put(key, value)
                }
            } else if (line.contains(":") && !line.startsWith("GET ") && !line.startsWith("POST ") && !line.startsWith("CONNECT ")) {
                val key = line.substringBefore(":").trim()
                val value = line.substringAfter(":").trim().removeSurrounding("\"")
                if (key.length in 1..32 && !structuredJson.has(key)) {
                    val asInt = value.toIntOrNull()
                    if (asInt != null) structuredJson.put(key, asInt) else structuredJson.put(key, value)
                }
            }
        }

        if (structuredJson.length() == 0) {
            structuredJson.put("configData", trimmed)
        }
        return structuredJson.toString(2)
    }

    fun analyzeConfigBytes(fileName: String, rawBytes: ByteArray): FileAnalysisReport {
        val ext = fileName.substringAfterLast('.', "").lowercase()
        val sha256 = computeSha256(rawBytes)
        val entropy = computeShannonEntropy(rawBytes)

        if (rawBytes.isEmpty()) {
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = 0L,
                sha256Hex = sha256,
                shannonEntropy = 0.0,
                formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                detectedContainerSignature = "EMPTY_BUFFER",
                diagnosticMessage = "File contains 0 bytes. Corrupted or empty file.",
                canDirectDecode = false,
                requiresPasswordKey = false
            )
        }

        // Check if compressed (GZIP, ZIP, ZLIB)
        val (decompressedBytes, compressionLabel) = tryDecompressContainerBytes(rawBytes)
        if (compressionLabel != null) {
            val innerText = cleanAndSanitizePrintableText(decompressedBytes)
            val isEncryptedInner = innerText.contains("\"ciphertext\"") && (innerText.contains("\"salt\"") || innerText.contains("\"iv\""))
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = rawBytes.size.toLong(),
                sha256Hex = sha256,
                shannonEntropy = entropy,
                formatState = ConfigFormatState.COMPRESSED_ARCHIVE,
                detectedContainerSignature = compressionLabel,
                diagnosticMessage = "Compressed $compressionLabel container detected (${decompressedBytes.size} bytes unpacked). Ready for clean JSON decoding.",
                canDirectDecode = !isEncryptedInner,
                requiresPasswordKey = isEncryptedInner
            )
        }

        // Check GZIP header that failed decompression (truncated/corrupted)
        if (rawBytes.size >= 2 && rawBytes[0] == 0x1F.toByte() && rawBytes[1] == 0x8B.toByte()) {
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = rawBytes.size.toLong(),
                sha256Hex = sha256,
                shannonEntropy = entropy,
                formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                detectedContainerSignature = "TRUNCATED_GZIP",
                diagnosticMessage = "GZIP header found (0x1F8B), but deflate stream is truncated or corrupted.",
                canDirectDecode = false,
                requiresPasswordKey = false
            )
        }

        // Check Binary Magic Headers: DTV1, HAT1, EHI1, NM01, HC01
        if (rawBytes.size >= 32) {
            val magic4 = String(rawBytes.copyOfRange(0, 4), StandardCharsets.US_ASCII)
            if (magic4 in setOf("DTV1", "HAT1", "EHI1", "NM01", "HC01")) {
                return FileAnalysisReport(
                    fileName = fileName,
                    extension = ext,
                    sizeBytes = rawBytes.size.toLong(),
                    sha256Hex = sha256,
                    shannonEntropy = entropy,
                    formatState = ConfigFormatState.ENCRYPTED_CONTAINER,
                    detectedContainerSignature = "$magic4 Binary AES-256-GCM",
                    diagnosticMessage = "Authenticated $magic4 binary encrypted container detected (PBKDF2-HMAC-SHA256 + AES-256-GCM). Requires valid decryption password or key.",
                    canDirectDecode = false,
                    requiresPasswordKey = true
                )
            }
        }

        val textTrimmed = String(rawBytes, StandardCharsets.UTF_8).trim()

        // Check JSON structure
        if (textTrimmed.startsWith("{") && textTrimmed.endsWith("}")) {
            return try {
                val json = JSONObject(textTrimmed)
                val isEncryptedEnvelope = json.has("ciphertext") && (json.has("salt") || json.has("iv"))
                if (isEncryptedEnvelope) {
                    val cipherName = json.optString("cipher", "AES-256-GCM")
                    val kdfName = json.optString("kdf", "PBKDF2-HMAC-SHA256")
                    FileAnalysisReport(
                        fileName = fileName,
                        extension = ext,
                        sizeBytes = rawBytes.size.toLong(),
                        sha256Hex = sha256,
                        shannonEntropy = entropy,
                        formatState = ConfigFormatState.ENCRYPTED_CONTAINER,
                        detectedContainerSignature = "JSON Envelope ($cipherName / $kdfName)",
                        diagnosticMessage = "Encrypted VPN container envelope detected. Protected with $cipherName and $kdfName. Enter password or use Unlocker.",
                        canDirectDecode = false,
                        requiresPasswordKey = true
                    )
                } else {
                    FileAnalysisReport(
                        fileName = fileName,
                        extension = ext,
                        sizeBytes = rawBytes.size.toLong(),
                        sha256Hex = sha256,
                        shannonEntropy = entropy,
                        formatState = ConfigFormatState.READABLE_JSON_OR_TEXT,
                        detectedContainerSignature = "Plaintext JSON Tunnel Profile",
                        diagnosticMessage = "Readable JSON configuration structure verified (${json.length()} top-level keys). All fields ready for clear JSON view.",
                        canDirectDecode = true,
                        requiresPasswordKey = false
                    )
                }
            } catch (e: Exception) {
                FileAnalysisReport(
                    fileName = fileName,
                    extension = ext,
                    sizeBytes = rawBytes.size.toLong(),
                    sha256Hex = sha256,
                    shannonEntropy = entropy,
                    formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                    detectedContainerSignature = "MALFORMED_JSON",
                    diagnosticMessage = "File starts/ends with braces but JSON syntax is malformed or corrupted: ${e.message}",
                    canDirectDecode = false,
                    requiresPasswordKey = false
                )
            }
        }

        // Check URI schemes or Base64 / Hex encoding
        if (textTrimmed.startsWith("vmess://") ||
            textTrimmed.startsWith("vless://") ||
            textTrimmed.startsWith("ss://") ||
            textTrimmed.startsWith("trojan://") ||
            textTrimmed.startsWith("darktunnel://") ||
            textTrimmed.startsWith("ssh://") ||
            isLikelyBase64(textTrimmed) ||
            isLikelyHex(textTrimmed)
        ) {
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = rawBytes.size.toLong(),
                sha256Hex = sha256,
                shannonEntropy = entropy,
                formatState = ConfigFormatState.ENCODED_TEXT,
                detectedContainerSignature = detectEncodingLabel(textTrimmed),
                diagnosticMessage = "Encoded configuration payload detected (${detectEncodingLabel(textTrimmed)}). Open Decoder or Unlocker to view clean formatted JSON.",
                canDirectDecode = true,
                requiresPasswordKey = false
            )
        }

        if (entropy > 7.1 || !isMostlyPrintableUtf8(rawBytes)) {
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = rawBytes.size.toLong(),
                sha256Hex = sha256,
                shannonEntropy = entropy,
                formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                detectedContainerSignature = "BINARY_OR_PROPRIETARY_CONTAINER",
                diagnosticMessage = "High entropy (${"%.2f".format(entropy)} bits/byte) binary container. Use Decoder or Unlocker to extract structured JSON configuration.",
                canDirectDecode = true,
                requiresPasswordKey = false
            )
        }

        return FileAnalysisReport(
            fileName = fileName,
            extension = ext,
            sizeBytes = rawBytes.size.toLong(),
            sha256Hex = sha256,
            shannonEntropy = entropy,
            formatState = ConfigFormatState.READABLE_JSON_OR_TEXT,
            detectedContainerSignature = "Plaintext Tunnel Script / Directives",
            diagnosticMessage = "Readable configuration detected. Ready for clear JSON inspection and editing.",
            canDirectDecode = true,
            requiresPasswordKey = false
        )
    }

    fun createEncryptedContainer(
        plaintextConfig: String,
        password: String,
        formatExtension: String = "dark",
        cipherMode: String = "AES-256-GCM",
        iterations: Int = DEFAULT_ITERATIONS,
        passwordHintNote: String = ""
    ): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(16).also { random.nextBytes(it) }
        val keyBytes = deriveKeyPbkdf2(password, salt, iterations)
        val secretKey = SecretKeySpec(keyBytes, "AES")

        val iv = if (cipherMode == "AES-256-CBC") {
            ByteArray(16).also { random.nextBytes(it) }
        } else {
            ByteArray(12).also { random.nextBytes(it) }
        }

        val cipher = if (cipherMode == "AES-256-CBC") {
            Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
                init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
            }
        } else {
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        }

        val ciphertext = cipher.doFinal(plaintextConfig.toByteArray(StandardCharsets.UTF_8))
        val envelope = JSONObject().apply {
            put("magic", "DARK_TUNNEL_CONTAINER_V1")
            put("format", formatExtension.lowercase())
            put("cipher", cipherMode)
            put("kdf", PBKDF2_ALGO)
            put("iterations", iterations)
            put("salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            put("plaintextSha256", computeSha256(plaintextConfig.toByteArray(StandardCharsets.UTF_8)))
            if (passwordHintNote.isNotBlank()) {
                put("hint", passwordHintNote)
            }
        }
        return envelope.toString(2).toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Unlocks encrypted containers and also deeply decodes any nested Base64/Hex/URI/JSON layers inside
     * so the user immediately sees crystal-clear, 2-space indented JSON configuration data.
     */
    fun unlockContainer(rawBytes: ByteArray, passwordOrKey: String): UnlockOperationResult {
        if (rawBytes.isEmpty()) {
            return UnlockOperationResult.Failure(
                errorTitle = "Empty or Corrupted Input",
                technicalReason = "Cannot unlock an empty (0-byte) configuration buffer.",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }

        // First decompress if GZIP / ZIP / ZLIB wrapped
        val (workingBytes, compressionLabel) = tryDecompressContainerBytes(rawBytes)
        if (compressionLabel == null && rawBytes.size >= 2 && rawBytes[0] == 0x1F.toByte() && rawBytes[1] == 0x8B.toByte()) {
            return UnlockOperationResult.Failure(
                errorTitle = "Corrupted GZIP Container",
                technicalReason = "GZIP header (0x1F8B) found, but compressed deflate stream is corrupted or truncated.",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }

        // Check if the file is actually encoded/compressed (no password encryption) — if so, decode it into clean JSON!
        val workingText = String(workingBytes, StandardCharsets.UTF_8).trim()
        val isBinaryMagic = workingBytes.size >= 32 &&
            String(workingBytes.copyOfRange(0, 4), StandardCharsets.US_ASCII) in setOf("DTV1", "HAT1", "EHI1", "NM01", "HC01")
        val isJsonEncrypted = workingText.startsWith("{") && workingText.endsWith("}") &&
            workingText.contains("\"ciphertext\"") && (workingText.contains("\"salt\"") || workingText.contains("\"iv\""))

        if (!isBinaryMagic && !isJsonEncrypted) {
            if (workingText.startsWith("{") && !workingText.endsWith("}")) {
                return UnlockOperationResult.Failure(
                    errorTitle = "Corrupted JSON Container",
                    technicalReason = "Container starts with '{' but is truncated or malformed.",
                    isWrongPassword = false,
                    isCorruptedFile = true
                )
            }
            val decoded = decodePayloadFromBytes(workingBytes)
            if (decoded.isSuccessful && decoded.finalOutput.isNotBlank()) {
                return UnlockOperationResult.Success(
                    decryptedContent = decoded.finalOutput,
                    formattedInspectorReport = decoded.formattedInspectorReport,
                    parsedFields = decoded.parsedFields,
                    cipherSuiteUsed = compressionLabel ?: decoded.detectedFormatSummary,
                    kdfIterations = 0,
                    integrityVerified = true
                )
            }
        }

        if (passwordOrKey.isEmpty()) {
            return UnlockOperationResult.Failure(
                errorTitle = "Password / Decryption Key Required",
                technicalReason = "No decryption password or key was supplied. Enter the valid key to derive the AES-256 decryption key.",
                isWrongPassword = true,
                isCorruptedFile = false
            )
        }

        // Check Binary Header DTV1 / HAT1 / EHI1 / NM01 / HC01
        if (isBinaryMagic) {
            val magic4 = String(workingBytes.copyOfRange(0, 4), StandardCharsets.US_ASCII)
            return try {
                val salt = workingBytes.copyOfRange(4, 20)
                val iv = workingBytes.copyOfRange(20, 32)
                val ciphertext = workingBytes.copyOfRange(32, workingBytes.size)
                val keyBytes = deriveKeyPbkdf2(passwordOrKey, salt, DEFAULT_ITERATIONS)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
                val plainBytes = cipher.doFinal(ciphertext)
                val rawPlainText = String(plainBytes, StandardCharsets.UTF_8)
                val deepDecoded = decodePayload(rawPlainText)
                val finalCleanText = if (deepDecoded.isSuccessful) deepDecoded.finalOutput else rawPlainText
                val fields = extractReadableConfigFields(finalCleanText)
                val cleanPrettyJson = ensureCleanFormattedJsonOutput(finalCleanText, fields)
                UnlockOperationResult.Success(
                    decryptedContent = rawPlainText,
                    formattedInspectorReport = cleanPrettyJson,
                    parsedFields = fields,
                    cipherSuiteUsed = "$magic4 Binary AES-256-GCM",
                    kdfIterations = DEFAULT_ITERATIONS,
                    integrityVerified = true
                )
            } catch (e: AEADBadTagException) {
                UnlockOperationResult.Failure(
                    errorTitle = "Authentication Tag Verification Failed",
                    technicalReason = "AES-256-GCM MAC tag mismatch (AEADBadTagException). The supplied password is incorrect or the ciphertext has been tampered with.",
                    isWrongPassword = true,
                    isCorruptedFile = false
                )
            } catch (e: Exception) {
                UnlockOperationResult.Failure(
                    errorTitle = "Binary Container Decryption Error",
                    technicalReason = "Cryptographic exception: ${e.javaClass.simpleName}: ${e.message}",
                    isWrongPassword = false,
                    isCorruptedFile = true
                )
            }
        }

        if (!workingText.startsWith("{") || !workingText.endsWith("}")) {
            return UnlockOperationResult.Failure(
                errorTitle = "Unsupported or Corrupted Container Format",
                technicalReason = "Input does not match a documented encrypted JSON envelope or DTV1/HAT1/EHI1/NM01/HC01 binary header.",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }

        val json = try {
            JSONObject(workingText)
        } catch (e: Exception) {
            return UnlockOperationResult.Failure(
                errorTitle = "Corrupted JSON Container",
                technicalReason = "Container JSON is malformed: ${e.message}",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }

        if (!json.has("ciphertext") || !json.has("iv") || !json.has("salt")) {
            return UnlockOperationResult.Failure(
                errorTitle = "Not an Encrypted Container",
                technicalReason = "JSON file does not contain 'salt', 'iv', and 'ciphertext' fields.",
                isWrongPassword = false,
                isCorruptedFile = false
            )
        }

        return try {
            val cipherMode = json.optString("cipher", "AES-256-GCM")
            val iterations = json.optInt("iterations", DEFAULT_ITERATIONS).coerceIn(1000, 200000)
            val salt = Base64.decode(json.getString("salt"), Base64.DEFAULT)
            val iv = Base64.decode(json.getString("iv"), Base64.DEFAULT)
            val ciphertext = Base64.decode(json.getString("ciphertext"), Base64.DEFAULT)
            val expectedSha256 = json.optString("plaintextSha256", "")

            val keyBytes = deriveKeyPbkdf2(passwordOrKey, salt, iterations)
            val secretKey = SecretKeySpec(keyBytes, "AES")

            val plainBytes = if (cipherMode.contains("CBC", ignoreCase = true)) {
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
                cipher.doFinal(ciphertext)
            } else {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
                cipher.doFinal(ciphertext)
            }

            if (expectedSha256.isNotBlank()) {
                val actualSha256 = computeSha256(plainBytes)
                if (!actualSha256.equals(expectedSha256, ignoreCase = true)) {
                    return UnlockOperationResult.Failure(
                        errorTitle = "Plaintext Checksum Mismatch",
                        technicalReason = "Decryption completed, but SHA-256 checksum ($actualSha256) did not match expected ($expectedSha256). Wrong key or corrupted payload.",
                        isWrongPassword = true,
                        isCorruptedFile = false
                    )
                }
            }

            val decryptedText = String(plainBytes, StandardCharsets.UTF_8)
            if (!isMostlyPrintableUtf8(plainBytes)) {
                return UnlockOperationResult.Failure(
                    errorTitle = "Decrypted Output Unreadable",
                    technicalReason = "Decrypted bytes contain non-printable binary garbage. The supplied key is incorrect.",
                    isWrongPassword = true,
                    isCorruptedFile = false
                )
            }

            // Also run deep decode in case the decrypted payload contains nested Base64/URIs
            val deepDecoded = decodePayload(decryptedText)
            val bestReadable = if (deepDecoded.isSuccessful && deepDecoded.finalOutput.isNotBlank()) {
                deepDecoded.finalOutput
            } else {
                decryptedText
            }
            val parsedFields = extractReadableConfigFields(bestReadable)
            val cleanPrettyJson = ensureCleanFormattedJsonOutput(bestReadable, parsedFields)

            UnlockOperationResult.Success(
                decryptedContent = decryptedText,
                formattedInspectorReport = cleanPrettyJson,
                parsedFields = parsedFields,
                cipherSuiteUsed = "$cipherMode / PBKDF2-HMAC-SHA256",
                kdfIterations = iterations,
                integrityVerified = true
            )
        } catch (e: AEADBadTagException) {
            UnlockOperationResult.Failure(
                errorTitle = "Incorrect Password or Key (GCM Auth Failed)",
                technicalReason = "AES-256-GCM authentication tag verification failed (AEADBadTagException). The password entered does not match the encryption key.",
                isWrongPassword = true,
                isCorruptedFile = false
            )
        } catch (e: BadPaddingException) {
            UnlockOperationResult.Failure(
                errorTitle = "Incorrect Password or Key (PKCS5 Padding Failed)",
                technicalReason = "AES-256-CBC padding verification failed (BadPaddingException). The password entered is invalid.",
                isWrongPassword = true,
                isCorruptedFile = false
            )
        } catch (e: IllegalArgumentException) {
            UnlockOperationResult.Failure(
                errorTitle = "Corrupted Base64 Ciphertext Fields",
                technicalReason = "Container fields ('salt', 'iv', or 'ciphertext') contain corrupted Base64 data: ${e.message}",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        } catch (e: Exception) {
            UnlockOperationResult.Failure(
                errorTitle = "Decryption Failed",
                technicalReason = "Cryptographic error: ${e.javaClass.simpleName} - ${e.message}",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }
    }

    /**
     * Decodes raw file bytes (handling GZIP/ZLIB/ZIP decompression, binary string extraction, and multi-layer text decoding)
     * into a clean, 2-space indented JSON structure.
     */
    fun decodePayloadFromBytes(rawBytes: ByteArray): DecodeOperationResult {
        val (unpackedBytes, compressionType) = tryDecompressContainerBytes(rawBytes)
        val cleanText = cleanAndSanitizePrintableText(unpackedBytes)
        val result = decodePayload(cleanText)
        if (compressionType != null) {
            val prependedStep = DecodeStepTrace(
                stepIndex = 0,
                encodingType = "Decompress $compressionType",
                summary = "Unpacked $compressionType stream (${rawBytes.size} B -> ${unpackedBytes.size} B).",
                outputPreview = result.finalOutput.take(180)
            )
            return result.copy(
                detectedFormatSummary = "$compressionType + ${result.detectedFormatSummary}",
                steps = listOf(prependedStep) + result.steps
            )
        }
        return result
    }

    /**
     * Multi-layer decoder for Base64, URL-Safe Base64, Hexadecimal, URL Encoding, GZIP-in-Base64,
     * JSON pretty-printing, and VPN URI schemes (vmess://, vless://, trojan://, ss://, darktunnel://, ssh://).
     * Always produces a crystal-clear, 2-space indented JSON string in both `finalOutput` and `formattedInspectorReport`.
     */
    fun decodePayload(rawInput: String): DecodeOperationResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return DecodeOperationResult(
                isSuccessful = false,
                isEncryptedAndNeedsKey = false,
                finalOutput = "",
                formattedInspectorReport = "",
                detectedFormatSummary = "Empty Input",
                steps = emptyList(),
                parsedFields = emptyMap()
            )
        }

        // Check if input is actually an encrypted container
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val json = JSONObject(trimmed)
                if (json.has("ciphertext") && (json.has("salt") || json.has("iv"))) {
                    val cipher = json.optString("cipher", "AES-256-GCM")
                    val kdf = json.optString("kdf", "PBKDF2-HMAC-SHA256")
                    val hint = json.optString("hint", "")
                    val fields = linkedMapOf(
                        "Container Status" to "LOCKED / ENCRYPTED (Key Required)",
                        "Cipher Algorithm" to cipher,
                        "Key Derivation (KDF)" to kdf
                    )
                    if (hint.isNotBlank()) {
                        fields["Password Hint"] = hint
                    }
                    val prettyLocked = json.toString(2)
                    return DecodeOperationResult(
                        isSuccessful = false,
                        isEncryptedAndNeedsKey = true,
                        finalOutput = prettyLocked,
                        formattedInspectorReport = prettyLocked,
                        detectedFormatSummary = "Encrypted Container ($cipher)",
                        steps = listOf(
                            DecodeStepTrace(
                                stepIndex = 1,
                                encodingType = "Cryptographic Container Detected",
                                summary = "Detected $cipher encrypted payload. Encrypted containers require a decryption password in the Config Unlocker screen.",
                                outputPreview = prettyLocked.take(180)
                            )
                        ),
                        parsedFields = fields
                    )
                }
            } catch (_: Exception) {
            }
        }

        val steps = mutableListOf<DecodeStepTrace>()
        var current = trimmed
        var stepCounter = 1

        // Iterative decoding loop (up to 6 layers of URIs, Hex, URL-Encoding, Base64, GZIP-in-Base64, and JSON)
        varprog@ for (depth in 0 until 6) {
            val candidate = current.trim()
            val lower = candidate.lowercase()

            // 1. Handle VPN URI schemes: vmess://, darktunnel://, ss://, vless://, trojan://, ssh://
            if (lower.startsWith("vmess://") || lower.startsWith("darktunnel://") || lower.startsWith("ss://")) {
                val scheme = candidate.substringBefore("://") + "://"
                val body = candidate.substringAfter("://").substringBefore("#").trim()
                val fragment = if (candidate.contains("#")) {
                    try {
                        URLDecoder.decode(candidate.substringAfter("#"), "UTF-8")
                    } catch (_: Exception) {
                        candidate.substringAfter("#")
                    }
                } else ""

                try {
                    val decodedBytes = decodeBase64Flexible(body)
                    val (unpacked, _) = tryDecompressContainerBytes(decodedBytes)
                    if (isMostlyPrintableUtf8(unpacked)) {
                        var decodedStr = String(unpacked, StandardCharsets.UTF_8).trim()
                        if (decodedStr.startsWith("{") && decodedStr.endsWith("}")) {
                            try {
                                val j = recursivelyDecodeAndFormatJsonObject(JSONObject(decodedStr))
                                if (fragment.isNotBlank() && !j.has("remarks") && !j.has("ps")) {
                                    j.put("remarks", fragment)
                                }
                                decodedStr = j.toString(2)
                            } catch (_: Exception) {
                            }
                        } else if (fragment.isNotBlank()) {
                            decodedStr = "$decodedStr\n# Profile Name: $fragment"
                        }
                        current = decodedStr
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "$scheme URI + Base64 Unpack",
                                summary = "Decoded $scheme tunnel URI into clear readable JSON configuration.",
                                outputPreview = current.take(180)
                            )
                        )
                        continue@varprog
                    }
                } catch (_: Exception) {
                }
            } else if (lower.startsWith("vless://") || lower.startsWith("trojan://") || lower.startsWith("ssh://")) {
                val parsed = parseStandardVpnUri(candidate)
                val prettyJson = JSONObject(parsed).toString(2)
                current = prettyJson
                steps.add(
                    DecodeStepTrace(
                        stepIndex = stepCounter++,
                        encodingType = "${candidate.substringBefore("://").uppercase()} URI Dissection",
                        summary = "Parsed tunnel URI parameters into structured readable JSON.",
                        outputPreview = prettyJson.take(180)
                    )
                )
                break@varprog
            }

            // 2. If valid JSON, recursively unpack all nested JSON strings and Base64 fields and pretty-print with 2-space indentation
            if (candidate.startsWith("{") && candidate.endsWith("}")) {
                try {
                    val jsonObj = JSONObject(candidate)
                    val unpackedObj = recursivelyDecodeAndFormatJsonObject(jsonObj)
                    val pretty = unpackedObj.toString(2)
                    if (pretty != current) {
                        current = pretty
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "JSON Structure Formatting",
                                summary = "Formatted and unpacked all JSON configuration fields (${unpackedObj.length()} keys).",
                                outputPreview = current.take(180)
                            )
                        )
                    }
                    break@varprog
                } catch (_: Exception) {
                }
            }

            // 3. Try Hexadecimal decode
            if (isLikelyHex(candidate)) {
                try {
                    val hexBytes = decodeHex(candidate)
                    val (unpacked, _) = tryDecompressContainerBytes(hexBytes)
                    if (isMostlyPrintableUtf8(unpacked)) {
                        current = String(unpacked, StandardCharsets.UTF_8).trim()
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "Hexadecimal (Base16) Decode",
                                summary = "Converted hexadecimal byte stream into ${unpacked.size} readable UTF-8 bytes.",
                                outputPreview = current.take(180)
                            )
                        )
                        continue@varprog
                    }
                } catch (_: Exception) {
                }
            }

            // 4. Try URL percent-decoding
            if (candidate.contains("%22") || candidate.contains("%7B") || candidate.contains("%3A") || candidate.contains("%2F")) {
                try {
                    val urlDecoded = URLDecoder.decode(candidate, "UTF-8")
                    if (urlDecoded != candidate) {
                        current = urlDecoded.trim()
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "URL Percent-Decode",
                                summary = "Unescaped URL percent-encoded configuration characters.",
                                outputPreview = current.take(180)
                            )
                        )
                        continue@varprog
                    }
                } catch (_: Exception) {
                }
            }

            // 5. Try Base64 decode (including GZIP/ZLIB compressed Base64 payloads common in .ehi / .hat / .hc)
            if (isLikelyBase64(candidate)) {
                try {
                    val b64Bytes = decodeBase64Flexible(candidate)
                    val (unpacked, compLabel) = tryDecompressContainerBytes(b64Bytes)
                    if (unpacked.isNotEmpty() && isMostlyPrintableUtf8(unpacked)) {
                        val b64Text = String(unpacked, StandardCharsets.UTF_8).trim()
                        if (b64Text != candidate) {
                            current = b64Text
                            val label = if (compLabel != null) "Base64 + $compLabel" else "Base64 (RFC-4648)"
                            steps.add(
                                DecodeStepTrace(
                                    stepIndex = stepCounter++,
                                    encodingType = label,
                                    summary = "Decoded $label stream into ${unpacked.size} readable UTF-8 bytes.",
                                    outputPreview = current.take(180)
                                )
                            )
                            continue@varprog
                        }
                    }
                } catch (_: Exception) {
                }
            }

            // 6. If multi-line config contains embedded Base64 blobs or key=value pairs, decode embedded values
            if (candidate.contains("\n") || candidate.contains("=")) {
                val decodedLines = decodeEmbeddedLinesIfAny(candidate)
                if (decodedLines != null && decodedLines != candidate) {
                    current = decodedLines
                    steps.add(
                        DecodeStepTrace(
                            stepIndex = stepCounter++,
                            encodingType = "Embedded Directive Value Decode",
                            summary = "Decoded Base64/Hex values embedded inside configuration directives.",
                            outputPreview = current.take(180)
                        )
                    )
                    continue@varprog
                }
            }

            break@varprog
        }

        val extractedFields = extractReadableConfigFields(current)
        // Always ensure the final output is clean, 2-space indented JSON without any ASCII banner borders
        val finalCleanJson = ensureCleanFormattedJsonOutput(current, extractedFields)
        val mergedFields = extractReadableConfigFields(finalCleanJson).let { newFields ->
            val combined = linkedMapOf<String, String>()
            combined.putAll(extractedFields)
            combined.putAll(newFields)
            combined
        }

        val formatSummary = if (steps.isEmpty()) {
            "Formatted JSON Configuration"
        } else {
            "Decoded (${steps.size} layer${if (steps.size > 1) "s" else ""}): ${steps.joinToString(" → ") { it.encodingType }}"
        }

        if (steps.isEmpty()) {
            val bytes = current.toByteArray(StandardCharsets.UTF_8)
            val isReadable = isMostlyPrintableUtf8(bytes)
            if (isReadable) {
                steps.add(
                    DecodeStepTrace(
                        stepIndex = 1,
                        encodingType = "Clean JSON Formatting",
                        summary = "Formatted configuration into clean 2-space indented JSON.",
                        outputPreview = finalCleanJson.take(180)
                    )
                )
            }
            return DecodeOperationResult(
                isSuccessful = isReadable,
                isEncryptedAndNeedsKey = false,
                finalOutput = finalCleanJson,
                formattedInspectorReport = finalCleanJson,
                detectedFormatSummary = formatSummary,
                steps = steps,
                parsedFields = mergedFields
            )
        }

        return DecodeOperationResult(
            isSuccessful = true,
            isEncryptedAndNeedsKey = false,
            finalOutput = finalCleanJson,
            formattedInspectorReport = finalCleanJson,
            detectedFormatSummary = formatSummary,
            steps = steps,
            parsedFields = mergedFields
        )
    }

    private fun decodeEmbeddedLinesIfAny(input: String): String? {
        var changed = false
        val lines = input.lines().map { line ->
            val trimmed = line.trim()
            if (trimmed.contains("=") && !trimmed.startsWith("#")) {
                val key = trimmed.substringBefore("=").trim()
                val rawVal = trimmed.substringAfter("=").trim().removeSurrounding("\"")
                if (isLikelyBase64(rawVal) && rawVal.length >= 16) {
                    try {
                        val dec = decodeBase64Flexible(rawVal)
                        val (unpacked, _) = tryDecompressContainerBytes(dec)
                        if (isMostlyPrintableUtf8(unpacked)) {
                            changed = true
                            "$key = ${String(unpacked, StandardCharsets.UTF_8).trim()}"
                        } else line
                    } catch (_: Exception) {
                        line
                    }
                } else line
            } else line
        }
        return if (changed) lines.joinToString("\n") else null
    }

    fun runAuthorizedPasswordRecovery(
        encryptedBytes: ByteArray,
        candidates: List<String>
    ): PasswordRecoveryReport {
        val startMs = System.currentTimeMillis()
        val distinctCandidates = candidates.map { it.trim() }.filter { it.isNotEmpty() }.distinct()

        if (distinctCandidates.isEmpty()) {
            return PasswordRecoveryReport(
                recoveredPassword = null,
                decryptedPayload = null,
                formattedInspectorReport = null,
                parsedFields = emptyMap(),
                testedCount = 0,
                elapsedTimeMs = 0L,
                algorithmSummary = "PBKDF2-HMAC-SHA256 / AES-256-GCM",
                explanationMessage = "No candidate passwords or hints were provided to test."
            )
        }

        var tested = 0
        for (candidate in distinctCandidates) {
            tested++
            when (val res = unlockContainer(encryptedBytes, candidate)) {
                is UnlockOperationResult.Success -> {
                    val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
                    return PasswordRecoveryReport(
                        recoveredPassword = candidate,
                        decryptedPayload = res.formattedInspectorReport,
                        formattedInspectorReport = res.formattedInspectorReport,
                        parsedFields = res.parsedFields,
                        testedCount = tested,
                        elapsedTimeMs = elapsed,
                        algorithmSummary = res.cipherSuiteUsed,
                        explanationMessage = "Match verified on candidate #$tested in ${elapsed}ms using ${res.cipherSuiteUsed}."
                    )
                }
                is UnlockOperationResult.Failure -> {
                    if (res.isCorruptedFile) {
                        val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
                        return PasswordRecoveryReport(
                            recoveredPassword = null,
                            decryptedPayload = null,
                            formattedInspectorReport = null,
                            parsedFields = emptyMap(),
                            testedCount = tested,
                            elapsedTimeMs = elapsed,
                            algorithmSummary = "Container Integrity Error",
                            explanationMessage = "Recovery halted: ${res.technicalReason}"
                        )
                    }
                }
            }
        }

        val elapsed = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
        return PasswordRecoveryReport(
            recoveredPassword = null,
            decryptedPayload = null,
            formattedInspectorReport = null,
            parsedFields = emptyMap(),
            testedCount = tested,
            elapsedTimeMs = elapsed,
            algorithmSummary = "AES-256-GCM + PBKDF2-HMAC-SHA256",
            explanationMessage = "Tested $tested candidate password(s) in ${elapsed}ms without a match. Strong AES-256-GCM encryption with PBKDF2 key stretching cannot be bypassed mathematically when the password is not in your authorized hint list."
        )
    }

    private fun deriveKeyPbkdf2(password: String, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGO)
        return factory.generateSecret(spec).encoded
    }

    fun gzip(data: ByteArray): ByteArray {
        val bos = ByteArrayOutputStream()
        GZIPOutputStream(bos).use { it.write(data) }
        return bos.toByteArray()
    }

    fun gunzip(compressed: ByteArray): ByteArray {
        val bis = ByteArrayInputStream(compressed)
        GZIPInputStream(bis).use { gis ->
            return gis.readBytes()
        }
    }

    fun isLikelyHex(input: String): Boolean {
        val cleaned = input.replace("\\s+".toRegex(), "")
        if (cleaned.length < 16 || cleaned.length % 2 != 0) return false
        return cleaned.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }

    fun decodeHex(input: String): ByteArray {
        val cleaned = input.replace("\\s+".toRegex(), "")
        val out = ByteArray(cleaned.length / 2)
        for (i in out.indices) {
            val idx = i * 2
            out[i] = cleaned.substring(idx, idx + 2).toInt(16).toByte()
        }
        return out
    }

    fun encodeHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun isLikelyBase64(input: String): Boolean {
        val cleaned = input.replace("\\s+".toRegex(), "")
        if (cleaned.length < 12) return false
        if (cleaned.startsWith("{") || cleaned.contains(" ")) return false
        val base64Regex = Regex("^[A-Za-z0-9+/=_-]+$")
        return base64Regex.matches(cleaned)
    }

    private fun decodeBase64Flexible(input: String): ByteArray {
        var cleaned = input.replace("\\s+".toRegex(), "")
        val flags = if (cleaned.contains("-") || cleaned.contains("_")) {
            Base64.URL_SAFE or Base64.NO_WRAP
        } else {
            Base64.DEFAULT
        }
        // Pad if needed
        val mod = cleaned.length % 4
        if (mod == 2) cleaned += "=="
        else if (mod == 3) cleaned += "="
        return Base64.decode(cleaned, flags)
    }

    fun isMostlyPrintableUtf8(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        val text = String(bytes, StandardCharsets.UTF_8)
        if (text.contains('\uFFFD')) return false
        var printable = 0
        for (ch in text) {
            if (ch == '\n' || ch == '\r' || ch == '\t' || ch.code in 32..126 || ch.code > 160) {
                printable++
            }
        }
        return printable.toDouble() / text.length.toDouble() >= 0.90
    }

    private fun detectEncodingLabel(text: String): String {
        val lower = text.lowercase()
        return when {
            lower.startsWith("vmess://") -> "VMess Base64 URI"
            lower.startsWith("vless://") -> "VLESS RFC-3986 URI"
            lower.startsWith("trojan://") -> "Trojan TLS URI"
            lower.startsWith("ss://") -> "Shadowsocks Base64 URI"
            lower.startsWith("darktunnel://") -> "DarkTunnel Encoded URI"
            lower.startsWith("ssh://") -> "SSH Tunnel URI"
            isLikelyHex(text) -> "Hexadecimal (Base16)"
            else -> "Base64 (RFC-4648)"
        }
    }

    private fun parseStandardVpnUri(uriText: String): Map<String, String> {
        val result = linkedMapOf<String, String>()
        val scheme = uriText.substringBefore("://", "")
        result["Protocol"] = scheme.uppercase()
        val remainder = uriText.substringAfter("://", "")
        val tag = if (remainder.contains("#")) {
            try {
                URLDecoder.decode(remainder.substringAfter("#"), "UTF-8")
            } catch (_: Exception) {
                remainder.substringAfter("#")
            }
        } else ""
        val withoutTag = remainder.substringBefore("#")
        val queryPart = if (withoutTag.contains("?")) withoutTag.substringAfter("?") else ""
        val authorityAndPath = withoutTag.substringBefore("?")
        val userInfo = if (authorityAndPath.contains("@")) authorityAndPath.substringBefore("@") else ""
        val hostPortPath = authorityAndPath.substringAfter("@")
        val hostPort = hostPortPath.substringBefore("/")
        val path = if (hostPortPath.contains("/")) "/" + hostPortPath.substringAfter("/") else "/"

        if (tag.isNotBlank()) result["Profile Name"] = tag
        result["Server Host"] = hostPort.substringBefore(":")
        result["Server Port"] = hostPort.substringAfter(":", "443")
        if (userInfo.isNotBlank()) {
            if (userInfo.contains(":")) {
                result["Username"] = userInfo.substringBefore(":")
                result["Password / Key"] = userInfo.substringAfter(":")
            } else {
                result["Username / UUID"] = userInfo
            }
        }
        result["WebSocket Path"] = path

        if (queryPart.isNotBlank()) {
            queryPart.split("&").forEach { pair ->
                val k = pair.substringBefore("=")
                val v = try {
                    URLDecoder.decode(pair.substringAfter("=", ""), "UTF-8")
                } catch (_: Exception) {
                    pair.substringAfter("=", "")
                }
                if (k.isNotBlank() && v.isNotBlank()) {
                    val prettyKey = when (k.lowercase()) {
                        "sni", "servername" -> "TLS SNI Host"
                        "security" -> "TLS Security"
                        "type", "net" -> "Transport Network"
                        "host" -> "Payload Host"
                        "path" -> "WebSocket Path"
                        else -> k
                    }
                    result[prettyKey] = v
                }
            }
        }
        return result
    }

    /**
     * Extracts all recognizable VPN configuration fields into clean, human-readable labels
     * from both JSON (including DarkTunnel `sshConfig`/`v2rayConfig` schemas) and key=value / INI config files.
     */
    fun extractReadableConfigFields(text: String): Map<String, String> {
        val fields = linkedMapOf<String, String>()
        val trimmed = text.trim()

        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val json = JSONObject(trimmed)

                fun putIfPresent(label: String, vararg keys: String) {
                    for (k in keys) {
                        if (json.has(k)) {
                            val v = json.optString(k, "").trim()
                            if (v.isNotEmpty() && v != "null" && !v.startsWith("{")) {
                                fields[label] = v
                                return
                            }
                        }
                    }
                }

                putIfPresent("Profile Name", "name", "ps", "remarks", "profileName", "Profile Name")
                putIfPresent("Protocol", "tunnelType", "protocolDisplay", "protocol", "type", "net", "Protocol")
                putIfPresent("Server Host / IP", "serverHost", "add", "server", "host", "Server Host")
                putIfPresent("Server Port", "serverPort", "port", "Server Port")
                putIfPresent("Username / UUID", "username", "user", "id", "uuid", "Username", "Username / UUID")
                putIfPresent("Password / Secret", "authSecret", "password", "pass", "Password / Key")
                putIfPresent("TLS / Security", "tls", "security", "TLS Security")
                putIfPresent("TLS SNI Host", "sni", "sniHost", "servername", "serverNameIndicator", "TLS SNI Host")
                putIfPresent("WebSocket Path", "wsPath", "path", "WebSocket Path")
                putIfPresent("HTTP Payload", "httpPayload", "payload", "customPayload")
                putIfPresent("Verification Status", "verificationStatus")
                putIfPresent("Note / Message", "note")

                // DarkTunnel `sshConfig` nested object support
                json.optJSONObject("sshConfig")?.let { sshCfg ->
                    sshCfg.optString("host", "").takeIf { it.isNotBlank() }?.let { fields["Server Host / IP"] = it }
                    if (sshCfg.has("port")) fields["Server Port"] = sshCfg.optInt("port", 443).toString()
                    sshCfg.optString("username", "").takeIf { it.isNotBlank() }?.let { fields["Username / UUID"] = it }
                    sshCfg.optString("password", "").takeIf { it.isNotBlank() }?.let { fields["Password / Secret"] = it }
                    sshCfg.optString("serverNameIndicator", "").takeIf { it.isNotBlank() }?.let { fields["TLS SNI Host"] = it }
                    sshCfg.optString("payload", "").takeIf { it.isNotBlank() }?.let { fields["HTTP Payload"] = it }
                    sshCfg.optJSONObject("proxy")?.let { proxy ->
                        val pType = proxy.optString("type", "")
                        if (pType.isNotBlank()) fields["Proxy Type"] = pType
                        val pHost = proxy.optString("host", "")
                        val pPort = proxy.optInt("port", 0)
                        if (pHost.isNotBlank()) fields["Proxy Endpoint"] = if (pPort > 0) "$pHost:$pPort" else pHost
                    }
                }

                // Nested objects: ssh, tls, websocket, dns
                json.optJSONObject("ssh")?.let { ssh ->
                    ssh.keys().forEach { k ->
                        val v = ssh.optString(k, "")
                        if (v.isNotBlank()) fields["SSH ${k.replaceFirstChar { it.uppercase() }}"] = v
                    }
                }
                json.optJSONObject("tls")?.let { tls ->
                    val enabled = tls.optBoolean("enabled", false)
                    fields["TLS Enabled"] = if (enabled) "Yes (Active)" else "No"
                    val sni = tls.optString("sni", "")
                    if (sni.isNotBlank()) fields["TLS SNI Host"] = sni
                    val alpn = tls.optString("alpn", "")
                    if (alpn.isNotBlank()) fields["TLS ALPN"] = alpn
                }
                json.optJSONObject("websocket")?.let { ws ->
                    val enabled = ws.optBoolean("enabled", false)
                    fields["WebSocket Enabled"] = if (enabled) "Yes (Active)" else "No"
                    val p = ws.optString("path", "")
                    if (p.isNotBlank()) fields["WebSocket Path"] = p
                    val pay = ws.optString("httpPayload", "")
                    if (pay.isNotBlank()) fields["HTTP Payload"] = pay
                }
                json.optJSONObject("dns")?.let { dns ->
                    val d1 = dns.optString("primary", "")
                    val d2 = dns.optString("secondary", "")
                    if (d1.isNotBlank()) fields["DNS Servers"] = "$d1, $d2".trimEnd(',', ' ')
                }

                // Also preserves exact raw keys for backward compatibility in tests (`add`, `port`, etc.)
                if (json.has("add")) fields["add"] = json.optString("add")
            } catch (_: Exception) {
            }
            return fields
        }

        // Parse non-JSON directives (INI, OpenVPN, HTTP Injector / Custom key=value or key: value lines)
        for (line in trimmed.lines()) {
            val cleanLine = line.trim()
            if (cleanLine.isEmpty() || cleanLine.startsWith("#") || cleanLine.startsWith("//") || cleanLine.startsWith(";")) continue
            if (cleanLine.contains("=")) {
                val k = cleanLine.substringBefore("=").trim()
                val v = cleanLine.substringAfter("=").trim().removeSurrounding("\"")
                if (k.isNotEmpty() && v.isNotEmpty()) {
                    fields[k] = v
                }
            } else if (cleanLine.contains(":") && !cleanLine.startsWith("GET ") && !cleanLine.startsWith("POST ")) {
                val k = cleanLine.substringBefore(":").trim()
                val v = cleanLine.substringAfter(":").trim()
                if (k.length in 2..28 && v.isNotEmpty()) {
                    fields[k] = v
                }
            } else if (cleanLine.startsWith("remote ")) {
                val parts = cleanLine.split("\\s+".toRegex())
                if (parts.size >= 2) fields["Server Host / IP"] = parts[1]
                if (parts.size >= 3) fields["Server Port"] = parts[2]
            } else if (cleanLine.startsWith("proto ")) {
                fields["Protocol"] = cleanLine.removePrefix("proto ").trim().uppercase()
            }
        }
        return fields
    }
}
