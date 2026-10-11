package com.example.crypto

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.InflaterInputStream
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
    val detectedFormatSummary: String,
    val steps: List<DecodeStepTrace>,
    val parsedFields: Map<String, String>
)

data class PasswordRecoveryReport(
    val recoveredPassword: String?,
    val decryptedPayload: String?,
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

        // Check GZIP magic bytes (0x1F 0x8B)
        if (rawBytes.size >= 2 && rawBytes[0] == 0x1F.toByte() && rawBytes[1] == 0x8B.toByte()) {
            return try {
                val decompressed = gunzip(rawBytes)
                val innerText = String(decompressed, StandardCharsets.UTF_8)
                FileAnalysisReport(
                    fileName = fileName,
                    extension = ext,
                    sizeBytes = rawBytes.size.toLong(),
                    sha256Hex = sha256,
                    shannonEntropy = entropy,
                    formatState = ConfigFormatState.COMPRESSED_ARCHIVE,
                    detectedContainerSignature = "GZIP_DEFLATE (0x1F8B)",
                    diagnosticMessage = "Compressed GZIP stream detected (${decompressed.size} bytes uncompressed). Ready for lossless decompression or inner container inspection.",
                    canDirectDecode = true,
                    requiresPasswordKey = innerText.contains("\"cipher\"") && innerText.contains("\"ciphertext\"")
                )
            } catch (e: Exception) {
                FileAnalysisReport(
                    fileName = fileName,
                    extension = ext,
                    sizeBytes = rawBytes.size.toLong(),
                    sha256Hex = sha256,
                    shannonEntropy = entropy,
                    formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                    detectedContainerSignature = "TRUNCATED_GZIP",
                    diagnosticMessage = "GZIP header found (0x1F8B), but deflate stream is truncated or corrupted: ${e.message}",
                    canDirectDecode = false,
                    requiresPasswordKey = false
                )
            }
        }

        val textTrimmed = String(rawBytes, StandardCharsets.UTF_8).trim()

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
                    diagnosticMessage = "Authenticated $magic4 binary encrypted container detected (PBKDF2-HMAC-SHA256 + AES-256-GCM). Requires valid decryption password.",
                    canDirectDecode = false,
                    requiresPasswordKey = true
                )
            }
        }

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
                        diagnosticMessage = "Encrypted VPN container envelope detected. Protected with $cipherName and $kdfName. Password or key is required to unlock.",
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
                        diagnosticMessage = "Readable JSON configuration structure verified (${json.length()} top-level keys). Ready for inspection, editing, or VPN connection.",
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
                diagnosticMessage = "Encoded configuration payload detected (${detectEncodingLabel(textTrimmed)}). Not encrypted—can be decoded directly in the Config Decoder.",
                canDirectDecode = true,
                requiresPasswordKey = false
            )
        }

        // Check if high-entropy binary (likely encrypted or corrupted)
        if (entropy > 7.1 || !isMostlyPrintableUtf8(rawBytes)) {
            return FileAnalysisReport(
                fileName = fileName,
                extension = ext,
                sizeBytes = rawBytes.size.toLong(),
                sha256Hex = sha256,
                shannonEntropy = entropy,
                formatState = ConfigFormatState.CORRUPTED_OR_INVALID,
                detectedContainerSignature = "UNRECOGNIZED_HIGH_ENTROPY_BINARY",
                diagnosticMessage = "High entropy (${"%.2f".format(entropy)} bits/byte) or non-printable binary without a documented header. File is either corrupted or uses an undocumented proprietary cipher.",
                canDirectDecode = false,
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
            diagnosticMessage = "Readable plaintext configuration detected. Ready for editing or decoding.",
            canDirectDecode = true,
            requiresPasswordKey = false
        )
    }

    /**
     * Creates a real AES-256-GCM + PBKDF2-HMAC-SHA256 encrypted container (JSON envelope or DTV1 binary)
     * so users can lock configs, test unlocking with real passwords, and test password recovery.
     */
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
     * Real cryptographic unlocking of compatible containers.
     * NEVER fakes success. Only returns Success when AES-GCM authentication tag or SHA-256 integrity
     * and readable structure verification succeed.
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
        if (passwordOrKey.isEmpty()) {
            return UnlockOperationResult.Failure(
                errorTitle = "Password / Decryption Key Required",
                technicalReason = "No decryption password or key was supplied. Enter the valid key to derive the AES-256 decryption key.",
                isWrongPassword = true,
                isCorruptedFile = false
            )
        }

        // First decompress if GZIP wrapped
        val workingBytes = if (rawBytes.size >= 2 && rawBytes[0] == 0x1F.toByte() && rawBytes[1] == 0x8B.toByte()) {
            try {
                gunzip(rawBytes)
            } catch (e: Exception) {
                return UnlockOperationResult.Failure(
                    errorTitle = "Corrupted GZIP Container",
                    technicalReason = "Failed to decompress outer GZIP stream: ${e.message}",
                    isWrongPassword = false,
                    isCorruptedFile = true
                )
            }
        } else {
            rawBytes
        }

        // Check Binary Header DTV1 / HAT1 / EHI1 / NM01 / HC01
        if (workingBytes.size >= 32) {
            val magic4 = String(workingBytes.copyOfRange(0, 4), StandardCharsets.US_ASCII)
            if (magic4 in setOf("DTV1", "HAT1", "EHI1", "NM01", "HC01")) {
                return try {
                    val salt = workingBytes.copyOfRange(4, 20)
                    val iv = workingBytes.copyOfRange(20, 32)
                    val ciphertext = workingBytes.copyOfRange(32, workingBytes.size)
                    val keyBytes = deriveKeyPbkdf2(passwordOrKey, salt, DEFAULT_ITERATIONS)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
                    val plainBytes = cipher.doFinal(ciphertext)
                    val plainText = String(plainBytes, StandardCharsets.UTF_8)
                    UnlockOperationResult.Success(
                        decryptedContent = plainText,
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
        }

        val text = String(workingBytes, StandardCharsets.UTF_8).trim()
        if (!text.startsWith("{") || !text.endsWith("}")) {
            return UnlockOperationResult.Failure(
                errorTitle = "Unsupported or Corrupted Container Format",
                technicalReason = "Input does not match a documented encrypted JSON envelope or DTV1/HAT1/EHI1/NM01/HC01 binary header.",
                isWrongPassword = false,
                isCorruptedFile = true
            )
        }

        val json = try {
            JSONObject(text)
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
                technicalReason = "JSON file does not contain 'salt', 'iv', and 'ciphertext' fields. If this file is already plaintext or encoded, open it in the Decoder or Editor.",
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

            UnlockOperationResult.Success(
                decryptedContent = decryptedText,
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
     * Multi-layer decoder for Base64, URL-Safe Base64, Hexadecimal, URL Encoding, and VPN URI schemes.
     * Explicitly distinguishes encoding from encryption and refuses to claim encrypted containers can be decoded without a key.
     */
    fun decodePayload(rawInput: String): DecodeOperationResult {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            return DecodeOperationResult(
                isSuccessful = false,
                isEncryptedAndNeedsKey = false,
                finalOutput = "",
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
                    return DecodeOperationResult(
                        isSuccessful = false,
                        isEncryptedAndNeedsKey = true,
                        finalOutput = trimmed,
                        detectedFormatSummary = "Encrypted Container ($cipher)",
                        steps = listOf(
                            DecodeStepTrace(
                                stepIndex = 1,
                                encodingType = "Cryptographic Inspection",
                                summary = "Detected $cipher encrypted payload. Encoding != Encryption: encrypted payloads cannot be decoded without their cryptographic key. Use the Config Unlocker screen with the valid password.",
                                outputPreview = trimmed.take(180)
                            )
                        ),
                        parsedFields = mapOf(
                            "Status" to "ENCRYPTED (Requires Key)",
                            "Cipher" to cipher,
                            "KDF" to json.optString("kdf", "PBKDF2-HMAC-SHA256")
                        )
                    )
                }
            } catch (_: Exception) {
            }
        }

        val steps = mutableListOf<DecodeStepTrace>()
        var current = trimmed
        var stepCounter = 1

        // Handle URI schemes first: vmess://, vless://, ss://, trojan://, darktunnel://
        val lower = current.lowercase()
        if (lower.startsWith("vmess://") || lower.startsWith("darktunnel://") || lower.startsWith("ss://")) {
            val scheme = current.substringBefore("://") + "://"
            val body = current.substringAfter("://").substringBefore("#")
            val fragment = if (current.contains("#")) URLDecoder.decode(current.substringAfter("#"), "UTF-8") else ""
            try {
                val decodedBytes = decodeBase64Flexible(body)
                val decodedStr = String(decodedBytes, StandardCharsets.UTF_8)
                if (isMostlyPrintableUtf8(decodedBytes)) {
                    current = if (fragment.isNotBlank() && !decodedStr.contains(fragment)) {
                        "$decodedStr\n# Tag: $fragment"
                    } else {
                        decodedStr
                    }
                    steps.add(
                        DecodeStepTrace(
                            stepIndex = stepCounter++,
                            encodingType = "$scheme URI + Base64 Decode",
                            summary = "Extracted and Base64-decoded $scheme tunnel URI payload (${decodedBytes.size} bytes).",
                            outputPreview = current.take(180)
                        )
                    )
                }
            } catch (_: Exception) {
            }
        } else if (lower.startsWith("vless://") || lower.startsWith("trojan://")) {
            val parsed = parseStandardVpnUri(current)
            val prettyJson = JSONObject(parsed).toString(2)
            steps.add(
                DecodeStepTrace(
                    stepIndex = stepCounter++,
                    encodingType = "URI Component Dissection",
                    summary = "Parsed RFC-3986 tunnel URI parameters into structured JSON.",
                    outputPreview = prettyJson.take(180)
                )
            )
            return DecodeOperationResult(
                isSuccessful = true,
                isEncryptedAndNeedsKey = false,
                finalOutput = prettyJson,
                detectedFormatSummary = "${current.substringBefore("://").uppercase()} Tunnel URI",
                steps = steps,
                parsedFields = parsed
            )
        }

        // Iterative decoding loop (up to 4 layers of Hex, URL-Encoding, or Base64)
        varprog@ for (depth in 0 until 4) {
            val candidate = current.trim()
            if (candidate.startsWith("{") && candidate.endsWith("}")) {
                // Pretty-print JSON if valid
                try {
                    val jsonObj = JSONObject(candidate)
                    val pretty = jsonObj.toString(2)
                    if (pretty != current) {
                        current = pretty
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "JSON Pretty-Format",
                                summary = "Validated and formatted readable JSON structure (${jsonObj.length()} root fields).",
                                outputPreview = current.take(180)
                            )
                        )
                    }
                    break@varprog
                } catch (_: Exception) {
                }
            }

            // Try Hexadecimal decode
            if (isLikelyHex(candidate)) {
                try {
                    val hexBytes = decodeHex(candidate)
                    if (isMostlyPrintableUtf8(hexBytes)) {
                        current = String(hexBytes, StandardCharsets.UTF_8)
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "Hexadecimal (Base16)",
                                summary = "Decoded hexadecimal byte string (${hexBytes.size} bytes).",
                                outputPreview = current.take(180)
                            )
                        )
                        continue@varprog
                    }
                } catch (_: Exception) {
                }
            }

            // Try URL percent-decoding
            if (candidate.contains("%22") || candidate.contains("%7B") || candidate.contains("%3A") || candidate.contains("%2F")) {
                try {
                    val urlDecoded = URLDecoder.decode(candidate, "UTF-8")
                    if (urlDecoded != candidate) {
                        current = urlDecoded
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "URL Percent-Encoding",
                                summary = "Unescaped RFC-3986 percent-encoded characters.",
                                outputPreview = current.take(180)
                            )
                        )
                        continue@varprog
                    }
                } catch (_: Exception) {
                }
            }

            // Try Base64 decode
            if (isLikelyBase64(candidate)) {
                try {
                    val b64Bytes = decodeBase64Flexible(candidate)
                    if (b64Bytes.isNotEmpty() && isMostlyPrintableUtf8(b64Bytes)) {
                        val b64Text = String(b64Bytes, StandardCharsets.UTF_8)
                        if (b64Text != candidate) {
                            current = b64Text
                            steps.add(
                                DecodeStepTrace(
                                    stepIndex = stepCounter++,
                                    encodingType = "Base64 (RFC-4648)",
                                    summary = "Decoded Base64 stream into ${b64Bytes.size} UTF-8 bytes.",
                                    outputPreview = current.take(180)
                                )
                            )
                            continue@varprog
                        }
                    }
                } catch (_: Exception) {
                }
            }

            break@varprog
        }

        val extractedFields = extractReadableConfigFields(current)

        if (steps.isEmpty()) {
            // Check if already readable text
            val bytes = current.toByteArray(StandardCharsets.UTF_8)
            val isReadable = isMostlyPrintableUtf8(bytes)
            if (isReadable) {
                steps.add(
                    DecodeStepTrace(
                        stepIndex = 1,
                        encodingType = "Direct Plaintext Inspection",
                        summary = "Input is already unencoded readable UTF-8 text.",
                        outputPreview = current.take(180)
                    )
                )
            }
            return DecodeOperationResult(
                isSuccessful = isReadable,
                isEncryptedAndNeedsKey = false,
                finalOutput = current,
                detectedFormatSummary = if (isReadable) "Plaintext / Structured Config" else "Unrecognized Binary or Invalid Encoding",
                steps = steps,
                parsedFields = extractedFields
            )
        }

        return DecodeOperationResult(
            isSuccessful = true,
            isEncryptedAndNeedsKey = false,
            finalOutput = current,
            detectedFormatSummary = "Decoded via ${steps.size} step(s): ${steps.joinToString(" → ") { it.encodingType }}",
            steps = steps,
            parsedFields = extractedFields
        )
    }

    /**
     * Authorized Password Recovery audit: tests user-supplied candidate password, saved password hints,
     * and authorized custom wordlist entries against an encrypted container.
     */
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
                        decryptedPayload = res.decryptedContent,
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
        val cleaned = input.replace("\\s+".toRegex(), "")
        val flags = if (cleaned.contains("-") || cleaned.contains("_")) {
            Base64.URL_SAFE
        } else {
            Base64.DEFAULT
        }
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
            isLikelyHex(text) -> "Hexadecimal (Base16)"
            else -> "Base64 (RFC-4648)"
        }
    }

    private fun parseStandardVpnUri(uriText: String): Map<String, String> {
        val result = linkedMapOf<String, String>()
        val scheme = uriText.substringBefore("://", "")
        result["protocol"] = scheme.lowercase()
        val remainder = uriText.substringAfter("://", "")
        val tag = if (remainder.contains("#")) URLDecoder.decode(remainder.substringAfter("#"), "UTF-8") else ""
        val withoutTag = remainder.substringBefore("#")
        val queryPart = if (withoutTag.contains("?")) withoutTag.substringAfter("?") else ""
        val authorityAndPath = withoutTag.substringBefore("?")
        val userInfo = if (authorityAndPath.contains("@")) authorityAndPath.substringBefore("@") else ""
        val hostPortPath = authorityAndPath.substringAfter("@")
        val hostPort = hostPortPath.substringBefore("/")
        val path = if (hostPortPath.contains("/")) "/" + hostPortPath.substringAfter("/") else "/"

        result["username_or_uuid"] = userInfo
        result["server"] = hostPort.substringBefore(":")
        result["port"] = hostPort.substringAfter(":", "443")
        result["path"] = path
        if (tag.isNotBlank()) result["remarks"] = tag

        if (queryPart.isNotBlank()) {
            queryPart.split("&").forEach { pair ->
                val k = pair.substringBefore("=")
                val v = URLDecoder.decode(pair.substringAfter("=", ""), "UTF-8")
                if (k.isNotBlank()) result[k] = v
            }
        }
        return result
    }

    fun extractReadableConfigFields(text: String): Map<String, String> {
        val fields = linkedMapOf<String, String>()
        val trimmed = text.trim()
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            try {
                val json = JSONObject(trimmed)
                val keysToCheck = listOf(
                    "protocol", "type", "server", "add", "host", "serverHost",
                    "port", "serverPort", "username", "user", "id", "uuid",
                    "sni", "sniHost", "servername", "wsPath", "path", "payload",
                    "tls", "security", "network", "net", "remarks", "ps", "name"
                )
                for (key in keysToCheck) {
                    if (json.has(key)) {
                        val v = json.optString(key, "")
                        if (v.isNotBlank()) fields[key] = v
                    }
                }
                if (json.has("ssh") && json.optJSONObject("ssh") != null) {
                    val ssh = json.getJSONObject("ssh")
                    ssh.keys().forEach { k ->
                        fields["ssh.$k"] = ssh.optString(k)
                    }
                }
                if (json.has("tls") && json.optJSONObject("tls") != null) {
                    val tls = json.getJSONObject("tls")
                    tls.keys().forEach { k ->
                        fields["tls.$k"] = tls.optString(k)
                    }
                }
                if (json.has("websocket") && json.optJSONObject("websocket") != null) {
                    val ws = json.getJSONObject("websocket")
                    ws.keys().forEach { k ->
                        fields["ws.$k"] = ws.optString(k)
                    }
                }
            } catch (_: Exception) {
            }
        }
        return fields
    }
}
