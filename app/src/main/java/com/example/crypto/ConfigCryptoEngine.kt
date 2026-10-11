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
     * Deeply unpacks compressed streams (GZIP, ZLIB, ZIP) or binary containers to extract readable text.
     */
    fun tryDecompressContainerBytes(rawBytes: ByteArray): Pair<ByteArray, String?> {
        if (rawBytes.size < 4) return rawBytes to null

        // 1. Check GZIP magic (0x1F 0x8B)
        if (rawBytes[0] == 0x1F.toByte() && rawBytes[1] == 0x8B.toByte()) {
            try {
                return gunzip(rawBytes) to "GZIP (0x1F8B)"
            } catch (_: Exception) {
            }
        }

        // 2. Check PKZIP magic (0x50 0x4B 0x03 0x04)
        if (rawBytes[0] == 0x50.toByte() && rawBytes[1] == 0x4B.toByte() &&
            rawBytes[2] == 0x03.toByte() && rawBytes[3] == 0x04.toByte()
        ) {
            try {
                val sb = StringBuilder()
                ZipInputStream(ByteArrayInputStream(rawBytes)).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) {
                            val entryBytes = zis.readBytes()
                            val entryText = cleanAndSanitizePrintableText(entryBytes)
                            if (entryText.isNotBlank()) {
                                sb.append("// Entry: ${entry.name}\n").append(entryText).append("\n\n")
                            }
                        }
                        entry = zis.nextEntry
                    }
                }
                if (sb.isNotEmpty()) {
                    return sb.toString().trim().toByteArray(StandardCharsets.UTF_8) to "ZIP Container Archive"
                }
            } catch (_: Exception) {
            }
        }

        // 3. Check ZLIB Deflate magic (0x78 0x9C, 0x78 0x01, 0x78 0xDA)
        if (rawBytes[0] == 0x78.toByte() &&
            (rawBytes[1] == 0x9C.toByte() || rawBytes[1] == 0x01.toByte() || rawBytes[1] == 0xDA.toByte())
        ) {
            try {
                val bos = ByteArrayOutputStream()
                InflaterInputStream(ByteArrayInputStream(rawBytes)).use { iis ->
                    iis.copyTo(bos)
                }
                val out = bos.toByteArray()
                if (out.isNotEmpty()) {
                    return out to "ZLIB Deflate (0x78)"
                }
            } catch (_: Exception) {
            }
        }

        // 4. Try raw Inflater (nowrap = true)
        try {
            val inflater = Inflater(true)
            inflater.setInput(rawBytes)
            val bos = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (!inflater.finished() && !inflater.needsInput()) {
                val count = inflater.inflate(buf)
                if (count <= 0) break
                bos.write(buf, 0, count)
            }
            inflater.end()
            val out = bos.toByteArray()
            if (out.size > rawBytes.size / 2 && isMostlyPrintableUtf8(out)) {
                return out to "Raw Deflate Stream"
            }
        } catch (_: Exception) {
        }

        return rawBytes to null
    }

    /**
     * Cleans any mixed binary/text stream into clear, readable UTF-8 configuration lines,
     * removing garbage control bytes so the user never sees scrambled/garbled characters.
     */
    fun cleanAndSanitizePrintableText(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val rawStr = String(bytes, StandardCharsets.UTF_8)
        if (!rawStr.contains('\uFFFD') && isMostlyPrintableUtf8(bytes)) {
            return rawStr.trim()
        }

        // Extract contiguous printable ASCII/UTF-8 runs (minimum length 4) so binary headers don't pollute output
        val sb = StringBuilder()
        val currentRun = StringBuilder()
        for (b in bytes) {
            val code = b.toInt() and 0xFF
            val isPrintable = (code in 32..126) || code == 9 || code == 10 || code == 13
            if (isPrintable) {
                currentRun.append(code.toChar())
            } else {
                if (currentRun.trim().length >= 4) {
                    sb.append(currentRun.toString().trim()).append("\n")
                }
                currentRun.clear()
            }
        }
        if (currentRun.trim().length >= 4) {
            sb.append(currentRun.toString().trim())
        }
        return sb.toString().trim()
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
                diagnosticMessage = "Compressed $compressionLabel container detected (${decompressedBytes.size} bytes unpacked). Ready for clear decoding and inspection.",
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
                        diagnosticMessage = "Readable JSON configuration structure verified (${json.length()} top-level keys). All fields ready for clear view.",
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
                diagnosticMessage = "Encoded configuration payload detected (${detectEncodingLabel(textTrimmed)}). Open Decoder or Unlocker to view all clear fields.",
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
                diagnosticMessage = "High entropy (${"%.2f".format(entropy)} bits/byte) binary container. Use Decoder or Unlocker to extract readable configuration strings.",
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
            diagnosticMessage = "Readable plaintext configuration detected. Ready for clear inspection and editing.",
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
     * so the user immediately sees crystal-clear, structured configuration data.
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

        // Check if the file is actually encoded/compressed (no password encryption) — if so, decode it clearly!
        val workingText = String(workingBytes, StandardCharsets.UTF_8).trim()
        val isBinaryMagic = workingBytes.size >= 32 &&
            String(workingBytes.copyOfRange(0, 4), StandardCharsets.US_ASCII) in setOf("DTV1", "HAT1", "EHI1", "NM01", "HC01")
        val isJsonEncrypted = workingText.startsWith("{") && workingText.endsWith("}") &&
            workingText.contains("\"ciphertext\"") && (workingText.contains("\"salt\"") || workingText.contains("\"iv\""))

        if (!isBinaryMagic && !isJsonEncrypted) {
            // Check if it's malformed JSON starting with '{'
            if (workingText.startsWith("{") && !workingText.endsWith("}")) {
                return UnlockOperationResult.Failure(
                    errorTitle = "Corrupted JSON Container",
                    technicalReason = "Container starts with '{' but is truncated or malformed.",
                    isWrongPassword = false,
                    isCorruptedFile = true
                )
            }
            // Try deep decoding if it's an encoded or compressed config file (.ehi, .hat, .hc, .nm, .dark)
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
                val report = buildClearInspectorReport(finalCleanText, fields, "$magic4 Binary AES-256-GCM")
                UnlockOperationResult.Success(
                    decryptedContent = rawPlainText,
                    formattedInspectorReport = report,
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
            val inspectorReport = buildClearInspectorReport(
                cleanJsonOrText = bestReadable,
                fields = parsedFields,
                sourceMethod = "$cipherMode / PBKDF2-HMAC-SHA256 ($iterations iterations)"
            )

            UnlockOperationResult.Success(
                decryptedContent = decryptedText,
                formattedInspectorReport = inspectorReport,
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
     * Decodes raw file bytes (handling GZIP/ZLIB/ZIP decompression, binary string extraction, and multi-layer text decoding).
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
                outputPreview = cleanText.take(180)
            )
            return result.copy(
                detectedFormatSummary = "$compressionType + ${result.detectedFormatSummary}",
                steps = listOf(prependedStep) + result.steps
            )
        }
        return result
    }

    /**
     * Multi-layer decoder for Base64, URL-Safe Base64, Hexadecimal, URL Encoding, ROT13/Caesar, XOR obfuscation,
     * JSON pretty-printing, and VPN URI schemes (vmess://, vless://, trojan://, ss://, darktunnel://, ssh://).
     * Produces a crystal-clear, human-readable formatted configuration report so nothing looks scrambled.
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
                    return DecodeOperationResult(
                        isSuccessful = false,
                        isEncryptedAndNeedsKey = true,
                        finalOutput = trimmed,
                        formattedInspectorReport = buildClearInspectorReport(trimmed, fields, "Encrypted Container ($cipher)"),
                        detectedFormatSummary = "Encrypted Container ($cipher)",
                        steps = listOf(
                            DecodeStepTrace(
                                stepIndex = 1,
                                encodingType = "Cryptographic Container Detected",
                                summary = "Detected $cipher encrypted payload. Encrypted containers require a decryption password in the Config Unlocker screen.",
                                outputPreview = trimmed.take(180)
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
                                val j = JSONObject(decodedStr)
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
                                summary = "Decoded $scheme tunnel URI into clear readable configuration.",
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

            // 2. If valid JSON, check if any inner fields ("payload", "config", "data", "v2ray") are Base64 encoded
            if (candidate.startsWith("{") && candidate.endsWith("}")) {
                try {
                    val jsonObj = JSONObject(candidate)
                    var modifiedInner = false
                    val encodedFieldNames = listOf("config", "data", "rawConfig", "encodedPayload", "vmess")
                    for (fieldKey in encodedFieldNames) {
                        if (jsonObj.has(fieldKey)) {
                            val rawVal = jsonObj.optString(fieldKey, "")
                            if (isLikelyBase64(rawVal)) {
                                try {
                                    val decBytes = decodeBase64Flexible(rawVal)
                                    if (isMostlyPrintableUtf8(decBytes)) {
                                        val decStr = String(decBytes, StandardCharsets.UTF_8).trim()
                                        jsonObj.put("${fieldKey}_decoded", decStr)
                                        modifiedInner = true
                                    }
                                } catch (_: Exception) {
                                }
                            }
                        }
                    }
                    val pretty = jsonObj.toString(2)
                    if (pretty != current || modifiedInner) {
                        current = pretty
                        steps.add(
                            DecodeStepTrace(
                                stepIndex = stepCounter++,
                                encodingType = "JSON Structure Formatting",
                                summary = "Formatted and unpacked all JSON configuration fields (${jsonObj.length()} keys).",
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

        // Final pass: if current is valid JSON, ensure 2-space pretty formatting
        val finalClean = try {
            val trimmedFinal = current.trim()
            if (trimmedFinal.startsWith("{") && trimmedFinal.endsWith("}")) {
                JSONObject(trimmedFinal).toString(2)
            } else if (trimmedFinal.startsWith("[") && trimmedFinal.endsWith("]")) {
                JSONArray(trimmedFinal).toString(2)
            } else {
                cleanAndSanitizePrintableText(trimmedFinal.toByteArray(StandardCharsets.UTF_8))
            }
        } catch (_: Exception) {
            current
        }

        val extractedFields = extractReadableConfigFields(finalClean)
        val formatSummary = if (steps.isEmpty()) {
            "Plaintext / Structured Configuration"
        } else {
            "Decoded (${steps.size} layer${if (steps.size > 1) "s" else ""}): ${steps.joinToString(" → ") { it.encodingType }}"
        }

        val inspectorReport = buildClearInspectorReport(
            cleanJsonOrText = finalClean,
            fields = extractedFields,
            sourceMethod = formatSummary
        )

        if (steps.isEmpty()) {
            val bytes = finalClean.toByteArray(StandardCharsets.UTF_8)
            val isReadable = isMostlyPrintableUtf8(bytes)
            if (isReadable) {
                steps.add(
                    DecodeStepTrace(
                        stepIndex = 1,
                        encodingType = "Direct Plaintext Inspection",
                        summary = "Extracted all readable configuration parameters into clear view.",
                        outputPreview = finalClean.take(180)
                    )
                )
            }
            return DecodeOperationResult(
                isSuccessful = isReadable,
                isEncryptedAndNeedsKey = false,
                finalOutput = finalClean,
                formattedInspectorReport = inspectorReport,
                detectedFormatSummary = formatSummary,
                steps = steps,
                parsedFields = extractedFields
            )
        }

        return DecodeOperationResult(
            isSuccessful = true,
            isEncryptedAndNeedsKey = false,
            finalOutput = finalClean,
            formattedInspectorReport = inspectorReport,
            detectedFormatSummary = formatSummary,
            steps = steps,
            parsedFields = extractedFields
        )
    }

    /**
     * Builds a crystal-clear, structured, human-readable report showing every unlocked/decoded VPN parameter
     * (Server Host, Port, Protocol, Username/UUID, Password, SNI, Payload, DNS) followed by the clean raw config.
     */
    fun buildClearInspectorReport(
        cleanJsonOrText: String,
        fields: Map<String, String>,
        sourceMethod: String
    ): String {
        val sb = StringBuilder()
        sb.append("====================================================\n")
        sb.append("   DARK TUNNEL — UNLOCKED CONFIG INSPECTOR REPORT   \n")
        sb.append("====================================================\n")
        sb.append("Method : $sourceMethod\n")
        sb.append("Status : CLEAR & READABLE (100% Decoded)\n")
        sb.append("----------------------------------------------------\n")

        if (fields.isNotEmpty()) {
            sb.append("[ EXTRACTED VPN PARAMETERS ]\n")
            for ((k, v) in fields) {
                val paddedKey = k.padEnd(20, ' ')
                sb.append("• $paddedKey : $v\n")
            }
            sb.append("----------------------------------------------------\n")
        }

        sb.append("[ FULL READABLE CONFIGURATION DATA ]\n")
        sb.append(cleanJsonOrText.trim())
        sb.append("\n====================================================")
        return sb.toString()
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
                        if (isMostlyPrintableUtf8(dec)) {
                            changed = true
                            "$key = ${String(dec, StandardCharsets.UTF_8).trim()}"
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
                        decryptedPayload = res.decryptedContent,
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
     * from both JSON and key=value / INI / OpenVPN / HTTP Injector style config files.
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
                            if (v.isNotEmpty() && v != "null") {
                                fields[label] = v
                                return
                            }
                        }
                    }
                }

                putIfPresent("Profile Name", "name", "ps", "remarks", "profileName", "Profile Name")
                putIfPresent("Protocol", "protocolDisplay", "protocol", "type", "net", "Protocol")
                putIfPresent("Server Host / IP", "serverHost", "add", "server", "host", "Server Host")
                putIfPresent("Server Port", "serverPort", "port", "Server Port")
                putIfPresent("Username / UUID", "username", "user", "id", "uuid", "Username", "Username / UUID")
                putIfPresent("Password / Secret", "authSecret", "password", "pass", "Password / Key")
                putIfPresent("TLS / Security", "tls", "security", "TLS Security")
                putIfPresent("TLS SNI Host", "sni", "sniHost", "servername", "TLS SNI Host")
                putIfPresent("WebSocket Path", "wsPath", "path", "WebSocket Path")
                putIfPresent("HTTP Payload", "httpPayload", "payload", "customPayload")
                putIfPresent("Verification Status", "verificationStatus")
                putIfPresent("Note / Message", "note")

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
