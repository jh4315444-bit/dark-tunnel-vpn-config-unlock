package com.example

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import com.example.crypto.ConfigCryptoEngine
import com.example.crypto.ConfigFormatState
import com.example.crypto.ConfigGeneratorEngine
import com.example.crypto.GeneratorInput
import com.example.crypto.TunnelProtocol
import com.example.crypto.UnlockOperationResult
import com.example.vpn.EndpointVerifier
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @Test
    fun `test 1 - verify app name resource and file analysis validation`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("Dark Tunnel Unlocker", context.getString(R.string.app_name))

        // Verify encrypted .dark container detection
        val encryptedSample = ConfigGeneratorEngine.buildAuthorizedSampleEncryptedDarkFile("DarkTunnel#2026")
        val report = ConfigCryptoEngine.analyzeConfigBytes("sample.dark", encryptedSample)
        assertEquals("dark", report.extension)
        assertEquals(ConfigFormatState.ENCRYPTED_CONTAINER, report.formatState)
        assertTrue(report.requiresPasswordKey)
        assertFalse(report.canDirectDecode)
        assertTrue(report.shannonEntropy > 3.5)
    }

    @Test
    fun `test 2 - verify multi-layer decoding with Base64, Hex, and VMess URI`() {
        // Test VMess Base64 URI
        val vmessUri = ConfigGeneratorEngine.buildAuthorizedSampleEncodedPayload()
        val decodeRes = ConfigCryptoEngine.decodePayload(vmessUri)
        assertTrue(decodeRes.isSuccessful)
        assertFalse(decodeRes.isEncryptedAndNeedsKey)
        assertTrue(decodeRes.finalOutput.contains("Diagnostic-WS-TLS-Profile"))
        assertEquals("example.com", decodeRes.parsedFields["add"])

        // Test Hexadecimal encoding of JSON
        val rawJson = """{"protocol":"SSH_DIRECT","serverHost":"192.0.2.10","serverPort":22}"""
        val hexEncoded = ConfigCryptoEngine.encodeHex(rawJson.toByteArray(StandardCharsets.UTF_8))
        val hexDecodeRes = ConfigCryptoEngine.decodePayload(hexEncoded)
        assertTrue(hexDecodeRes.isSuccessful)
        assertTrue(hexDecodeRes.finalOutput.contains("192.0.2.10"))

        // Verify that encrypted containers are NOT falsely treated as simple encoding
        val encryptedBytes = ConfigGeneratorEngine.buildAuthorizedSampleEncryptedDarkFile("SecretKey123")
        val encryptedStr = String(encryptedBytes, StandardCharsets.UTF_8)
        val encryptedDecodeAttempt = ConfigCryptoEngine.decodePayload(encryptedStr)
        assertFalse(encryptedDecodeAttempt.isSuccessful)
        assertTrue(encryptedDecodeAttempt.isEncryptedAndNeedsKey)
    }

    @Test
    fun `test 3 & 4 - verify unlocking with correct password, wrong password, and corrupted file`() {
        val secretPlaintext = """{"name":"Production-Tunnel","serverHost":"vpn.example.org","serverPort":443}"""
        val correctPassword = "CorrectHorseBatteryStaple!99"
        val lockedBytes = ConfigCryptoEngine.createEncryptedContainer(
            plaintextConfig = secretPlaintext,
            password = correctPassword,
            formatExtension = "dark",
            cipherMode = "AES-256-GCM"
        )

        // 1. Correct password must succeed and match exact plaintext
        val unlockSuccess = ConfigCryptoEngine.unlockContainer(lockedBytes, correctPassword)
        assertTrue(unlockSuccess is UnlockOperationResult.Success)
        val successData = unlockSuccess as UnlockOperationResult.Success
        assertEquals(secretPlaintext, successData.decryptedContent)
        assertTrue(successData.integrityVerified)

        // 2. Wrong password must fail with authentication failure (never fake success)
        val unlockWrongPass = ConfigCryptoEngine.unlockContainer(lockedBytes, "WrongPassword123")
        assertTrue(unlockWrongPass is UnlockOperationResult.Failure)
        val wrongPassFailure = unlockWrongPass as UnlockOperationResult.Failure
        assertTrue(wrongPassFailure.isWrongPassword)
        assertFalse(wrongPassFailure.isCorruptedFile)

        // 3. Corrupted file must fail with corruption flag
        val corruptedBytes = "{ \"magic\": \"BROKEN_JSON".toByteArray(StandardCharsets.UTF_8)
        val unlockCorrupted = ConfigCryptoEngine.unlockContainer(corruptedBytes, correctPassword)
        assertTrue(unlockCorrupted is UnlockOperationResult.Failure)
        val corruptedFailure = unlockCorrupted as UnlockOperationResult.Failure
        assertTrue(corruptedFailure.isCorruptedFile)
    }

    @Test
    fun `test 4b - verify authorized password recovery audit`() {
        val lockedBytes = ConfigGeneratorEngine.buildAuthorizedSampleEncryptedDarkFile("AuthorizedKey#77")
        val candidates = listOf("wrong1", "wrong2", "AuthorizedKey#77", "wrong3")
        val report = ConfigCryptoEngine.runAuthorizedPasswordRecovery(lockedBytes, candidates)
        assertEquals("AuthorizedKey#77", report.recoveredPassword)
        assertNotNull(report.decryptedPayload)
        assertEquals(3, report.testedCount)

        // Verify failure when password is not in authorized list
        val failedReport = ConfigCryptoEngine.runAuthorizedPasswordRecovery(lockedBytes, listOf("not_it_1", "not_it_2"))
        assertNull(failedReport.recoveredPassword)
        assertEquals(2, failedReport.testedCount)
    }

    @Test
    fun `test 5 - verify configuration generation and input validation`() {
        val invalidInput = GeneratorInput(
            profileName = "",
            protocol = TunnelProtocol.SSH_WS_TLS,
            serverHost = "invalid host spaces",
            serverPortText = "99999",
            username = "",
            passwordOrUuid = "",
            sniHost = "",
            wsPath = "missing_slash",
            customHttpPayload = ""
        )
        val invalidCheck = ConfigGeneratorEngine.validateInput(invalidInput)
        assertFalse(invalidCheck.isValid)
        assertTrue(invalidCheck.errors.size >= 4)

        val validInput = GeneratorInput(
            profileName = "Verified-Edge-Node",
            protocol = TunnelProtocol.SSH_WS_TLS,
            serverHost = "edge.example.com",
            serverPortText = "443",
            username = "tunnel_operator",
            passwordOrUuid = "sec_token",
            sniHost = "cdn.example.com",
            wsPath = "/ws-stream",
            customHttpPayload = "",
            lockWithPassword = "ContainerLockPassword"
        )
        val validCheck = ConfigGeneratorEngine.validateInput(validInput)
        assertTrue(validCheck.isValid)

        val generated = ConfigGeneratorEngine.generateConfig(validInput, isVerifiedReachable = false)
        assertTrue(generated.readableJson.contains("UNTESTED_GENERATED_TEMPLATE"))
        assertTrue(generated.darkTunnelUri.startsWith("darktunnel://"))
        assertNotNull(generated.encryptedDarkBytes)
    }

    @Test
    fun `test 6 - verify real TCP socket endpoint verifier against local authorized test socket`() = runBlocking {
        val serverSocket = ServerSocket(0)
        val assignedPort = serverSocket.localPort
        val serverThread = thread(start = true) {
            try {
                val client = serverSocket.accept()
                client.getOutputStream().write("SSH-2.0-OpenSSH_AuthorizedTest\r\n".toByteArray())
                client.close()
            } catch (_: Exception) {
            } finally {
                serverSocket.close()
            }
        }

        val checkResult = EndpointVerifier.verifyServerHandshake(
            host = "localhost",
            port = assignedPort,
            useTls = false,
            sniHost = "",
            wsPath = "/ws"
        )
        serverThread.join(2000)
        assertTrue(checkResult.isReachable)
        assertTrue(checkResult.latencyMs >= 1L)
    }
}
