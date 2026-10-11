package com.example.viewmodel

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.crypto.ConfigCryptoEngine
import com.example.crypto.ConfigFormatState
import com.example.crypto.ConfigGeneratorEngine
import com.example.crypto.DecodeOperationResult
import com.example.crypto.FileAnalysisReport
import com.example.crypto.GeneratedConfigBundle
import com.example.crypto.GeneratorInput
import com.example.crypto.PasswordRecoveryReport
import com.example.crypto.TunnelProtocol
import com.example.crypto.UnlockOperationResult
import com.example.data.DarkTunnelDatabase
import com.example.data.DarkTunnelRepository
import com.example.data.ImportedConfigEntity
import com.example.data.OperationHistoryEntity
import com.example.data.PasswordHintEntity
import com.example.data.SavedTemplateEntity
import com.example.data.SettingsPreferences
import com.example.data.WorkbenchSettings
import com.example.vpn.DarkTunnelVpnService
import com.example.vpn.EndpointVerifier
import com.example.vpn.HandshakeCheckResult
import com.example.vpn.VpnConnectionParams
import com.example.vpn.VpnStateBus
import com.example.vpn.VpnTelemetryState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets

enum class WorkbenchDestination(val title: String) {
    DASHBOARD("Dashboard"),
    UNLOCKER("Unlocker"),
    DECODER("Decoder"),
    PASSWORD_RECOVERY("Password Recovery"),
    GENERATOR("Generator"),
    EDITOR("Editor"),
    VPN_CONNECTION("VPN Connection"),
    HISTORY("History"),
    SETTINGS("Settings")
}

data class ActiveFileBuffer(
    val fileName: String,
    val rawBytes: ByteArray,
    val backupFilePath: String,
    val analysisReport: FileAnalysisReport
)

class DarkTunnelViewModel(application: Application) : AndroidViewModel(application) {

    private val database = DarkTunnelDatabase.getDatabase(application)
    private val repository = DarkTunnelRepository(database.dao())
    private val settingsPrefs = SettingsPreferences(application)

    private val _currentDestination = MutableStateFlow(WorkbenchDestination.DASHBOARD)
    val currentDestination: StateFlow<WorkbenchDestination> = _currentDestination.asStateFlow()

    val settingsState: StateFlow<WorkbenchSettings> = settingsPrefs.settingsFlow.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = WorkbenchSettings()
    )

    val importedConfigs: StateFlow<List<ImportedConfigEntity>> = repository.importedConfigs.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    val operationHistory: StateFlow<List<OperationHistoryEntity>> = repository.operationHistory.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    val passwordHints: StateFlow<List<PasswordHintEntity>> = repository.passwordHints.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    val savedTemplates: StateFlow<List<SavedTemplateEntity>> = repository.savedTemplates.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    val vpnTelemetry: StateFlow<VpnTelemetryState> = VpnStateBus.telemetry

    // Active file & Unlocker state
    private val _activeFileBuffer = MutableStateFlow<ActiveFileBuffer?>(null)
    val activeFileBuffer: StateFlow<ActiveFileBuffer?> = _activeFileBuffer.asStateFlow()

    private val _unlockPasswordInput = MutableStateFlow("")
    val unlockPasswordInput: StateFlow<String> = _unlockPasswordInput.asStateFlow()

    private val _unlockResult = MutableStateFlow<UnlockOperationResult?>(null)
    val unlockResult: StateFlow<UnlockOperationResult?> = _unlockResult.asStateFlow()

    private val _isProcessing = MutableStateFlow(false)
    val isProcessing: StateFlow<Boolean> = _isProcessing.asStateFlow()

    // Decoder state
    private val _decoderInputText = MutableStateFlow("")
    val decoderInputText: StateFlow<String> = _decoderInputText.asStateFlow()

    private val _decodeResult = MutableStateFlow<DecodeOperationResult?>(null)
    val decodeResult: StateFlow<DecodeOperationResult?> = _decodeResult.asStateFlow()

    // Password Recovery state
    private val _recoverySinglePassword = MutableStateFlow("")
    val recoverySinglePassword: StateFlow<String> = _recoverySinglePassword.asStateFlow()

    private val _recoveryWordlistInput = MutableStateFlow("")
    val recoveryWordlistInput: StateFlow<String> = _recoveryWordlistInput.asStateFlow()

    private val _recoveryReport = MutableStateFlow<PasswordRecoveryReport?>(null)
    val recoveryReport: StateFlow<PasswordRecoveryReport?> = _recoveryReport.asStateFlow()

    // Generator state
    private val _generatorInput = MutableStateFlow(
        GeneratorInput(
            profileName = "Enterprise-Edge-WSS",
            protocol = TunnelProtocol.SSH_WS_TLS,
            serverHost = "",
            serverPortText = "443",
            username = "",
            passwordOrUuid = "",
            sniHost = "",
            wsPath = "/ws-tunnel",
            customHttpPayload = "",
            lockWithPassword = ""
        )
    )
    val generatorInput: StateFlow<GeneratorInput> = _generatorInput.asStateFlow()

    private val _generatorValidationErrors = MutableStateFlow<List<String>>(emptyList())
    val generatorValidationErrors: StateFlow<List<String>> = _generatorValidationErrors.asStateFlow()

    private val _generatedBundle = MutableStateFlow<GeneratedConfigBundle?>(null)
    val generatedBundle: StateFlow<GeneratedConfigBundle?> = _generatedBundle.asStateFlow()

    private val _endpointCheckResult = MutableStateFlow<HandshakeCheckResult?>(null)
    val endpointCheckResult: StateFlow<HandshakeCheckResult?> = _endpointCheckResult.asStateFlow()

    // Config Editor state
    private val _editorFileName = MutableStateFlow("untitled_config.json")
    val editorFileName: StateFlow<String> = _editorFileName.asStateFlow()

    private val _editorOriginalContent = MutableStateFlow("")
    val editorOriginalContent: StateFlow<String> = _editorOriginalContent.asStateFlow()

    private val _editorContent = MutableStateFlow(
        """
        {
          "configVersion": "1.0",
          "name": "Custom-Tunnel-Config",
          "protocol": "SSH_WS_TLS",
          "serverHost": "",
          "serverPort": 443,
          "username": "",
          "tls": {
            "enabled": true,
            "sni": ""
          },
          "websocket": {
            "enabled": true,
            "path": "/ws"
          }
        }
        """.trimIndent()
    )
    val editorContent: StateFlow<String> = _editorContent.asStateFlow()

    private val _editorFindQuery = MutableStateFlow("")
    val editorFindQuery: StateFlow<String> = _editorFindQuery.asStateFlow()

    private val _editorReplaceQuery = MutableStateFlow("")
    val editorReplaceQuery: StateFlow<String> = _editorReplaceQuery.asStateFlow()

    // VPN Connection form state
    private val _vpnParams = MutableStateFlow(
        VpnConnectionParams(
            profileName = "Direct Authorized Endpoint",
            protocol = "SSH_WS_TLS",
            serverHost = "",
            serverPort = 443,
            username = "",
            sniHost = "",
            wsPath = "/ws"
        )
    )
    val vpnParams: StateFlow<VpnConnectionParams> = _vpnParams.asStateFlow()

    // Status Banner Toast/Snackbar feedback
    private val _statusBannerMessage = MutableStateFlow<String?>(null)
    val statusBannerMessage: StateFlow<String?> = _statusBannerMessage.asStateFlow()

    init {
        viewModelScope.launch {
            // Seed default authorized diagnostic password hint if empty so users can test Password Recovery right away
            database.dao().getAllPasswordHints().collect { hints ->
                if (hints.isEmpty()) {
                    repository.addPasswordHint(
                        label = "Authorized Diagnostic Sample Key",
                        candidatePassword = "DarkTunnel#2026",
                        notes = "Default key for testing the built-in Authorized Diagnostic Sample (.dark) file."
                    )
                }
                return@collect
            }
        }
    }

    fun navigateTo(destination: WorkbenchDestination) {
        _currentDestination.value = destination
    }

    fun dismissStatusBanner() {
        _statusBannerMessage.value = null
    }

    fun showBanner(message: String) {
        _statusBannerMessage.value = message
    }

    // 1. Config File Importer & Backup creation
    fun importConfigFromUri(uri: Uri, displayNameHint: String?) {
        viewModelScope.launch {
            _isProcessing.value = true
            try {
                val context = getApplication<Application>()
                val rawBytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
                }
                val resolvedName = displayNameHint?.takeIf { it.isNotBlank() }
                    ?: uri.lastPathSegment?.substringAfterLast('/')
                    ?: "imported_config.dark"

                processImportedBytes(resolvedName, rawBytes)
            } catch (e: Exception) {
                showBanner("Failed to import file: ${e.message}")
                repository.logOperation("IMPORT", displayNameHint ?: "URI", "FAILED", "IO Error: ${e.message}")
            } finally {
                _isProcessing.value = false
            }
        }
    }

    fun loadAuthorizedDiagnosticSample(type: String) {
        viewModelScope.launch {
            _isProcessing.value = true
            try {
                when (type) {
                    "ENCRYPTED_DARK" -> {
                        val bytes = ConfigGeneratorEngine.buildAuthorizedSampleEncryptedDarkFile("DarkTunnel#2026")
                        processImportedBytes("authorized_sample_locked.dark", bytes)
                        _unlockPasswordInput.value = "DarkTunnel#2026"
                        showBanner("Loaded encrypted sample (.dark) and created backup. Key: DarkTunnel#2026")
                    }
                    "ENCODED_VMESS" -> {
                        val payload = ConfigGeneratorEngine.buildAuthorizedSampleEncodedPayload()
                        val bytes = payload.toByteArray(StandardCharsets.UTF_8)
                        processImportedBytes("sample_encoded_uri.ehi", bytes)
                        _decoderInputText.value = payload
                        showBanner("Loaded Base64 VMess URI sample (.ehi) for decoding.")
                    }
                    "CORRUPTED_SAMPLE" -> {
                        val brokenBytes = "{ \"magic\": \"DARK_TUNNEL\", \"ciphertext\": \"!!CORRUPTED_STREAM".toByteArray(StandardCharsets.UTF_8)
                        processImportedBytes("corrupted_capture.hat", brokenBytes)
                        showBanner("Loaded corrupted container sample (.hat) to demonstrate integrity error detection.")
                    }
                }
            } finally {
                _isProcessing.value = false
            }
        }
    }

    suspend fun processImportedBytes(fileName: String, rawBytes: ByteArray): FileAnalysisReport {
        return withContext(Dispatchers.IO) {
            val context = getApplication<Application>()
            val backupDir = File(context.filesDir, "config_backups").apply { mkdirs() }
            val safeFileName = fileName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
            val backupFile = File(backupDir, "backup_${System.currentTimeMillis()}_$safeFileName")
            backupFile.writeBytes(rawBytes)

            val report = ConfigCryptoEngine.analyzeConfigBytes(fileName, rawBytes)
            val buffer = ActiveFileBuffer(
                fileName = fileName,
                rawBytes = rawBytes,
                backupFilePath = backupFile.absolutePath,
                analysisReport = report
            )
            _activeFileBuffer.value = buffer
            _unlockResult.value = null

            // Pre-populate decoder or editor if readable/encoded
            if (report.formatState == ConfigFormatState.ENCODED_TEXT) {
                _decoderInputText.value = String(rawBytes, StandardCharsets.UTF_8)
            } else if (report.formatState == ConfigFormatState.READABLE_JSON_OR_TEXT) {
                val text = String(rawBytes, StandardCharsets.UTF_8)
                _editorFileName.value = fileName
                _editorOriginalContent.value = text
                _editorContent.value = text
            }

            repository.addImportedConfig(
                ImportedConfigEntity(
                    fileName = fileName,
                    formatExtension = report.extension.ifEmpty { "unknown" },
                    fileSizeBytes = report.sizeBytes,
                    sha256Checksum = report.sha256Hex,
                    shannonEntropy = report.shannonEntropy,
                    detectedState = report.formatState.name,
                    algorithmSummary = report.detectedContainerSignature,
                    backupFilePath = backupFile.absolutePath,
                    unlockedContent = if (report.formatState == ConfigFormatState.READABLE_JSON_OR_TEXT) {
                        String(rawBytes, StandardCharsets.UTF_8)
                    } else null
                )
            )

            repository.logOperation(
                category = "IMPORT",
                targetName = fileName,
                status = if (report.formatState == ConfigFormatState.CORRUPTED_OR_INVALID) "WARNING" else "SUCCESS",
                details = "${report.detectedContainerSignature} (${report.sizeBytes} B, SHA-256: ${report.sha256Hex.take(12)}...) Backup saved."
            )
            report
        }
    }

    fun selectImportedConfigFromRecord(record: ImportedConfigEntity) {
        viewModelScope.launch(Dispatchers.IO) {
            val backupFile = File(record.backupFilePath)
            if (backupFile.exists()) {
                val bytes = backupFile.readBytes()
                val report = ConfigCryptoEngine.analyzeConfigBytes(record.fileName, bytes)
                _activeFileBuffer.value = ActiveFileBuffer(
                    fileName = record.fileName,
                    rawBytes = bytes,
                    backupFilePath = record.backupFilePath,
                    analysisReport = report
                )
                _unlockResult.value = null
                showBanner("Restored ${record.fileName} from immutable backup.")
            } else {
                showBanner("Backup file no longer exists on disk.")
            }
        }
    }

    fun deleteImportedConfig(id: Int) {
        viewModelScope.launch {
            repository.removeImportedConfig(id)
        }
    }

    // 2. Config Unlocker
    fun updateUnlockPassword(password: String) {
        _unlockPasswordInput.value = password
    }

    fun executeUnlockActiveFile() {
        val current = _activeFileBuffer.value
        if (current == null) {
            showBanner("Import or select a configuration file first.")
            return
        }
        viewModelScope.launch {
            _isProcessing.value = true
            val password = _unlockPasswordInput.value
            val result = withContext(Dispatchers.Default) {
                ConfigCryptoEngine.unlockContainer(current.rawBytes, password)
            }
            _unlockResult.value = result
            when (result) {
                is UnlockOperationResult.Success -> {
                    _editorFileName.value = current.fileName.substringBeforeLast('.') + "_unlocked.json"
                    _editorOriginalContent.value = result.decryptedContent
                    _editorContent.value = result.decryptedContent
                    repository.logOperation(
                        category = "UNLOCK",
                        targetName = current.fileName,
                        status = "SUCCESS",
                        details = "Unlocked via ${result.cipherSuiteUsed} (${result.kdfIterations} iterations)."
                    )
                    showBanner("Configuration unlocked and verified! Loaded into Config Editor.")
                }
                is UnlockOperationResult.Failure -> {
                    repository.logOperation(
                        category = "UNLOCK",
                        targetName = current.fileName,
                        status = "FAILED",
                        details = "${result.errorTitle}: ${result.technicalReason}"
                    )
                }
            }
            _isProcessing.value = false
        }
    }

    fun lockCurrentEditorContentToActiveBuffer(password: String, formatExt: String = "dark") {
        if (password.isBlank()) {
            showBanner("Enter a non-empty encryption password to lock the configuration.")
            return
        }
        viewModelScope.launch {
            _isProcessing.value = true
            val plaintext = _editorContent.value
            val encryptedBytes = withContext(Dispatchers.Default) {
                ConfigCryptoEngine.createEncryptedContainer(
                    plaintextConfig = plaintext,
                    password = password,
                    formatExtension = formatExt
                )
            }
            val newName = _editorFileName.value.substringBeforeLast('.') + "_locked.$formatExt"
            processImportedBytes(newName, encryptedBytes)
            _unlockPasswordInput.value = password
            showBanner("Created AES-256-GCM encrypted .$formatExt container ($newName).")
            _isProcessing.value = false
        }
    }

    // 3. Config Decoder
    fun updateDecoderInput(text: String) {
        _decoderInputText.value = text
    }

    fun executeDecodePayload() {
        val input = _decoderInputText.value
        viewModelScope.launch {
            _isProcessing.value = true
            val res = withContext(Dispatchers.Default) {
                ConfigCryptoEngine.decodePayload(input)
            }
            _decodeResult.value = res
            repository.logOperation(
                category = "DECODE",
                targetName = "Decoder Payload (${input.length} chars)",
                status = if (res.isSuccessful) "SUCCESS" else "WARNING",
                details = res.detectedFormatSummary
            )
            _isProcessing.value = false
        }
    }

    fun sendDecodedOutputToEditor() {
        val decoded = _decodeResult.value?.finalOutput ?: return
        if (decoded.isNotBlank()) {
            _editorFileName.value = "decoded_profile.json"
            _editorOriginalContent.value = decoded
            _editorContent.value = decoded
            _currentDestination.value = WorkbenchDestination.EDITOR
            showBanner("Opened decoded configuration in Config Editor.")
        }
    }

    // 4. Password Recovery
    fun updateRecoverySinglePassword(value: String) {
        _recoverySinglePassword.value = value
    }

    fun updateRecoveryWordlist(value: String) {
        _recoveryWordlistInput.value = value
    }

    fun addSavedPasswordHint(label: String, candidate: String, notes: String) {
        if (label.isBlank() || candidate.isBlank()) {
            showBanner("Both label and password candidate are required.")
            return
        }
        viewModelScope.launch {
            repository.addPasswordHint(label.trim(), candidate.trim(), notes.trim())
            showBanner("Saved password hint '$label' to local authorized vault.")
        }
    }

    fun deletePasswordHint(id: Int) {
        viewModelScope.launch {
            repository.removePasswordHint(id)
        }
    }

    fun executePasswordRecoveryAudit() {
        val active = _activeFileBuffer.value
        if (active == null) {
            showBanner("Import or load an encrypted configuration file first.")
            return
        }
        viewModelScope.launch {
            _isProcessing.value = true
            val candidates = mutableListOf<String>()
            if (_recoverySinglePassword.value.isNotBlank()) {
                candidates.add(_recoverySinglePassword.value.trim())
            }
            passwordHints.value.forEach { hint ->
                candidates.add(hint.candidatePassword)
            }
            _recoveryWordlistInput.value.lines().forEach { line ->
                if (line.isNotBlank()) candidates.add(line.trim())
            }

            val report = withContext(Dispatchers.Default) {
                ConfigCryptoEngine.runAuthorizedPasswordRecovery(active.rawBytes, candidates)
            }
            _recoveryReport.value = report

            repository.logOperation(
                category = "RECOVERY",
                targetName = active.fileName,
                status = if (report.recoveredPassword != null) "SUCCESS" else "FAILED",
                details = report.explanationMessage
            )

            if (report.recoveredPassword != null && report.decryptedPayload != null) {
                _editorFileName.value = active.fileName.substringBeforeLast('.') + "_recovered.json"
                _editorOriginalContent.value = report.decryptedPayload
                _editorContent.value = report.decryptedPayload
                showBanner("Password recovered (${report.recoveredPassword})! Decrypted payload loaded into Editor.")
            }
            _isProcessing.value = false
        }
    }

    // 5. VPN Config Generator
    fun updateGeneratorInput(transform: (GeneratorInput) -> GeneratorInput) {
        _generatorInput.value = transform(_generatorInput.value)
        _generatorValidationErrors.value = emptyList()
    }

    fun testGeneratorEndpointReachability() {
        val current = _generatorInput.value
        val validation = ConfigGeneratorEngine.validateInput(current)
        if (!validation.isValid) {
            _generatorValidationErrors.value = validation.errors
            return
        }
        viewModelScope.launch {
            _isProcessing.value = true
            val port = current.serverPortText.trim().toIntOrNull() ?: current.protocol.defaultPort
            val res = EndpointVerifier.verifyServerHandshake(
                host = current.serverHost,
                port = port,
                useTls = current.protocol.requiresSni,
                sniHost = current.sniHost,
                wsPath = current.wsPath
            )
            _endpointCheckResult.value = res
            repository.logOperation(
                category = "VERIFY_HOST",
                targetName = "${current.serverHost}:$port",
                status = if (res.isReachable) "SUCCESS" else "FAILED",
                details = if (res.isReachable) "Verified in ${res.latencyMs}ms: ${res.serverBannerOrProtocol}" else (res.errorDetails ?: "Unreachable")
            )
            _isProcessing.value = false
        }
    }

    fun executeGenerateConfig() {
        val current = _generatorInput.value
        val validation = ConfigGeneratorEngine.validateInput(current)
        if (!validation.isValid) {
            _generatorValidationErrors.value = validation.errors
            return
        }
        viewModelScope.launch {
            val isVerified = _endpointCheckResult.value?.isReachable == true
            val bundle = withContext(Dispatchers.Default) {
                ConfigGeneratorEngine.generateConfig(current, isVerifiedReachable = isVerified)
            }
            _generatedBundle.value = bundle

            // Save template to Room
            val port = current.serverPortText.trim().toIntOrNull() ?: current.protocol.defaultPort
            repository.saveTemplate(
                SavedTemplateEntity(
                    name = current.profileName.trim(),
                    protocol = current.protocol.name,
                    serverHost = current.serverHost.trim(),
                    serverPort = port,
                    username = current.username.trim(),
                    sniHost = current.sniHost.trim(),
                    wsPath = current.wsPath.trim(),
                    customPayload = current.customHttpPayload,
                    rawConfigJson = bundle.readableJson,
                    isVerifiedReachable = isVerified,
                    lastVerifiedLatencyMs = _endpointCheckResult.value?.latencyMs
                )
            )

            repository.logOperation(
                category = "GENERATE",
                targetName = current.profileName,
                status = "SUCCESS",
                details = "Generated ${current.protocol.displayName} (${if (isVerified) "Tested & Connectable" else "Template Only"})."
            )

            // Also populate editor and VPN connection parameters for seamless workflow
            _editorFileName.value = "${current.profileName.replace(" ", "_").lowercase()}.json"
            _editorOriginalContent.value = bundle.readableJson
            _editorContent.value = bundle.readableJson

            _vpnParams.value = VpnConnectionParams(
                profileName = current.profileName.trim(),
                protocol = current.protocol.name,
                serverHost = current.serverHost.trim(),
                serverPort = port,
                username = current.username.trim(),
                sniHost = current.sniHost.trim(),
                wsPath = current.wsPath.trim(),
                primaryDns = settingsState.value.customDnsPrimary,
                secondaryDns = settingsState.value.customDnsSecondary,
                mtu = settingsState.value.vpnMtu
            )

            showBanner("Configuration generated and saved to Templates.")
        }
    }

    fun deleteSavedTemplate(id: Int) {
        viewModelScope.launch {
            repository.removeTemplate(id)
        }
    }

    fun loadTemplateIntoGeneratorAndVpn(template: SavedTemplateEntity) {
        val proto = TunnelProtocol.entries.find { it.name == template.protocol } ?: TunnelProtocol.SSH_WS_TLS
        _generatorInput.value = GeneratorInput(
            profileName = template.name,
            protocol = proto,
            serverHost = template.serverHost,
            serverPortText = template.serverPort.toString(),
            username = template.username,
            passwordOrUuid = "",
            sniHost = template.sniHost,
            wsPath = template.wsPath,
            customHttpPayload = template.customPayload
        )
        _vpnParams.value = VpnConnectionParams(
            profileName = template.name,
            protocol = template.protocol,
            serverHost = template.serverHost,
            serverPort = template.serverPort,
            username = template.username,
            sniHost = template.sniHost,
            wsPath = template.wsPath,
            primaryDns = settingsState.value.customDnsPrimary,
            secondaryDns = settingsState.value.customDnsSecondary,
            mtu = settingsState.value.vpnMtu
        )
        _editorFileName.value = "${template.name.replace(" ", "_").lowercase()}.json"
        _editorOriginalContent.value = template.rawConfigJson
        _editorContent.value = template.rawConfigJson
        showBanner("Loaded template '${template.name}'.")
    }

    // 6. Config Editor
    fun updateEditorFileName(name: String) {
        _editorFileName.value = name
    }

    fun updateEditorContent(content: String) {
        _editorContent.value = content
    }

    fun updateEditorFindQuery(query: String) {
        _editorFindQuery.value = query
    }

    fun updateEditorReplaceQuery(replacement: String) {
        _editorReplaceQuery.value = replacement
    }

    fun executeEditorReplaceAll() {
        val findStr = _editorFindQuery.value
        if (findStr.isEmpty()) {
            showBanner("Enter a Find string first.")
            return
        }
        val current = _editorContent.value
        val count = current.split(findStr).size - 1
        if (count <= 0) {
            showBanner("No occurrences of '$findStr' found.")
            return
        }
        _editorContent.value = current.replace(findStr, _editorReplaceQuery.value)
        showBanner("Replaced $count occurrence(s) of '$findStr'.")
    }

    fun createNewBlankConfigInEditor() {
        val blank = JSONObject().apply {
            put("configVersion", "1.0")
            put("name", "New-Scratch-Config")
            put("protocol", "SSH_WS_TLS")
            put("serverHost", "")
            put("serverPort", 443)
            put("username", "")
            put("tls", JSONObject().apply {
                put("enabled", true)
                put("sni", "")
            })
            put("websocket", JSONObject().apply {
                put("enabled", true)
                put("path", "/ws")
                put("httpPayload", "")
            })
        }.toString(2)
        _editorFileName.value = "new_config_${System.currentTimeMillis() % 10000}.json"
        _editorOriginalContent.value = blank
        _editorContent.value = blank
        showBanner("Initialized new configuration from scratch.")
    }

    fun formatJsonInEditor() {
        val text = _editorContent.value.trim()
        try {
            val json = JSONObject(text)
            _editorContent.value = json.toString(2)
            showBanner("JSON validated and formatted.")
        } catch (e: Exception) {
            showBanner("JSON Syntax Error: ${e.message}")
        }
    }

    fun revertEditorToOriginal() {
        if (_editorOriginalContent.value.isNotEmpty()) {
            _editorContent.value = _editorOriginalContent.value
            showBanner("Reverted editor buffer to original unmodified snapshot.")
        }
    }

    fun saveEditedCopyLocally() {
        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            val editedDir = File(context.filesDir, "edited_configs").apply { mkdirs() }
            val baseName = _editorFileName.value.ifBlank { "edited_config.json" }
            val safeName = baseName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
            val outFile = File(editedDir, "edited_${System.currentTimeMillis()}_$safeName")
            val bytes = _editorContent.value.toByteArray(StandardCharsets.UTF_8)
            outFile.writeBytes(bytes)

            val report = ConfigCryptoEngine.analyzeConfigBytes(safeName, bytes)
            repository.addImportedConfig(
                ImportedConfigEntity(
                    fileName = "edited_$safeName",
                    formatExtension = report.extension.ifEmpty { "json" },
                    fileSizeBytes = report.sizeBytes,
                    sha256Checksum = report.sha256Hex,
                    shannonEntropy = report.shannonEntropy,
                    detectedState = report.formatState.name,
                    algorithmSummary = "Saved Edited Copy (${report.detectedContainerSignature})",
                    backupFilePath = outFile.absolutePath,
                    unlockedContent = _editorContent.value
                )
            )
            repository.logOperation(
                category = "EDIT",
                targetName = safeName,
                status = "SUCCESS",
                details = "Saved separate edited copy (${bytes.size} bytes). Original file preserved untouched."
            )
            withContext(Dispatchers.Main) {
                showBanner("Saved edited copy separately as edited_$safeName. Original preserved.")
            }
        }
    }

    fun exportContentToUri(uri: Uri, contentBytes: ByteArray, label: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val context = getApplication<Application>()
                context.contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(contentBytes)
                    out.flush()
                }
                repository.logOperation(
                    category = "EXPORT",
                    targetName = label,
                    status = "SUCCESS",
                    details = "Exported ${contentBytes.size} bytes to user storage."
                )
                withContext(Dispatchers.Main) {
                    showBanner("Successfully exported $label (${contentBytes.size} bytes).")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showBanner("Export failed: ${e.message}")
                }
            }
        }
    }

    fun applyEditorConfigToVpnModule() {
        val text = _editorContent.value.trim()
        try {
            val json = JSONObject(text)
            val host = json.optString("serverHost", json.optString("add", json.optString("server", "")))
            val port = json.optInt("serverPort", json.optInt("port", 443))
            val name = json.optString("name", json.optString("ps", _editorFileName.value))
            val proto = json.optString("protocol", "SSH_WS_TLS")
            val user = json.optString("username", json.optString("id", ""))
            val sni = json.optJSONObject("tls")?.optString("sni", "") ?: json.optString("sni", "")
            val wsPath = json.optJSONObject("websocket")?.optString("path", "/ws") ?: json.optString("path", "/ws")

            _vpnParams.value = VpnConnectionParams(
                profileName = name,
                protocol = proto,
                serverHost = host,
                serverPort = port,
                username = user,
                sniHost = sni,
                wsPath = wsPath,
                primaryDns = settingsState.value.customDnsPrimary,
                secondaryDns = settingsState.value.customDnsSecondary,
                mtu = settingsState.value.vpnMtu
            )
            _currentDestination.value = WorkbenchDestination.VPN_CONNECTION
            showBanner("Applied configuration '$name' to VPN Connection Module.")
        } catch (e: Exception) {
            showBanner("Could not parse JSON fields for VPN module: ${e.message}")
        }
    }

    // 7. VPN Connection Module
    fun updateVpnParams(transform: (VpnConnectionParams) -> VpnConnectionParams) {
        _vpnParams.value = transform(_vpnParams.value)
    }

    fun startVpnServiceConnection() {
        val params = _vpnParams.value
        if (params.serverHost.isBlank()) {
            showBanner("Server host is required. Enter an authorized connectable server address.")
            return
        }
        val context = getApplication<Application>()
        val intent = Intent(context, DarkTunnelVpnService::class.java).apply {
            action = DarkTunnelVpnService.ACTION_CONNECT
            putExtra(DarkTunnelVpnService.EXTRA_PROFILE_NAME, params.profileName)
            putExtra(DarkTunnelVpnService.EXTRA_PROTOCOL, params.protocol)
            putExtra(DarkTunnelVpnService.EXTRA_HOST, params.serverHost.trim())
            putExtra(DarkTunnelVpnService.EXTRA_PORT, params.serverPort)
            putExtra(DarkTunnelVpnService.EXTRA_USERNAME, params.username.trim())
            putExtra(DarkTunnelVpnService.EXTRA_SNI, params.sniHost.trim())
            putExtra(DarkTunnelVpnService.EXTRA_WS_PATH, params.wsPath.trim())
            putExtra(DarkTunnelVpnService.EXTRA_DNS1, settingsState.value.customDnsPrimary)
            putExtra(DarkTunnelVpnService.EXTRA_DNS2, settingsState.value.customDnsSecondary)
            putExtra(DarkTunnelVpnService.EXTRA_MTU, settingsState.value.vpnMtu)
        }
        context.startService(intent)
        viewModelScope.launch {
            repository.logOperation(
                category = "VPN",
                targetName = "${params.serverHost}:${params.serverPort}",
                status = "INFO",
                details = "Initiated VPN tunnel connection & endpoint socket handshake."
            )
        }
    }

    fun stopVpnServiceConnection() {
        val context = getApplication<Application>()
        val intent = Intent(context, DarkTunnelVpnService::class.java).apply {
            action = DarkTunnelVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)
        viewModelScope.launch {
            repository.logOperation(
                category = "VPN",
                targetName = _vpnParams.value.serverHost.ifBlank { "Active Tunnel" },
                status = "INFO",
                details = "Disconnected VPN tunnel."
            )
        }
    }

    // 8. History & Settings
    fun clearOperationHistory() {
        viewModelScope.launch {
            repository.clearHistory()
            showBanner("Cleared operation audit history.")
        }
    }

    fun toggleDarkMode(enabled: Boolean) {
        viewModelScope.launch {
            settingsPrefs.setDarkMode(enabled)
        }
    }

    fun toggleAutoBackup(enabled: Boolean) {
        viewModelScope.launch {
            settingsPrefs.setAutoBackup(enabled)
        }
    }

    fun toggleStrictVerification(enabled: Boolean) {
        viewModelScope.launch {
            settingsPrefs.setStrictVerification(enabled)
        }
    }

    fun saveNetworkSettings(dns1: String, dns2: String, mtuText: String) {
        val mtu = mtuText.toIntOrNull() ?: 1400
        viewModelScope.launch {
            settingsPrefs.updateDnsAndMtu(dns1.trim(), dns2.trim(), mtu)
            showBanner("Saved DNS ($dns1, $dns2) and MTU ($mtu) settings.")
        }
    }
}
