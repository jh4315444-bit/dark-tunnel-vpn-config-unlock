package com.example

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.components.StatusBadge
import com.example.ui.screens.DashboardScreen
import com.example.ui.screens.DecoderScreen
import com.example.ui.screens.EditorScreen
import com.example.ui.screens.GeneratorScreen
import com.example.ui.screens.HistoryScreen
import com.example.ui.screens.PasswordRecoveryScreen
import com.example.ui.screens.SettingsScreen
import com.example.ui.screens.UnlockerScreen
import com.example.ui.screens.VpnConnectionScreen
import com.example.ui.theme.DarkTunnelTheme
import com.example.ui.theme.MidnightNavy
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import com.example.viewmodel.DarkTunnelViewModel
import com.example.viewmodel.WorkbenchDestination
import com.example.vpn.VpnTunnelStatus
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: DarkTunnelViewModel = viewModel()
            val settings by viewModel.settingsState.collectAsStateWithLifecycle()

            DarkTunnelTheme(darkTheme = settings.isDarkMode) {
                DarkTunnelWorkbenchApp(viewModel = viewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DarkTunnelWorkbenchApp(viewModel: DarkTunnelViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val snackbarHostState = remember { SnackbarHostState() }

    val currentDestination by viewModel.currentDestination.collectAsStateWithLifecycle()
    val settings by viewModel.settingsState.collectAsStateWithLifecycle()
    val activeBuffer by viewModel.activeFileBuffer.collectAsStateWithLifecycle()
    val importedConfigs by viewModel.importedConfigs.collectAsStateWithLifecycle()
    val operationHistory by viewModel.operationHistory.collectAsStateWithLifecycle()
    val passwordHints by viewModel.passwordHints.collectAsStateWithLifecycle()
    val savedTemplates by viewModel.savedTemplates.collectAsStateWithLifecycle()
    val vpnTelemetry by viewModel.vpnTelemetry.collectAsStateWithLifecycle()
    val isProcessing by viewModel.isProcessing.collectAsStateWithLifecycle()

    val unlockPasswordInput by viewModel.unlockPasswordInput.collectAsStateWithLifecycle()
    val unlockResult by viewModel.unlockResult.collectAsStateWithLifecycle()
    val decoderInputText by viewModel.decoderInputText.collectAsStateWithLifecycle()
    val decodeResult by viewModel.decodeResult.collectAsStateWithLifecycle()
    val recoverySinglePassword by viewModel.recoverySinglePassword.collectAsStateWithLifecycle()
    val recoveryWordlistInput by viewModel.recoveryWordlistInput.collectAsStateWithLifecycle()
    val recoveryReport by viewModel.recoveryReport.collectAsStateWithLifecycle()

    val generatorInput by viewModel.generatorInput.collectAsStateWithLifecycle()
    val generatorValidationErrors by viewModel.generatorValidationErrors.collectAsStateWithLifecycle()
    val endpointCheckResult by viewModel.endpointCheckResult.collectAsStateWithLifecycle()
    val generatedBundle by viewModel.generatedBundle.collectAsStateWithLifecycle()

    val editorFileName by viewModel.editorFileName.collectAsStateWithLifecycle()
    val editorContent by viewModel.editorContent.collectAsStateWithLifecycle()
    val editorFindQuery by viewModel.editorFindQuery.collectAsStateWithLifecycle()
    val editorReplaceQuery by viewModel.editorReplaceQuery.collectAsStateWithLifecycle()
    val vpnParams by viewModel.vpnParams.collectAsStateWithLifecycle()
    val statusBannerMessage by viewModel.statusBannerMessage.collectAsStateWithLifecycle()

    // Pending export bytes for SAF CreateDocument
    var pendingExportBytes by remember { mutableStateOf<ByteArray?>(null) }
    var pendingExportLabel by remember { mutableStateOf("exported_config.json") }

    // SAF File Import Launcher
    val importFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            var resolvedName: String? = null
            try {
                context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (nameIdx >= 0) {
                            resolvedName = cursor.getString(nameIdx)
                        }
                    }
                }
            } catch (_: Exception) {
            }
            viewModel.importConfigFromUri(uri, resolvedName)
        }
    }

    // SAF File Export Launcher
    val exportFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri ->
        val bytes = pendingExportBytes
        if (uri != null && bytes != null) {
            viewModel.exportContentToUri(uri, bytes, pendingExportLabel)
        }
    }

    // Android VpnService.prepare() Permission Launcher
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startVpnServiceConnection()
        } else {
            viewModel.showBanner("Android VPN permission was denied by user.")
        }
    }

    val triggerVpnConnect: () -> Unit = {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            viewModel.startVpnServiceConnection()
        }
    }

    val triggerExport: (ByteArray, String) -> Unit = { bytes, suggestedName ->
        pendingExportBytes = bytes
        pendingExportLabel = suggestedName
        exportFileLauncher.launch(suggestedName)
    }

    LaunchedEffect(statusBannerMessage) {
        val msg = statusBannerMessage
        if (msg != null) {
            snackbarHostState.showSnackbar(msg)
            viewModel.dismissStatusBanner()
        }
    }

    // Handle Back navigation on secondary screens
    if (currentDestination != WorkbenchDestination.DASHBOARD) {
        BackHandler {
            viewModel.navigateTo(WorkbenchDestination.DASHBOARD)
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = MaterialTheme.colorScheme.surface,
                modifier = Modifier.width(300.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(vertical = 12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = NeonCyan,
                            modifier = Modifier.size(32.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "Dark Tunnel Unlocker",
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "v1.0 • Cryptographic Workbench",
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonGreen
                            )
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                    Spacer(modifier = Modifier.height(12.dp))

                    WorkbenchDestination.entries.forEach { dest ->
                        val icon = destinationIcon(dest)
                        NavigationDrawerItem(
                            icon = { Icon(icon, contentDescription = dest.title) },
                            label = { Text(dest.title, fontWeight = FontWeight.Medium) },
                            selected = currentDestination == dest,
                            onClick = {
                                viewModel.navigateTo(dest)
                                scope.launch { drawerState.close() }
                            },
                            colors = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor = NeonCyan.copy(alpha = 0.16f),
                                selectedIconColor = NeonCyan,
                                selectedTextColor = NeonCyan
                            ),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .padding(vertical = 2.dp)
                                .testTag("drawer_nav_${dest.name.lowercase()}")
                        )
                    }
                }
            }
        }
    ) {
        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            topBar = {
                Column {
                    TopAppBar(
                        title = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = currentDestination.title,
                                    style = MaterialTheme.typography.titleLarge
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                if (vpnTelemetry.status == VpnTunnelStatus.CONNECTED) {
                                    StatusBadge(text = "VPN ON", color = NeonGreen)
                                }
                            }
                        },
                        navigationIcon = {
                            IconButton(
                                onClick = { scope.launch { drawerState.open() } },
                                modifier = Modifier.testTag("open_drawer_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Menu,
                                    contentDescription = "Open Navigation Menu",
                                    tint = NeonCyan
                                )
                            }
                        },
                        actions = {
                            IconButton(
                                onClick = { viewModel.navigateTo(WorkbenchDestination.HISTORY) },
                                modifier = Modifier.testTag("topbar_history_button")
                            ) {
                                Icon(Icons.Default.History, contentDescription = "Operation History", tint = NeonCyan)
                            }
                            IconButton(
                                onClick = { viewModel.navigateTo(WorkbenchDestination.SETTINGS) },
                                modifier = Modifier.testTag("topbar_settings_button")
                            ) {
                                Icon(Icons.Default.Settings, contentDescription = "Settings", tint = NeonCyan)
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.background.copy(alpha = 0.95f)
                        )
                    )
                    if (isProcessing) {
                        LinearProgressIndicator(
                            color = NeonCyan,
                            trackColor = MidnightNavy,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            },
            bottomBar = {
                val primaryTabs = listOf(
                    WorkbenchDestination.DASHBOARD,
                    WorkbenchDestination.UNLOCKER,
                    WorkbenchDestination.DECODER,
                    WorkbenchDestination.GENERATOR,
                    WorkbenchDestination.VPN_CONNECTION
                )
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface
                ) {
                    primaryTabs.forEach { tab ->
                        NavigationBarItem(
                            selected = currentDestination == tab,
                            onClick = { viewModel.navigateTo(tab) },
                            icon = {
                                Icon(
                                    imageVector = destinationIcon(tab),
                                    contentDescription = tab.title
                                )
                            },
                            label = { Text(tab.title.substringBefore(" ")) },
                            modifier = Modifier.testTag("bottom_nav_${tab.name.lowercase()}")
                        )
                    }
                }
            }
        ) { innerPadding ->
            val bgModifier = if (settings.isDarkMode) {
                Modifier.background(
                    Brush.verticalGradient(
                        colors = listOf(ObsidianDeep, MidnightNavy, ObsidianDeep)
                    )
                )
            } else {
                Modifier.background(MaterialTheme.colorScheme.background)
            }

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .then(bgModifier)
                    .padding(innerPadding)
            ) {
                when (currentDestination) {
                    WorkbenchDestination.DASHBOARD -> DashboardScreen(
                        activeBuffer = activeBuffer,
                        importedConfigs = importedConfigs,
                        vpnTelemetry = vpnTelemetry,
                        onLaunchFilePicker = { importFileLauncher.launch(arrayOf("*/*")) },
                        onLoadDiagnosticSample = { viewModel.loadAuthorizedDiagnosticSample(it) },
                        onSelectImportedRecord = { viewModel.selectImportedConfigFromRecord(it) },
                        onDeleteImportedRecord = { viewModel.deleteImportedConfig(it) },
                        onNavigate = { viewModel.navigateTo(it) }
                    )

                    WorkbenchDestination.UNLOCKER -> UnlockerScreen(
                        activeBuffer = activeBuffer,
                        passwordInput = unlockPasswordInput,
                        unlockResult = unlockResult,
                        onPasswordChange = { viewModel.updateUnlockPassword(it) },
                        onExecuteUnlock = { viewModel.executeUnlockActiveFile() },
                        onImportFile = { importFileLauncher.launch(arrayOf("*/*")) },
                        onLoadSampleEncrypted = { viewModel.loadAuthorizedDiagnosticSample("ENCRYPTED_DARK") },
                        onLoadSampleCorrupted = { viewModel.loadAuthorizedDiagnosticSample("CORRUPTED_SAMPLE") },
                        onNavigate = { viewModel.navigateTo(it) },
                        onExportUnlocked = { text ->
                            triggerExport(text.toByteArray(Charsets.UTF_8), "unlocked_config.json")
                        },
                        onApplyToVpn = { text -> viewModel.applyConfigTextToVpnModule(text) },
                        onShowMessage = { viewModel.showBanner(it) }
                    )

                    WorkbenchDestination.DECODER -> DecoderScreen(
                        inputText = decoderInputText,
                        decodeResult = decodeResult,
                        onInputChange = { viewModel.updateDecoderInput(it) },
                        onExecuteDecode = { viewModel.executeDecodePayload() },
                        onLoadSampleEncoded = { viewModel.loadAuthorizedDiagnosticSample("ENCODED_VMESS") },
                        onSendToEditor = { viewModel.sendDecodedOutputToEditor() },
                        onExportDecoded = { text ->
                            triggerExport(text.toByteArray(Charsets.UTF_8), "decoded_config.json")
                        },
                        onApplyToVpn = { text -> viewModel.applyConfigTextToVpnModule(text) },
                        onNavigate = { viewModel.navigateTo(it) },
                        onShowMessage = { viewModel.showBanner(it) }
                    )

                    WorkbenchDestination.PASSWORD_RECOVERY -> PasswordRecoveryScreen(
                        activeBuffer = activeBuffer,
                        singlePasswordCandidate = recoverySinglePassword,
                        wordlistInput = recoveryWordlistInput,
                        savedHints = passwordHints,
                        recoveryReport = recoveryReport,
                        onSinglePasswordChange = { viewModel.updateRecoverySinglePassword(it) },
                        onWordlistChange = { viewModel.updateRecoveryWordlist(it) },
                        onAddPasswordHint = { l, p, n -> viewModel.addSavedPasswordHint(l, p, n) },
                        onDeletePasswordHint = { viewModel.deletePasswordHint(it) },
                        onRunRecoveryAudit = { viewModel.executePasswordRecoveryAudit() },
                        onImportFile = { importFileLauncher.launch(arrayOf("*/*")) },
                        onLoadSampleEncrypted = { viewModel.loadAuthorizedDiagnosticSample("ENCRYPTED_DARK") },
                        onNavigate = { viewModel.navigateTo(it) }
                    )

                    WorkbenchDestination.GENERATOR -> GeneratorScreen(
                        input = generatorInput,
                        validationErrors = generatorValidationErrors,
                        endpointCheck = endpointCheckResult,
                        generatedBundle = generatedBundle,
                        savedTemplates = savedTemplates,
                        onUpdateInput = { viewModel.updateGeneratorInput(it) },
                        onTestEndpointReachability = { viewModel.testGeneratorEndpointReachability() },
                        onGenerateConfig = { viewModel.executeGenerateConfig() },
                        onLoadTemplate = { viewModel.loadTemplateIntoGeneratorAndVpn(it) },
                        onDeleteTemplate = { viewModel.deleteSavedTemplate(it) },
                        onExportGenerated = { bytes, name -> triggerExport(bytes, name) },
                        onShowMessage = { viewModel.showBanner(it) }
                    )

                    WorkbenchDestination.EDITOR -> EditorScreen(
                        fileName = editorFileName,
                        editorContent = editorContent,
                        findQuery = editorFindQuery,
                        replaceQuery = editorReplaceQuery,
                        onFileNameChange = { viewModel.updateEditorFileName(it) },
                        onContentChange = { viewModel.updateEditorContent(it) },
                        onFindQueryChange = { viewModel.updateEditorFindQuery(it) },
                        onReplaceQueryChange = { viewModel.updateEditorReplaceQuery(it) },
                        onExecuteReplaceAll = { viewModel.executeEditorReplaceAll() },
                        onNewBlankConfig = { viewModel.createNewBlankConfigInEditor() },
                        onFormatJson = { viewModel.formatJsonInEditor() },
                        onRevertToOriginal = { viewModel.revertEditorToOriginal() },
                        onSaveEditedCopyLocally = { viewModel.saveEditedCopyLocally() },
                        onExportToStorage = { bytes, name -> triggerExport(bytes, name) },
                        onLockToEncryptedDark = { pass -> viewModel.lockCurrentEditorContentToActiveBuffer(pass, "dark") },
                        onApplyToVpnModule = { viewModel.applyEditorConfigToVpnModule() },
                        onShowMessage = { viewModel.showBanner(it) }
                    )

                    WorkbenchDestination.VPN_CONNECTION -> VpnConnectionScreen(
                        params = vpnParams,
                        telemetry = vpnTelemetry,
                        onUpdateParams = { viewModel.updateVpnParams(it) },
                        onRequestConnect = triggerVpnConnect,
                        onRequestDisconnect = { viewModel.stopVpnServiceConnection() }
                    )

                    WorkbenchDestination.HISTORY -> HistoryScreen(
                        historyList = operationHistory,
                        onClearHistory = { viewModel.clearOperationHistory() }
                    )

                    WorkbenchDestination.SETTINGS -> SettingsScreen(
                        settings = settings,
                        onToggleDarkMode = { viewModel.toggleDarkMode(it) },
                        onToggleAutoBackup = { viewModel.toggleAutoBackup(it) },
                        onToggleStrictVerification = { viewModel.toggleStrictVerification(it) },
                        onSaveNetworkSettings = { d1, d2, m -> viewModel.saveNetworkSettings(d1, d2, m) }
                    )
                }
            }
        }
    }
}

private fun destinationIcon(destination: WorkbenchDestination): ImageVector {
    return when (destination) {
        WorkbenchDestination.DASHBOARD -> Icons.Default.Dashboard
        WorkbenchDestination.UNLOCKER -> Icons.Default.LockOpen
        WorkbenchDestination.DECODER -> Icons.Default.Code
        WorkbenchDestination.PASSWORD_RECOVERY -> Icons.Default.VpnKey
        WorkbenchDestination.GENERATOR -> Icons.Default.Build
        WorkbenchDestination.EDITOR -> Icons.Default.Edit
        WorkbenchDestination.VPN_CONNECTION -> Icons.Default.VpnLock
        WorkbenchDestination.HISTORY -> Icons.Default.History
        WorkbenchDestination.SETTINGS -> Icons.Default.Settings
    }
}
