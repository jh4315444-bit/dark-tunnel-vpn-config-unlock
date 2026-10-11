package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.crypto.UnlockOperationResult
import com.example.ui.components.CodePreviewBox
import com.example.ui.components.CyberCard
import com.example.ui.components.EntropyGaugeIndicator
import com.example.ui.components.FormatStateBadge
import com.example.ui.components.SectionHeader
import com.example.ui.components.StatusBadge
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import com.example.viewmodel.ActiveFileBuffer
import com.example.viewmodel.WorkbenchDestination

@Composable
fun UnlockerScreen(
    activeBuffer: ActiveFileBuffer?,
    passwordInput: String,
    unlockResult: UnlockOperationResult?,
    onPasswordChange: (String) -> Unit,
    onExecuteUnlock: () -> Unit,
    onImportFile: () -> Unit,
    onLoadSampleEncrypted: () -> Unit,
    onLoadSampleCorrupted: () -> Unit,
    onNavigate: (WorkbenchDestination) -> Unit,
    onExportUnlocked: (String) -> Unit,
    onApplyToVpn: (String) -> Unit,
    onShowMessage: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var showPassword by remember { mutableStateOf(true) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("unlocker_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.LockOpen,
                title = "Config Unlocker",
                subtitle = "Unlock encrypted or compressed VPN configs to see all clear server, port, SNI & payload details"
            )
        }

        // Target File Inspection Card
        item {
            CyberCard(accentColor = NeonCyan) {
                if (activeBuffer == null) {
                    Text(
                        text = "No Configuration File Loaded",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Import any VPN config (.dark, .hat, .ehi, .nm, .hc, .json) or tap 'Load Sample .dark' below to immediately see all unlocked configuration text clearly.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onImportFile,
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                            modifier = Modifier.weight(1f).testTag("unlocker_import_button")
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Import File", fontWeight = FontWeight.Bold)
                        }
                        OutlinedButton(
                            onClick = onLoadSampleEncrypted,
                            border = BorderStroke(1.dp, NeonGreen),
                            modifier = Modifier.weight(1f).testTag("unlocker_load_sample_button")
                        ) {
                            Text("Load Sample .dark", color = NeonGreen)
                        }
                    }
                } else {
                    val rep = activeBuffer.analysisReport
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = rep.fileName,
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${rep.sizeBytes} bytes • ${rep.detectedContainerSignature}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = NeonCyan
                            )
                        }
                        FormatStateBadge(state = rep.formatState)
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    EntropyGaugeIndicator(entropy = rep.shannonEntropy)
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = rep.diagnosticMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onImportFile,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Switch File")
                        }
                        OutlinedButton(
                            onClick = onLoadSampleEncrypted,
                            border = BorderStroke(1.dp, NeonGreen.copy(alpha = 0.6f)),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Sample .dark", color = NeonGreen)
                        }
                        OutlinedButton(
                            onClick = onLoadSampleCorrupted,
                            border = BorderStroke(1.dp, CrimsonError.copy(alpha = 0.6f)),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Corrupted .hat", color = CrimsonError)
                        }
                    }
                }
            }
        }

        // Decryption Key Input Card
        item {
            CyberCard(accentColor = NeonGreen) {
                Text(
                    text = "Decryption Key / Password",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Enter the password for encrypted containers, or press Unlock directly for compressed/encoded files to reveal all clear settings.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = passwordInput,
                    onValueChange = onPasswordChange,
                    label = { Text("Password or Decryption Key (if locked)") },
                    placeholder = { Text("e.g. DarkTunnel#2026") },
                    singleLine = true,
                    visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                    leadingIcon = {
                        Icon(Icons.Default.Key, contentDescription = null, tint = NeonCyan)
                    },
                    trailingIcon = {
                        IconButton(onClick = { showPassword = !showPassword }) {
                            Icon(
                                imageVector = if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = "Toggle password visibility"
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("unlock_password_input")
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = onExecuteUnlock,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonGreen,
                        contentColor = ObsidianDeep
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                        .testTag("execute_unlock_button")
                ) {
                    Icon(Icons.Default.LockOpen, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Unlock & Show All Clear Config Data", fontWeight = FontWeight.Bold)
                }
            }
        }

        // Actual Cryptographic Operation Result with Crystal-Clear Parameter Breakdown
        if (unlockResult != null) {
            item {
                when (unlockResult) {
                    is UnlockOperationResult.Success -> {
                        CyberCard(accentColor = NeonGreen) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.CheckCircle,
                                    contentDescription = "Unlock Succeeded",
                                    tint = NeonGreen,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "Unlocked — Clear Configuration Inspector",
                                        style = MaterialTheme.typography.titleLarge,
                                        color = NeonGreen
                                    )
                                    Text(
                                        text = "${unlockResult.cipherSuiteUsed} • 100% Readable Output",
                                        fontFamily = JetBrainsMonoFontFamily,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }

                            // 1. Highlighted Clear Key-Value Table (Server, Port, SNI, Payload, Username, etc.)
                            if (unlockResult.parsedFields.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(14.dp))
                                Text(
                                    text = "Extracted VPN Parameters (Tap any row to copy):",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = NeonCyan
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                ClearConfigParametersTable(
                                    fields = unlockResult.parsedFields,
                                    onCopyValue = { label, value ->
                                        clipboard.setText(AnnotatedString(value))
                                        onShowMessage("Copied $label: $value")
                                    }
                                )
                            }

                            Spacer(modifier = Modifier.height(14.dp))
                            Text(
                                text = "Full Unlocked Inspector Report & Readable Config:",
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            CodePreviewBox(code = unlockResult.formattedInspectorReport)
                            Spacer(modifier = Modifier.height(12.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                OutlinedButton(
                                    onClick = {
                                        clipboard.setText(AnnotatedString(unlockResult.formattedInspectorReport))
                                        onShowMessage("Copied full unlocked report to clipboard.")
                                    },
                                    modifier = Modifier.weight(1f).testTag("copy_unlocked_button")
                                ) {
                                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Copy All")
                                }
                                OutlinedButton(
                                    onClick = { onExportUnlocked(unlockResult.decryptedContent) },
                                    modifier = Modifier.weight(1f).testTag("export_unlocked_button")
                                ) {
                                    Icon(Icons.Default.SaveAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Save File")
                                }
                                Button(
                                    onClick = { onNavigate(WorkbenchDestination.EDITOR) },
                                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                                    modifier = Modifier.weight(1f).testTag("edit_unlocked_button")
                                ) {
                                    Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Editor", fontWeight = FontWeight.Bold)
                                }
                            }

                            Spacer(modifier = Modifier.height(8.dp))
                            Button(
                                onClick = { onApplyToVpn(unlockResult.decryptedContent) },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.VpnLock, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Use Unlocked Config in VPN Connection", fontWeight = FontWeight.Bold)
                            }
                        }
                    }

                    is UnlockOperationResult.Failure -> {
                        CyberCard(accentColor = CrimsonError) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.ErrorOutline,
                                    contentDescription = "Unlock Failed",
                                    tint = CrimsonError,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = unlockResult.errorTitle,
                                        style = MaterialTheme.typography.titleLarge,
                                        color = CrimsonError
                                    )
                                    StatusBadge(
                                        text = if (unlockResult.isCorruptedFile) "INTEGRITY / FORMAT ERROR" else "AUTHENTICATION FAILED",
                                        color = CrimsonError
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = unlockResult.technicalReason,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            if (unlockResult.isWrongPassword) {
                                Spacer(modifier = Modifier.height(10.dp))
                                OutlinedButton(
                                    onClick = { onNavigate(WorkbenchDestination.PASSWORD_RECOVERY) },
                                    border = BorderStroke(1.dp, ElectricAmber),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Test Saved Hints in Password Recovery", color = ElectricAmber)
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun ClearConfigParametersTable(
    fields: Map<String, String>,
    onCopyValue: (String, String) -> Unit
) {
    // Filter out internal duplicate test key 'add' if 'Server Host / IP' is already present
    val displayEntries = fields.entries.filterNot { (k, _) ->
        k == "add" && (fields.containsKey("Server Host / IP") || fields.containsKey("Server Host"))
    }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
        border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            displayEntries.forEachIndexed { index, (label, value) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = label.uppercase(),
                            fontFamily = JetBrainsMonoFontFamily,
                            style = MaterialTheme.typography.labelMedium,
                            color = NeonCyan,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = value,
                            fontFamily = JetBrainsMonoFontFamily,
                            style = MaterialTheme.typography.bodyLarge,
                            color = NeonGreen,
                            fontWeight = FontWeight.Medium
                        )
                    }
                    IconButton(onClick = { onCopyValue(label, value) }) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy $label",
                            tint = NeonCyan,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
                if (index < displayEntries.lastIndex) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
                }
            }
        }
    }
}
