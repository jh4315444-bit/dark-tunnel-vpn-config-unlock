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
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.crypto.PasswordRecoveryReport
import com.example.data.PasswordHintEntity
import com.example.ui.components.CodePreviewBox
import com.example.ui.components.CyberCard
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
fun PasswordRecoveryScreen(
    activeBuffer: ActiveFileBuffer?,
    singlePasswordCandidate: String,
    wordlistInput: String,
    savedHints: List<PasswordHintEntity>,
    recoveryReport: PasswordRecoveryReport?,
    onSinglePasswordChange: (String) -> Unit,
    onWordlistChange: (String) -> Unit,
    onAddPasswordHint: (String, String, String) -> Unit,
    onDeletePasswordHint: (Int) -> Unit,
    onRunRecoveryAudit: () -> Unit,
    onImportFile: () -> Unit,
    onLoadSampleEncrypted: () -> Unit,
    onNavigate: (WorkbenchDestination) -> Unit
) {
    var newHintLabel by remember { mutableStateOf("") }
    var newHintPassword by remember { mutableStateOf("") }
    var newHintNotes by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("password_recovery_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.VpnKey,
                title = "Password Recovery",
                subtitle = "Authorized key verification from user hints & custom wordlists"
            )
        }

        // Honest Cryptographic Limitation Notice
        item {
            CyberCard(accentColor = ElectricAmber) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = ElectricAmber,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Cryptographic Security & Authorization Notice",
                        style = MaterialTheme.typography.titleMedium,
                        color = ElectricAmber
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = stringResource(id = R.string.recovery_disclaimer),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Target File Card
        item {
            CyberCard(accentColor = NeonCyan) {
                if (activeBuffer == null) {
                    Text(
                        text = "No Target Encrypted File Selected",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onImportFile,
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Import File", fontWeight = FontWeight.Bold)
                        }
                        OutlinedButton(
                            onClick = onLoadSampleEncrypted,
                            border = BorderStroke(1.dp, NeonGreen),
                            modifier = Modifier.weight(1f).testTag("recovery_load_sample_button")
                        ) {
                            Text("Load Sample .dark", color = NeonGreen)
                        }
                    }
                } else {
                    Text(
                        text = "Target File: ${activeBuffer.fileName}",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "${activeBuffer.analysisReport.detectedContainerSignature} • ${activeBuffer.analysisReport.sizeBytes} bytes",
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelMedium,
                        color = NeonCyan
                    )
                }
            }
        }

        // Candidate Password & Authorized Wordlist Input
        item {
            CyberCard(accentColor = NeonGreen) {
                Text(
                    text = "Test User-Supplied Password & Authorized Wordlist",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = singlePasswordCandidate,
                    onValueChange = onSinglePasswordChange,
                    label = { Text("Direct Password Candidate to Test") },
                    placeholder = { Text("Enter suspected password") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("recovery_single_password_input")
                )

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = wordlistInput,
                    onValueChange = onWordlistChange,
                    label = { Text("Authorized Password List (One candidate per line)") },
                    placeholder = { Text("my_old_vpn_key_2025\ncompany_edge_pass\nDarkTunnel#2026") },
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("recovery_wordlist_input")
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = onRunRecoveryAudit,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonGreen,
                        contentColor = ObsidianDeep
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                        .testTag("execute_recovery_button")
                ) {
                    Icon(Icons.Default.VpnKey, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Run Authorized Recovery Audit (${savedHints.size} Saved Hints + Inputs)",
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        // Recovery Audit Report
        if (recoveryReport != null) {
            item {
                val isSuccess = recoveryReport.recoveredPassword != null
                val accent = if (isSuccess) NeonGreen else CrimsonError
                CyberCard(accentColor = accent) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (isSuccess) Icons.Default.CheckCircle else Icons.Default.ErrorOutline,
                            contentDescription = null,
                            tint = accent,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = if (isSuccess) "Matching Password Recovered!" else "No Matching Key Found",
                                style = MaterialTheme.typography.titleLarge,
                                color = accent
                            )
                            Text(
                                text = "Tested ${recoveryReport.testedCount} candidate(s) in ${recoveryReport.elapsedTimeMs}ms • ${recoveryReport.algorithmSummary}",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = recoveryReport.explanationMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    if (isSuccess && recoveryReport.recoveredPassword != null) {
                        Spacer(modifier = Modifier.height(10.dp))
                        StatusBadge(
                            text = "RECOVERED KEY: ${recoveryReport.recoveredPassword}",
                            color = NeonGreen
                        )
                        if (recoveryReport.decryptedPayload != null) {
                            Spacer(modifier = Modifier.height(10.dp))
                            CodePreviewBox(code = recoveryReport.decryptedPayload)
                            Spacer(modifier = Modifier.height(10.dp))
                            Button(
                                onClick = { onNavigate(WorkbenchDestination.EDITOR) },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Recovered Config in Editor", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // User's Saved Password Hints Vault
        item {
            CyberCard(accentColor = NeonCyan) {
                Text(
                    text = "Add to User's Saved Password Hints Vault",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = newHintLabel,
                    onValueChange = { newHintLabel = it },
                    label = { Text("Profile / Server Label") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("hint_label_input")
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = newHintPassword,
                    onValueChange = { newHintPassword = it },
                    label = { Text("Candidate Password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("hint_password_input")
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = newHintNotes,
                    onValueChange = { newHintNotes = it },
                    label = { Text("Memory Hint / Notes") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedButton(
                    onClick = {
                        onAddPasswordHint(newHintLabel, newHintPassword, newHintNotes)
                        newHintLabel = ""
                        newHintPassword = ""
                        newHintNotes = ""
                    },
                    border = BorderStroke(1.dp, NeonCyan),
                    modifier = Modifier.fillMaxWidth().testTag("save_hint_button")
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, tint = NeonCyan)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save Password Hint Locally", color = NeonCyan)
                }
            }
        }

        items(savedHints, key = { it.id }) { hint ->
            CyberCard(accentColor = NeonCyan.copy(alpha = 0.4f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = hint.label,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Key: ${hint.candidatePassword}",
                            fontFamily = JetBrainsMonoFontFamily,
                            style = MaterialTheme.typography.labelMedium,
                            color = NeonGreen
                        )
                        if (hint.notes.isNotBlank()) {
                            Text(
                                text = hint.notes,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    IconButton(onClick = { onDeletePasswordHint(hint.id) }) {
                        Icon(Icons.Default.Delete, contentDescription = "Delete Hint", tint = CrimsonError)
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
