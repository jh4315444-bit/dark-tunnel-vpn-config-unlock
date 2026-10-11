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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FindReplace
import androidx.compose.material.icons.filled.FormatAlignLeft
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.components.ConfigSyntaxHighlightTransformation
import com.example.ui.components.CyberCard
import com.example.ui.components.SectionHeader
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep

@Composable
fun EditorScreen(
    fileName: String,
    editorContent: String,
    findQuery: String,
    replaceQuery: String,
    onFileNameChange: (String) -> Unit,
    onContentChange: (String) -> Unit,
    onFindQueryChange: (String) -> Unit,
    onReplaceQueryChange: (String) -> Unit,
    onExecuteReplaceAll: () -> Unit,
    onNewBlankConfig: () -> Unit,
    onFormatJson: () -> Unit,
    onRevertToOriginal: () -> Unit,
    onSaveEditedCopyLocally: () -> Unit,
    onExportToStorage: (ByteArray, String) -> Unit,
    onLockToEncryptedDark: (String) -> Unit,
    onApplyToVpnModule: () -> Unit,
    onShowMessage: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    val syntaxTransformation = remember { ConfigSyntaxHighlightTransformation() }
    var showFindReplaceBar by remember { mutableStateOf(false) }
    var lockPassword by remember { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("editor_screen"),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.Edit,
                title = "Config Code Editor",
                subtitle = "Syntax-highlighted JSON & HTTP payload editor with immutable backup preservation"
            )
        }

        // Toolbar Card
        item {
            CyberCard(accentColor = NeonCyan) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = fileName,
                        onValueChange = onFileNameChange,
                        label = { Text("Working File Name (Saved Separately)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("editor_filename_input")
                    )
                    OutlinedButton(
                        onClick = onNewBlankConfig,
                        border = BorderStroke(1.dp, NeonGreen),
                        modifier = Modifier.testTag("editor_new_scratch_button")
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("New", color = NeonGreen)
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    OutlinedButton(
                        onClick = { showFindReplaceBar = !showFindReplaceBar },
                        modifier = Modifier.weight(1f).testTag("editor_toggle_find_button")
                    ) {
                        Icon(Icons.Default.FindReplace, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Find/Replace", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = onFormatJson,
                        modifier = Modifier.weight(1f).testTag("editor_format_json_button")
                    ) {
                        Icon(Icons.Default.FormatAlignLeft, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Format JSON", style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = onRevertToOriginal,
                        modifier = Modifier.weight(1f).testTag("editor_revert_button")
                    ) {
                        Icon(Icons.Default.Restore, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Revert", style = MaterialTheme.typography.labelMedium)
                    }
                }

                if (showFindReplaceBar) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = findQuery,
                            onValueChange = onFindQueryChange,
                            label = { Text("Find") },
                            singleLine = true,
                            modifier = Modifier.weight(1f).testTag("editor_find_input")
                        )
                        OutlinedTextField(
                            value = replaceQuery,
                            onValueChange = onReplaceQueryChange,
                            label = { Text("Replace With") },
                            singleLine = true,
                            modifier = Modifier.weight(1f).testTag("editor_replace_input")
                        )
                        Button(
                            onClick = onExecuteReplaceAll,
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                            modifier = Modifier.testTag("editor_replace_all_button")
                        ) {
                            Text("Replace", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }

        // Syntax Highlighted Code Editor Field
        item {
            CyberCard(accentColor = NeonGreen) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Configuration Buffer (${editorContent.lines().size} lines • ${editorContent.length} chars)",
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelMedium,
                        color = NeonCyan
                    )
                    Text(
                        text = "Original Preserved",
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelMedium,
                        color = NeonGreen
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = editorContent,
                    onValueChange = onContentChange,
                    textStyle = TextStyle(
                        fontFamily = JetBrainsMonoFontFamily,
                        fontSize = 13.sp,
                        lineHeight = 19.sp
                    ),
                    visualTransformation = syntaxTransformation,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
                    minLines = 12,
                    maxLines = 22,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = Color(0xFF060A12),
                        unfocusedContainerColor = Color(0xFF060A12),
                        focusedTextColor = Color(0xFFE2E8F0),
                        unfocusedTextColor = Color(0xFFE2E8F0),
                        focusedBorderColor = NeonCyan,
                        unfocusedBorderColor = NeonCyan.copy(alpha = 0.35f)
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("editor_code_textfield")
                )

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            clipboard.setText(AnnotatedString(editorContent))
                            onShowMessage("Copied editor buffer to clipboard.")
                        },
                        modifier = Modifier.weight(1f).testTag("editor_copy_button")
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Copy")
                    }
                    Button(
                        onClick = onSaveEditedCopyLocally,
                        colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                        modifier = Modifier.weight(1f).testTag("editor_save_copy_button")
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Save Copy", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = {
                            onExportToStorage(
                                editorContent.toByteArray(Charsets.UTF_8),
                                fileName.ifBlank { "edited_config.json" }
                            )
                        },
                        border = BorderStroke(1.dp, NeonCyan),
                        modifier = Modifier.weight(1f).testTag("editor_export_button")
                    ) {
                        Icon(Icons.Default.SaveAlt, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Export", color = NeonCyan)
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Button(
                    onClick = onApplyToVpnModule,
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                    modifier = Modifier.fillMaxWidth().testTag("editor_apply_to_vpn_button")
                ) {
                    Icon(Icons.Default.VpnLock, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Load into VPN Connection Module", fontWeight = FontWeight.Bold)
                }
            }
        }

        // Lock & Encrypt Editor Content into .dark Container
        item {
            CyberCard(accentColor = ElectricAmber) {
                Text(
                    text = "Lock & Seal as Encrypted .dark Container",
                    style = MaterialTheme.typography.titleMedium,
                    color = ElectricAmber
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Encrypt the current editor buffer with AES-256-GCM + PBKDF2-HMAC-SHA256 to create a locked .dark container for distribution or unlocking verification.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = lockPassword,
                        onValueChange = { lockPassword = it },
                        label = { Text("Encryption Password") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("editor_lock_password_input")
                    )
                    Button(
                        onClick = { onLockToEncryptedDark(lockPassword) },
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricAmber, contentColor = ObsidianDeep),
                        modifier = Modifier.testTag("editor_lock_container_button")
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Lock .dark", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
