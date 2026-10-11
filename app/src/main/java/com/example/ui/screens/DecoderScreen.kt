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
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.crypto.DecodeOperationResult
import com.example.ui.components.CodePreviewBox
import com.example.ui.components.CyberCard
import com.example.ui.components.SectionHeader
import com.example.ui.components.StatusBadge
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import com.example.viewmodel.WorkbenchDestination

@Composable
fun DecoderScreen(
    inputText: String,
    decodeResult: DecodeOperationResult?,
    onInputChange: (String) -> Unit,
    onExecuteDecode: () -> Unit,
    onLoadSampleEncoded: () -> Unit,
    onSendToEditor: () -> Unit,
    onExportDecoded: (String) -> Unit,
    onApplyToVpn: (String) -> Unit,
    onNavigate: (WorkbenchDestination) -> Unit,
    onShowMessage: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("decoder_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.Code,
                title = "Config Decoder",
                subtitle = "Deep Unpacker for Base64, Hex, GZIP/ZLIB & VPN URIs into Clear Readable Text"
            )
        }

        // Encoded Input Card
        item {
            CyberCard(accentColor = NeonCyan) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Encoded / Raw Config Input",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    OutlinedButton(
                        onClick = onLoadSampleEncoded,
                        border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                        modifier = Modifier.testTag("decoder_load_sample_button")
                    ) {
                        Text("Load VMess Sample", color = NeonCyan, style = MaterialTheme.typography.labelMedium)
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = inputText,
                    onValueChange = onInputChange,
                    label = { Text("Paste Base64, Hex, or vmess:// / vless:// / darktunnel:// / ssh:// URI") },
                    minLines = 4,
                    maxLines = 8,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("decoder_input_field")
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = onExecuteDecode,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonCyan,
                        contentColor = ObsidianDeep
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                        .testTag("execute_decode_button")
                ) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Decode & Show All Clear Parameters", fontWeight = FontWeight.Bold)
                }
            }
        }

        // Decode Result Card with Clear Parameter Inspector Table
        if (decodeResult != null) {
            item {
                val accent = when {
                    decodeResult.isEncryptedAndNeedsKey -> ElectricAmber
                    decodeResult.isSuccessful -> NeonGreen
                    else -> CrimsonError
                }

                CyberCard(accentColor = accent) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Clear Decoded Config Inspector",
                                style = MaterialTheme.typography.titleLarge,
                                color = accent
                            )
                            Text(
                                text = decodeResult.detectedFormatSummary,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        StatusBadge(
                            text = when {
                                decodeResult.isEncryptedAndNeedsKey -> "KEY REQUIRED"
                                decodeResult.isSuccessful -> "CLEAR & READABLE"
                                else -> "UNRECOGNIZED"
                            },
                            color = accent
                        )
                    }

                    if (decodeResult.isEncryptedAndNeedsKey) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "This file is an AES-256 encrypted container. Open the Config Unlocker and enter the decryption password to reveal all clear fields.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = ElectricAmber
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            onClick = { onNavigate(WorkbenchDestination.UNLOCKER) },
                            colors = ButtonDefaults.buttonColors(containerColor = ElectricAmber, contentColor = ObsidianDeep),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Go to Config Unlocker", fontWeight = FontWeight.Bold)
                        }
                    }

                    // 1. Clean Formatted JSON Code Viewer right at the top
                    Spacer(modifier = Modifier.height(14.dp))
                    Text(
                        text = "Decoded Clean JSON Configuration:",
                        style = MaterialTheme.typography.titleMedium,
                        color = NeonGreen
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    CodePreviewBox(
                        code = decodeResult.formattedInspectorReport.ifBlank { decodeResult.finalOutput },
                        modifier = Modifier.testTag("decoded_output_box")
                    )

                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(decodeResult.formattedInspectorReport.ifBlank { decodeResult.finalOutput }))
                                onShowMessage("Copied clean JSON configuration to clipboard.")
                            },
                            modifier = Modifier.weight(1f).testTag("decoder_copy_button")
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Copy JSON")
                        }
                        OutlinedButton(
                            onClick = { onExportDecoded(decodeResult.finalOutput) },
                            modifier = Modifier.weight(1f).testTag("decoder_export_button")
                        ) {
                            Icon(Icons.Default.SaveAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Save As")
                        }
                        Button(
                            onClick = onSendToEditor,
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                            modifier = Modifier.weight(1f).testTag("decoder_open_editor_button")
                        ) {
                            Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Editor", fontWeight = FontWeight.Bold)
                        }
                    }

                    // 2. Clear Extracted Configuration Parameters Table
                    if (decodeResult.parsedFields.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = "Unlocked / Decoded VPN Settings (Tap to Copy):",
                            style = MaterialTheme.typography.titleMedium,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        ClearConfigParametersTable(
                            fields = decodeResult.parsedFields,
                            onCopyValue = { label, value ->
                                clipboard.setText(AnnotatedString(value))
                                onShowMessage("Copied $label: $value")
                            }
                        )
                    }

                    // 3. Step trace
                    if (decodeResult.steps.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = "Decoding Layers Applied:",
                            style = MaterialTheme.typography.labelLarge,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        decodeResult.steps.forEach { step ->
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 3.dp)
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text(
                                        text = "Layer ${step.stepIndex}: ${step.encodingType}",
                                        fontWeight = FontWeight.Bold,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = NeonGreen
                                    )
                                    Text(
                                        text = step.summary,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }

                    if (decodeResult.isSuccessful) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Button(
                            onClick = { onApplyToVpn(decodeResult.finalOutput) },
                            colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.VpnLock, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Load Decoded Settings into VPN Connection", fontWeight = FontWeight.Bold)
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
