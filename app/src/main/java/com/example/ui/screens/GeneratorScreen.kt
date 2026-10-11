package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.crypto.GeneratedConfigBundle
import com.example.crypto.GeneratorInput
import com.example.crypto.TunnelProtocol
import com.example.data.SavedTemplateEntity
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
import com.example.vpn.HandshakeCheckResult

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GeneratorScreen(
    input: GeneratorInput,
    validationErrors: List<String>,
    endpointCheck: HandshakeCheckResult?,
    generatedBundle: GeneratedConfigBundle?,
    savedTemplates: List<SavedTemplateEntity>,
    onUpdateInput: ((GeneratorInput) -> GeneratorInput) -> Unit,
    onTestEndpointReachability: () -> Unit,
    onGenerateConfig: () -> Unit,
    onLoadTemplate: (SavedTemplateEntity) -> Unit,
    onDeleteTemplate: (Int) -> Unit,
    onExportGenerated: (ByteArray, String) -> Unit,
    onShowMessage: (String) -> Unit
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("generator_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.Build,
                title = "VPN Config Generator",
                subtitle = "SSH, WebSocket, TLS (SNI) & VLESS Configuration Builder"
            )
        }

        // Distinction Notice: Template vs Tested Endpoint
        item {
            CyberCard(accentColor = ElectricAmber) {
                Text(
                    text = "No Fake Servers Policy • Template vs. Verified Endpoint",
                    style = MaterialTheme.typography.titleMedium,
                    color = ElectricAmber
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Generated configurations are marked as UNTESTED_GENERATED_TEMPLATE unless you run a live TCP/TLS socket verification against your own authorized server. Never embeds fabricated credentials or fake free-internet servers.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Protocol Selection & Parameters Form
        item {
            CyberCard(accentColor = NeonCyan) {
                Text(
                    text = "1. Select Tunnel Protocol",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TunnelProtocol.entries.forEach { proto ->
                        FilterChip(
                            selected = input.protocol == proto,
                            onClick = {
                                onUpdateInput {
                                    it.copy(
                                        protocol = proto,
                                        serverPortText = proto.defaultPort.toString()
                                    )
                                }
                            },
                            label = { Text(proto.displayName) },
                            modifier = Modifier.testTag("proto_chip_${proto.name.lowercase()}")
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                OutlinedTextField(
                    value = input.profileName,
                    onValueChange = { v -> onUpdateInput { it.copy(profileName = v) } },
                    label = { Text("Profile Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("gen_profile_name_input")
                )
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = input.serverHost,
                        onValueChange = { v -> onUpdateInput { it.copy(serverHost = v) } },
                        label = { Text("Server Address (Host/IP)") },
                        placeholder = { Text("your-server.example.com") },
                        singleLine = true,
                        modifier = Modifier.weight(2f).testTag("gen_server_host_input")
                    )
                    OutlinedTextField(
                        value = input.serverPortText,
                        onValueChange = { v -> onUpdateInput { it.copy(serverPortText = v) } },
                        label = { Text("Port") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("gen_server_port_input")
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = input.username,
                        onValueChange = { v -> onUpdateInput { it.copy(username = v) } },
                        label = { Text("Username / UUID") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("gen_username_input")
                    )
                    OutlinedTextField(
                        value = input.passwordOrUuid,
                        onValueChange = { v -> onUpdateInput { it.copy(passwordOrUuid = v) } },
                        label = { Text("Password / Auth Secret") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("gen_password_input")
                    )
                }

                if (input.protocol.requiresSni) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = input.sniHost,
                        onValueChange = { v -> onUpdateInput { it.copy(sniHost = v) } },
                        label = { Text("TLS SNI (Server Name Indication)") },
                        placeholder = { Text("cdn.your-domain.com") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("gen_sni_input")
                    )
                }

                if (input.protocol.requiresWs) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = input.wsPath,
                        onValueChange = { v -> onUpdateInput { it.copy(wsPath = v) } },
                        label = { Text("WebSocket Path (must start with /)") },
                        placeholder = { Text("/ws-tunnel") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag("gen_ws_path_input")
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = input.customHttpPayload,
                        onValueChange = { v -> onUpdateInput { it.copy(customHttpPayload = v) } },
                        label = { Text("Custom HTTP Upgrade Payload (Optional)") },
                        placeholder = { Text("Leave blank to auto-generate standard HTTP/1.1 WebSocket Upgrade header") },
                        minLines = 2,
                        maxLines = 4,
                        modifier = Modifier.fillMaxWidth().testTag("gen_payload_input")
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = input.lockWithPassword,
                    onValueChange = { v -> onUpdateInput { it.copy(lockWithPassword = v) } },
                    label = { Text("Optional: Lock .dark Container with AES-256 Password") },
                    placeholder = { Text("Leave empty for unlocked JSON only") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("gen_lock_password_input")
                )

                // Validation Errors
                if (validationErrors.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(10.dp))
                    validationErrors.forEach { err ->
                        Text(
                            text = "• $err",
                            color = CrimsonError,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.testTag("gen_validation_error")
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onTestEndpointReachability,
                        border = BorderStroke(1.dp, NeonCyan),
                        modifier = Modifier.weight(1f).height(48.dp).testTag("gen_verify_endpoint_button")
                    ) {
                        Icon(Icons.Default.NetworkCheck, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Test Server", color = NeonCyan)
                    }
                    Button(
                        onClick = onGenerateConfig,
                        colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                        modifier = Modifier.weight(1f).height(48.dp).testTag("execute_generate_button")
                    ) {
                        Icon(Icons.Default.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Generate Config", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Live Endpoint Handshake Verification Status
        if (endpointCheck != null) {
            item {
                val color = if (endpointCheck.isReachable) NeonGreen else CrimsonError
                CyberCard(accentColor = color) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (endpointCheck.isReachable) "Endpoint Verified Connectable" else "Endpoint Handshake Failed",
                            style = MaterialTheme.typography.titleMedium,
                            color = color
                        )
                        StatusBadge(
                            text = if (endpointCheck.isReachable) "TESTED (${endpointCheck.latencyMs}ms)" else "UNREACHABLE",
                            color = color
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (endpointCheck.isReachable) {
                            endpointCheck.serverBannerOrProtocol
                        } else {
                            endpointCheck.errorDetails ?: "Connection failed"
                        },
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }

        // Generated Configuration Output
        if (generatedBundle != null) {
            item {
                CyberCard(accentColor = NeonGreen) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = generatedBundle.profileName,
                                style = MaterialTheme.typography.titleLarge,
                                color = NeonGreen
                            )
                            Text(
                                text = generatedBundle.protocol.displayName,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        StatusBadge(
                            text = if (generatedBundle.isVerifiedServer) "TESTED CONNECTABLE" else "GENERATED TEMPLATE",
                            color = if (generatedBundle.isVerifiedServer) NeonGreen else ElectricAmber
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    CodePreviewBox(
                        code = generatedBundle.readableJson,
                        modifier = Modifier.testTag("generated_json_preview")
                    )

                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(generatedBundle.readableJson))
                                onShowMessage("Copied generated JSON config to clipboard.")
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Copy JSON")
                        }
                        OutlinedButton(
                            onClick = {
                                onExportGenerated(
                                    generatedBundle.readableJson.toByteArray(Charsets.UTF_8),
                                    "${generatedBundle.profileName.replace(" ", "_")}.json"
                                )
                            },
                            modifier = Modifier.weight(1f).testTag("export_generated_json_button")
                        ) {
                            Icon(Icons.Default.SaveAlt, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Export .json")
                        }
                        if (generatedBundle.encryptedDarkBytes != null) {
                            Button(
                                onClick = {
                                    onExportGenerated(
                                        generatedBundle.encryptedDarkBytes,
                                        "${generatedBundle.profileName.replace(" ", "_")}.dark"
                                    )
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                                modifier = Modifier.weight(1f).testTag("export_generated_dark_button")
                            ) {
                                Text("Export .dark", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }

        // Saved Custom Templates
        if (savedTemplates.isNotEmpty()) {
            item {
                Text(
                    text = "Saved Custom Templates (${savedTemplates.size})",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onBackground
                )
            }
            items(savedTemplates, key = { it.id }) { tpl ->
                CyberCard(accentColor = NeonCyan.copy(alpha = 0.5f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(
                                    text = tpl.name,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                StatusBadge(
                                    text = if (tpl.isVerifiedReachable) "VERIFIED" else "TEMPLATE",
                                    color = if (tpl.isVerifiedReachable) NeonGreen else ElectricAmber
                                )
                            }
                            Text(
                                text = "${tpl.protocol} • ${tpl.serverHost}:${tpl.serverPort} • User: ${tpl.username}",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Row {
                            OutlinedButton(onClick = { onLoadTemplate(tpl) }) {
                                Text("Load")
                            }
                            IconButton(onClick = { onDeleteTemplate(tpl.id) }) {
                                Icon(Icons.Default.Delete, contentDescription = "Delete Template", tint = CrimsonError)
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
