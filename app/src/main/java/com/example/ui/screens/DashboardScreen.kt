package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.crypto.ConfigCryptoEngine
import com.example.data.ImportedConfigEntity
import com.example.ui.components.CyberCard
import com.example.ui.components.EntropyGaugeIndicator
import com.example.ui.components.FormatStateBadge
import com.example.ui.components.StatusBadge
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import com.example.viewmodel.ActiveFileBuffer
import com.example.viewmodel.WorkbenchDestination
import com.example.vpn.VpnTelemetryState
import com.example.vpn.VpnTunnelStatus

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DashboardScreen(
    activeBuffer: ActiveFileBuffer?,
    importedConfigs: List<ImportedConfigEntity>,
    vpnTelemetry: VpnTelemetryState,
    onLaunchFilePicker: () -> Unit,
    onLoadDiagnosticSample: (String) -> Unit,
    onSelectImportedRecord: (ImportedConfigEntity) -> Unit,
    onDeleteImportedRecord: (Int) -> Unit,
    onNavigate: (WorkbenchDestination) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("dashboard_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            // Hero Banner Card
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(176.dp)
                    .clip(RoundedCornerShape(20.dp))
            ) {
                Image(
                    painter = painterResource(id = R.drawable.img_hero_tunnel),
                    contentDescription = "Dark Tunnel Cryptographic Workbench Banner",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize()
                )
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                colors = listOf(
                                    ObsidianDeep.copy(alpha = 0.35f),
                                    ObsidianDeep.copy(alpha = 0.92f)
                                )
                            )
                        )
                        .padding(18.dp),
                    contentAlignment = Alignment.BottomStart
                ) {
                    Column {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            StatusBadge(text = "AES-256-GCM / PBKDF2", color = NeonCyan)
                            StatusBadge(
                                text = if (vpnTelemetry.status == VpnTunnelStatus.CONNECTED) "TUNNEL ACTIVE" else "TUNNEL STANDBY",
                                color = if (vpnTelemetry.status == VpnTunnelStatus.CONNECTED) NeonGreen else ElectricAmber
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Dark Tunnel Config Unlocker",
                            style = MaterialTheme.typography.headlineMedium,
                            color = Color.White
                        )
                        Text(
                            text = "Cryptographic VPN Config Inspector, Multi-Layer Decoder & Real VpnService Workbench",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color(0xFFCBD5E1)
                        )
                    }
                }
            }
        }

        // 1. Config File Importer Section
        item {
            CyberCard(accentColor = NeonCyan) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.UploadFile,
                            contentDescription = "Config File Importer",
                            tint = NeonCyan,
                            modifier = Modifier.size(26.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Config File Importer & Backup Engine",
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "Supports .dark, .hat, .ehi, .nm, .hc, .json, .ovpn, .txt",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ConfigCryptoEngine.SUPPORTED_EXTENSIONS.forEach { ext ->
                        StatusBadge(text = ".$ext", color = NeonCyan)
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                Button(
                    onClick = onLaunchFilePicker,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = NeonCyan,
                        contentColor = ObsidianDeep
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                        .testTag("import_config_button")
                ) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Import VPN Config File from Device Storage", fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "Or load a real diagnostic sample container to verify unlocking, decoding, or corruption detection:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { onLoadDiagnosticSample("ENCRYPTED_DARK") },
                        border = BorderStroke(1.dp, NeonGreen.copy(alpha = 0.6f)),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("load_sample_encrypted_button")
                    ) {
                        Text("Locked .dark", color = NeonGreen, style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { onLoadDiagnosticSample("ENCODED_VMESS") },
                        border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("load_sample_encoded_button")
                    ) {
                        Text("Encoded .ehi", color = NeonCyan, style = MaterialTheme.typography.labelMedium)
                    }
                    OutlinedButton(
                        onClick = { onLoadDiagnosticSample("CORRUPTED_SAMPLE") },
                        border = BorderStroke(1.dp, CrimsonError.copy(alpha = 0.6f)),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("load_sample_corrupted_button")
                    ) {
                        Text("Corrupted .hat", color = CrimsonError, style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
        }

        // Active File Analysis Report Card
        if (activeBuffer != null) {
            val report = activeBuffer.analysisReport
            item {
                CyberCard(accentColor = NeonGreen) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Active File Inspection",
                                style = MaterialTheme.typography.labelLarge,
                                color = NeonGreen
                            )
                            Text(
                                text = report.fileName,
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                        FormatStateBadge(state = report.formatState)
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    EntropyGaugeIndicator(entropy = report.shannonEntropy)
                    Spacer(modifier = Modifier.height(12.dp))

                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Format: .${report.extension.ifEmpty { "raw" }}  •  Size: ${report.sizeBytes} bytes",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "Signature: ${report.detectedContainerSignature}",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonCyan
                            )
                            Text(
                                text = "SHA-256: ${report.sha256Hex}",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = "Immutable Backup: ${activeBuffer.backupFilePath}",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonGreen
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = report.diagnosticMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (report.requiresPasswordKey) {
                            Button(
                                onClick = { onNavigate(WorkbenchDestination.UNLOCKER) },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                                modifier = Modifier.weight(1f).testTag("open_in_unlocker_button")
                            ) {
                                Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Unlocker", fontWeight = FontWeight.Bold)
                            }
                            OutlinedButton(
                                onClick = { onNavigate(WorkbenchDestination.PASSWORD_RECOVERY) },
                                border = BorderStroke(1.dp, ElectricAmber),
                                modifier = Modifier.weight(1f).testTag("open_in_recovery_button")
                            ) {
                                Icon(Icons.Default.Key, contentDescription = null, tint = ElectricAmber, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Recover Key", color = ElectricAmber)
                            }
                        } else if (report.canDirectDecode) {
                            Button(
                                onClick = { onNavigate(WorkbenchDestination.UNLOCKER) },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                                modifier = Modifier.weight(1f).testTag("open_in_unlocker_button")
                            ) {
                                Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("View Clean JSON", fontWeight = FontWeight.Bold)
                            }
                            Button(
                                onClick = { onNavigate(WorkbenchDestination.DECODER) },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = ObsidianDeep),
                                modifier = Modifier.weight(1f).testTag("open_in_decoder_button")
                            ) {
                                Icon(Icons.Default.Code, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Decoder", fontWeight = FontWeight.Bold)
                            }
                            OutlinedButton(
                                onClick = { onNavigate(WorkbenchDestination.EDITOR) },
                                border = BorderStroke(1.dp, NeonGreen),
                                modifier = Modifier.weight(1f).testTag("open_in_editor_button")
                            ) {
                                Icon(Icons.Default.Edit, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Editor", color = NeonGreen)
                            }
                        }
                    }
                }
            }
        }

        // Quick Navigation Grid for all Workbench Modules
        item {
            Text(
                text = "Workbench Modules",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(modifier = Modifier.height(8.dp))

            val modules = listOf(
                Triple(WorkbenchDestination.UNLOCKER, Icons.Default.LockOpen, "AES-256-GCM / PBKDF2 Unlocker"),
                Triple(WorkbenchDestination.DECODER, Icons.Default.Code, "Base64, Hex & URI Decoder"),
                Triple(WorkbenchDestination.PASSWORD_RECOVERY, Icons.Default.VpnKey, "Authorized Key Recovery"),
                Triple(WorkbenchDestination.GENERATOR, Icons.Default.Build, "SSH / WS / TLS Generator"),
                Triple(WorkbenchDestination.EDITOR, Icons.Default.Edit, "Syntax Code Editor"),
                Triple(WorkbenchDestination.VPN_CONNECTION, Icons.Default.VpnLock, "Android VpnService Tunnel")
            )

            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                modules.chunked(2).forEach { rowItems ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        rowItems.forEach { (dest, icon, desc) ->
                            Surface(
                                shape = RoundedCornerShape(14.dp),
                                color = MaterialTheme.colorScheme.surface,
                                border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.28f)),
                                modifier = Modifier
                                    .weight(1f)
                                    .clickable { onNavigate(dest) }
                                    .testTag("module_card_${dest.name.lowercase()}")
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Icon(
                                        imageVector = icon,
                                        contentDescription = dest.title,
                                        tint = NeonCyan,
                                        modifier = Modifier.size(24.dp)
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = dest.title,
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Text(
                                        text = desc,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // Imported Files & Immutable Backups List
        item {
            Text(
                text = "Imported Files & Immutable Backups (${importedConfigs.size})",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
        }

        if (importedConfigs.isEmpty()) {
            item {
                CyberCard(accentColor = MaterialTheme.colorScheme.outline) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = "No Imported Files",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(36.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No configuration files imported yet",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Import a .dark, .hat, .ehi, .nm, .hc, or .json file above, or load one of the diagnostic samples.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(importedConfigs, key = { it.id }) { record ->
                CyberCard(accentColor = NeonCyan.copy(alpha = 0.5f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = record.fileName,
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${record.algorithmSummary} • ${record.fileSizeBytes} B • Entropy ${"%.2f".format(record.shannonEntropy)}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = "SHA-256: ${record.sha256Checksum.take(24)}...",
                                fontFamily = JetBrainsMonoFontFamily,
                                style = MaterialTheme.typography.labelMedium,
                                color = NeonCyan
                            )
                        }
                        Row {
                            IconButton(
                                onClick = { onSelectImportedRecord(record) },
                                modifier = Modifier.testTag("restore_backup_${record.id}")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Restore,
                                    contentDescription = "Load Backup",
                                    tint = NeonGreen
                                )
                            }
                            IconButton(
                                onClick = { onDeleteImportedRecord(record.id) },
                                modifier = Modifier.testTag("delete_imported_${record.id}")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Delete,
                                    contentDescription = "Delete Record",
                                    tint = CrimsonError
                                )
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
