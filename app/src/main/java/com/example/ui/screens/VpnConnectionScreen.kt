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
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.LinkOff
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.ui.components.CyberCard
import com.example.ui.components.SectionHeader
import com.example.ui.components.StatusBadge
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import com.example.vpn.VpnConnectionParams
import com.example.vpn.VpnStateBus
import com.example.vpn.VpnTelemetryState
import com.example.vpn.VpnTunnelStatus

@Composable
fun VpnConnectionScreen(
    params: VpnConnectionParams,
    telemetry: VpnTelemetryState,
    onUpdateParams: ((VpnConnectionParams) -> VpnConnectionParams) -> Unit,
    onRequestConnect: () -> Unit,
    onRequestDisconnect: () -> Unit
) {
    val isConnected = telemetry.status == VpnTunnelStatus.CONNECTED
    val isConnecting = telemetry.status == VpnTunnelStatus.VERIFYING_HANDSHAKE ||
        telemetry.status == VpnTunnelStatus.ESTABLISHING_TUN

    val statusColor = when (telemetry.status) {
        VpnTunnelStatus.CONNECTED -> NeonGreen
        VpnTunnelStatus.VERIFYING_HANDSHAKE, VpnTunnelStatus.ESTABLISHING_TUN -> NeonCyan
        VpnTunnelStatus.ERROR -> CrimsonError
        VpnTunnelStatus.DISCONNECTED -> ElectricAmber
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("vpn_connection_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.VpnLock,
                title = "VPN Connection Module",
                subtitle = "Android VpnService TUN Interface & Real Socket Handshake Engine"
            )
        }

        // Strict Integrity & No Fake Server Policy Card
        item {
            CyberCard(accentColor = ElectricAmber) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = ElectricAmber, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Authentic Tunnel Verification Policy",
                        style = MaterialTheme.typography.titleMedium,
                        color = ElectricAmber
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(id = R.string.vpn_disclaimer),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Live Tunnel Status & Telemetry Dashboard
        item {
            CyberCard(accentColor = statusColor) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Tunnel State",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = telemetry.status.name.replace("_", " "),
                            style = MaterialTheme.typography.headlineMedium,
                            color = statusColor,
                            modifier = Modifier.testTag("vpn_status_label")
                        )
                    }
                    if (isConnecting) {
                        CircularProgressIndicator(
                            color = NeonCyan,
                            modifier = Modifier.size(32.dp),
                            strokeWidth = 3.dp
                        )
                    } else {
                        StatusBadge(
                            text = if (isConnected) "TUN0 ESTABLISHED" else "STANDBY",
                            color = statusColor
                        )
                    }
                }

                if (telemetry.handshakeSummary.isNotBlank()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Handshake: ${telemetry.handshakeSummary} (${telemetry.handshakeLatencyMs}ms)",
                        fontFamily = JetBrainsMonoFontFamily,
                        style = MaterialTheme.typography.labelMedium,
                        color = NeonCyan
                    )
                }

                if (telemetry.errorMessage != null) {
                    Spacer(modifier = Modifier.height(10.dp))
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = CrimsonError.copy(alpha = 0.14f),
                        border = BorderStroke(1.dp, CrimsonError.copy(alpha = 0.6f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.ErrorOutline, contentDescription = null, tint = CrimsonError)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = telemetry.errorMessage,
                                style = MaterialTheme.typography.bodyMedium,
                                color = CrimsonError,
                                modifier = Modifier.testTag("vpn_error_message")
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // 3 Telemetry Tiles: Elapsed Time, Upload, Download
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TelemetryStatTile(
                        icon = Icons.Default.Timer,
                        label = "Elapsed",
                        value = formatDuration(telemetry.elapsedSeconds),
                        color = NeonCyan,
                        modifier = Modifier.weight(1f)
                    )
                    TelemetryStatTile(
                        icon = Icons.Default.CloudUpload,
                        label = "Upload",
                        value = formatByteCount(telemetry.bytesUploaded),
                        color = NeonGreen,
                        modifier = Modifier.weight(1f)
                    )
                    TelemetryStatTile(
                        icon = Icons.Default.CloudDownload,
                        label = "Download",
                        value = formatByteCount(telemetry.bytesDownloaded),
                        color = NeonCyan,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = onRequestConnect,
                        enabled = !isConnected && !isConnecting,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = NeonGreen,
                            contentColor = ObsidianDeep
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .height(52.dp)
                            .testTag("vpn_connect_button")
                    ) {
                        Icon(Icons.Default.Link, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Connect", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = onRequestDisconnect,
                        enabled = isConnected || isConnecting,
                        border = BorderStroke(1.dp, CrimsonError),
                        modifier = Modifier
                            .weight(1f)
                            .height(52.dp)
                            .testTag("vpn_disconnect_button")
                    ) {
                        Icon(Icons.Default.LinkOff, contentDescription = null, tint = CrimsonError)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Disconnect", color = CrimsonError, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Endpoint Configuration Parameters
        item {
            CyberCard(accentColor = NeonCyan) {
                Text(
                    text = "Target Authorized Server Configuration",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = params.profileName,
                    onValueChange = { v -> onUpdateParams { it.copy(profileName = v) } },
                    label = { Text("Session Profile Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("vpn_profile_name_input")
                )
                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = params.serverHost,
                        onValueChange = { v -> onUpdateParams { it.copy(serverHost = v) } },
                        label = { Text("Authorized Server Host / IP") },
                        placeholder = { Text("e.g. your-vpn.example.com") },
                        singleLine = true,
                        modifier = Modifier.weight(2f).testTag("vpn_server_host_input")
                    )
                    OutlinedTextField(
                        value = params.serverPort.toString(),
                        onValueChange = { v ->
                            val p = v.toIntOrNull() ?: 443
                            onUpdateParams { it.copy(serverPort = p) }
                        },
                        label = { Text("Port") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("vpn_server_port_input")
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = params.sniHost,
                        onValueChange = { v -> onUpdateParams { it.copy(sniHost = v) } },
                        label = { Text("TLS SNI Hostname") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("vpn_sni_input")
                    )
                    OutlinedTextField(
                        value = params.wsPath,
                        onValueChange = { v -> onUpdateParams { it.copy(wsPath = v) } },
                        label = { Text("WebSocket Path") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("vpn_ws_path_input")
                    )
                }
            }
        }

        // Live Connection & Handshake Log Console
        item {
            CyberCard(accentColor = NeonCyan.copy(alpha = 0.6f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Tunnel Handshake & VpnService Console",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    IconButton(onClick = { VpnStateBus.clearLogs() }) {
                        Icon(
                            imageVector = Icons.Default.DeleteSweep,
                            contentDescription = "Clear VPN Logs",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = Color(0xFF050811),
                    border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.25f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        if (telemetry.connectionLogs.isEmpty()) {
                            Text(
                                text = "[READY] Enter an authorized connectable server above and press Connect. Pre-flight TCP/TLS socket verification and Android VpnService permission check will execute before establishing tun0.",
                                fontFamily = JetBrainsMonoFontFamily,
                                fontSize = 12.sp,
                                color = Color(0xFF94A3B8)
                            )
                        } else {
                            telemetry.connectionLogs.forEach { logLine ->
                                val lineColor = when {
                                    logLine.contains("ERROR") -> CrimsonError
                                    logLine.contains("established") || logLine.contains("verified") -> NeonGreen
                                    else -> Color(0xFFE2E8F0)
                                }
                                Text(
                                    text = logLine,
                                    fontFamily = JetBrainsMonoFontFamily,
                                    fontSize = 11.sp,
                                    lineHeight = 16.sp,
                                    color = lineColor
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

@Composable
private fun TelemetryStatTile(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.35f))
    ) {
        Column(
            modifier = Modifier.padding(10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(imageVector = icon, contentDescription = label, tint = color, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                fontFamily = JetBrainsMonoFontFamily,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun formatDuration(seconds: Long): String {
    val hrs = seconds / 3600
    val mins = (seconds % 3600) / 60
    val secs = seconds % 60
    return "%02d:%02d:%02d".format(hrs, mins, secs)
}

private fun formatByteCount(bytes: Long): String {
    return when {
        bytes >= 1024 * 1024 -> "%.2f MB".format(bytes / (1024.0 * 1024.0))
        bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
        else -> "$bytes B"
    }
}
