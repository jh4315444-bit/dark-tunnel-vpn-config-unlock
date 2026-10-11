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
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.data.OperationHistoryEntity
import com.example.data.WorkbenchSettings
import com.example.ui.components.CyberCard
import com.example.ui.components.SectionHeader
import com.example.ui.components.StatusBadge
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.ObsidianDeep
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(
    historyList: List<OperationHistoryEntity>,
    onClearHistory: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("history_screen"),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                BoxWrapper(modifier = Modifier.weight(1f)) {
                    SectionHeader(
                        icon = Icons.Default.History,
                        title = "Audit History",
                        subtitle = "Local cryptographic & tunnel operation log (No sensitive passwords logged)"
                    )
                }
                if (historyList.isNotEmpty()) {
                    OutlinedButton(
                        onClick = onClearHistory,
                        border = BorderStroke(1.dp, CrimsonError),
                        modifier = Modifier.testTag("clear_history_button")
                    ) {
                        Icon(Icons.Default.DeleteSweep, contentDescription = null, tint = CrimsonError, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Clear", color = CrimsonError)
                    }
                }
            }
        }

        if (historyList.isEmpty()) {
            item {
                CyberCard(accentColor = MaterialTheme.colorScheme.outline) {
                    Text(
                        text = "No Audit Operations Logged Yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Every file import, backup, unlock, decode, recovery test, config generation, and VPN connection attempt is recorded locally here.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            items(historyList, key = { it.id }) { item ->
                val badgeColor = when (item.status) {
                    "SUCCESS" -> NeonGreen
                    "FAILED" -> CrimsonError
                    "WARNING" -> ElectricAmber
                    else -> NeonCyan
                }
                CyberCard(accentColor = badgeColor.copy(alpha = 0.5f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            StatusBadge(text = item.category, color = NeonCyan)
                            StatusBadge(text = item.status, color = badgeColor)
                        }
                        Text(
                            text = dateFormat.format(Date(item.timestamp)),
                            fontFamily = JetBrainsMonoFontFamily,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = item.targetName,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = item.details,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun BoxWrapper(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(modifier = modifier) { content() }
}

@Composable
fun SettingsScreen(
    settings: WorkbenchSettings,
    onToggleDarkMode: (Boolean) -> Unit,
    onToggleAutoBackup: (Boolean) -> Unit,
    onToggleStrictVerification: (Boolean) -> Unit,
    onSaveNetworkSettings: (String, String, String) -> Unit
) {
    var dns1 by remember(settings.customDnsPrimary) { mutableStateOf(settings.customDnsPrimary) }
    var dns2 by remember(settings.customDnsSecondary) { mutableStateOf(settings.customDnsSecondary) }
    var mtuText by remember(settings.vpnMtu) { mutableStateOf(settings.vpnMtu.toString()) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp)
            .testTag("settings_screen"),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(4.dp))
            SectionHeader(
                icon = Icons.Default.Settings,
                title = "Workbench Settings",
                subtitle = "Appearance, automatic backups, TUN interface parameters & privacy posture"
            )
        }

        // Theme & Security Toggles
        item {
            CyberCard(accentColor = NeonCyan) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Obsidian Dark Mode Theme",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Switch between Dark Tunnel Obsidian Gradient and Clean Light Mode",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = settings.isDarkMode,
                        onCheckedChange = onToggleDarkMode,
                        modifier = Modifier.testTag("settings_dark_mode_switch")
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Automatic Immutable File Backup",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Preserve an untouched backup copy of every imported configuration before analysis or unlocking",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = settings.autoBackupBeforeProcess,
                        onCheckedChange = onToggleAutoBackup,
                        modifier = Modifier.testTag("settings_auto_backup_switch")
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Strict Socket Handshake Verification",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Verify remote TCP/TLS endpoint reachability before establishing VpnService TUN interface",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = settings.strictHostKeyVerification,
                        onCheckedChange = onToggleStrictVerification
                    )
                }
            }
        }

        // VPN TUN & DNS Settings
        item {
            CyberCard(accentColor = NeonGreen) {
                Text(
                    text = "VPN TUN Interface & DNS Parameters",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = dns1,
                        onValueChange = { dns1 = it },
                        label = { Text("Primary DNS") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("settings_dns1_input")
                    )
                    OutlinedTextField(
                        value = dns2,
                        onValueChange = { dns2 = it },
                        label = { Text("Secondary DNS") },
                        singleLine = true,
                        modifier = Modifier.weight(1f).testTag("settings_dns2_input")
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = mtuText,
                    onValueChange = { mtuText = it },
                    label = { Text("TUN Interface MTU (1280 - 1500)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("settings_mtu_input")
                )

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = { onSaveNetworkSettings(dns1, dns2, mtuText) },
                    colors = ButtonDefaults.buttonColors(containerColor = NeonGreen, contentColor = ObsidianDeep),
                    modifier = Modifier.fillMaxWidth().testTag("settings_save_network_button")
                ) {
                    Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save DNS & MTU Settings", fontWeight = FontWeight.Bold)
                }
            }
        }

        // Security & Privacy Architecture Summary
        item {
            CyberCard(accentColor = ElectricAmber) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = ElectricAmber, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Zero-Exfiltration Local Security Guarantees",
                        style = MaterialTheme.typography.titleMedium,
                        color = ElectricAmber
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "• 100% On-Device Processing: All config inspection, AES-256-GCM unlocking, Base64/Hex decoding, and PBKDF2 password recovery run locally on your device.\n" +
                        "• Credential Hygiene: Passwords and keys are never logged to Logcat or operation history.\n" +
                        "• Scoped Storage: Uses Android Storage Access Framework (SAF) with zero invasive storage permissions.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}
