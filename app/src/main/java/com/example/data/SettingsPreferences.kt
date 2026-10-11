package com.example.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "dark_tunnel_settings")

data class WorkbenchSettings(
    val isDarkMode: Boolean = true,
    val autoBackupBeforeProcess: Boolean = true,
    val strictHostKeyVerification: Boolean = true,
    val customDnsPrimary: String = "1.1.1.1",
    val customDnsSecondary: String = "8.8.8.8",
    val vpnMtu: Int = 1400
)

class SettingsPreferences(private val context: Context) {
    private object Keys {
        val DARK_MODE = booleanPreferencesKey("dark_mode")
        val AUTO_BACKUP = booleanPreferencesKey("auto_backup")
        val STRICT_VERIFICATION = booleanPreferencesKey("strict_verification")
        val DNS_PRIMARY = stringPreferencesKey("dns_primary")
        val DNS_SECONDARY = stringPreferencesKey("dns_secondary")
        val VPN_MTU = intPreferencesKey("vpn_mtu")
    }

    val settingsFlow: Flow<WorkbenchSettings> = context.dataStore.data.map { prefs ->
        WorkbenchSettings(
            isDarkMode = prefs[Keys.DARK_MODE] ?: true,
            autoBackupBeforeProcess = prefs[Keys.AUTO_BACKUP] ?: true,
            strictHostKeyVerification = prefs[Keys.STRICT_VERIFICATION] ?: true,
            customDnsPrimary = prefs[Keys.DNS_PRIMARY] ?: "1.1.1.1",
            customDnsSecondary = prefs[Keys.DNS_SECONDARY] ?: "8.8.8.8",
            vpnMtu = prefs[Keys.VPN_MTU] ?: 1400
        )
    }

    suspend fun setDarkMode(enabled: Boolean) {
        context.dataStore.edit { it[Keys.DARK_MODE] = enabled }
    }

    suspend fun setAutoBackup(enabled: Boolean) {
        context.dataStore.edit { it[Keys.AUTO_BACKUP] = enabled }
    }

    suspend fun setStrictVerification(enabled: Boolean) {
        context.dataStore.edit { it[Keys.STRICT_VERIFICATION] = enabled }
    }

    suspend fun updateDnsAndMtu(primary: String, secondary: String, mtu: Int) {
        context.dataStore.edit {
            it[Keys.DNS_PRIMARY] = primary.ifBlank { "1.1.1.1" }
            it[Keys.DNS_SECONDARY] = secondary.ifBlank { "8.8.8.8" }
            it[Keys.VPN_MTU] = mtu.coerceIn(1280, 1500)
        }
    }
}
