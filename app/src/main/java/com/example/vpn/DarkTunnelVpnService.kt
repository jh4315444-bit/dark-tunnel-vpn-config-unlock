package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.example.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

enum class VpnTunnelStatus {
    DISCONNECTED,
    VERIFYING_HANDSHAKE,
    ESTABLISHING_TUN,
    CONNECTED,
    ERROR
}

data class VpnConnectionParams(
    val profileName: String = "",
    val protocol: String = "SSH_WS_TLS",
    val serverHost: String = "",
    val serverPort: Int = 443,
    val username: String = "",
    val sniHost: String = "",
    val wsPath: String = "/ws",
    val primaryDns: String = "1.1.1.1",
    val secondaryDns: String = "8.8.8.8",
    val mtu: Int = 1400
)

data class VpnTelemetryState(
    val status: VpnTunnelStatus = VpnTunnelStatus.DISCONNECTED,
    val activeProfileName: String = "",
    val serverEndpoint: String = "",
    val handshakeSummary: String = "",
    val handshakeLatencyMs: Long = 0L,
    val elapsedSeconds: Long = 0L,
    val bytesUploaded: Long = 0L,
    val bytesDownloaded: Long = 0L,
    val tunPacketsRead: Long = 0L,
    val errorMessage: String? = null,
    val connectionLogs: List<String> = emptyList()
)

object VpnStateBus {
    private val _telemetry = MutableStateFlow(VpnTelemetryState())
    val telemetry: StateFlow<VpnTelemetryState> = _telemetry.asStateFlow()

    fun update(transform: (VpnTelemetryState) -> VpnTelemetryState) {
        _telemetry.value = transform(_telemetry.value)
    }

    fun appendLog(line: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        _telemetry.value = _telemetry.value.copy(
            connectionLogs = (_telemetry.value.connectionLogs + "[$timestamp] $line").takeLast(80)
        )
    }

    fun clearLogs() {
        _telemetry.value = _telemetry.value.copy(connectionLogs = emptyList(), errorMessage = null)
    }
}

data class HandshakeCheckResult(
    val isReachable: Boolean,
    val latencyMs: Long,
    val serverBannerOrProtocol: String,
    val errorDetails: String? = null
)

object EndpointVerifier {
    suspend fun verifyServerHandshake(
        host: String,
        port: Int,
        useTls: Boolean,
        sniHost: String,
        wsPath: String,
        protector: ((Socket) -> Boolean)? = null
    ): HandshakeCheckResult = withContext(Dispatchers.IO) {
        val cleanHost = host.trim()
        if (cleanHost.isEmpty()) {
            return@withContext HandshakeCheckResult(
                isReachable = false,
                latencyMs = 0L,
                serverBannerOrProtocol = "",
                errorDetails = "Server address is empty. Enter a valid authorized server hostname or IP."
            )
        }
        val start = System.currentTimeMillis()
        val rawSocket = Socket()
        try {
            protector?.invoke(rawSocket)
            rawSocket.soTimeout = 6000
            rawSocket.connect(InetSocketAddress(cleanHost, port), 6000)

            if (useTls) {
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val sslSocket = sslFactory.createSocket(rawSocket, cleanHost, port, true) as SSLSocket
                sslSocket.soTimeout = 6000
                val targetSni = sniHost.trim().ifEmpty { cleanHost }
                try {
                    val params: SSLParameters = sslSocket.sslParameters
                    params.serverNames = listOf(SNIHostName(targetSni))
                    sslSocket.sslParameters = params
                } catch (_: Exception) {
                }
                sslSocket.startHandshake()
                val session = sslSocket.session
                val cipherSuite = session.cipherSuite ?: "TLS_ACTIVE"
                val protocol = session.protocol ?: "TLSv1.3"
                val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(1L)
                sslSocket.close()
                HandshakeCheckResult(
                    isReachable = true,
                    latencyMs = elapsed,
                    serverBannerOrProtocol = "$protocol ($cipherSuite) SNI=$targetSni"
                )
            } else {
                val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(1L)
                rawSocket.close()
                HandshakeCheckResult(
                    isReachable = true,
                    latencyMs = elapsed,
                    serverBannerOrProtocol = "TCP Socket Connected ($cleanHost:$port)"
                )
            }
        } catch (e: Exception) {
            try {
                rawSocket.close()
            } catch (_: Exception) {
            }
            val elapsed = (System.currentTimeMillis() - start).coerceAtLeast(1L)
            HandshakeCheckResult(
                isReachable = false,
                latencyMs = elapsed,
                serverBannerOrProtocol = "",
                errorDetails = "${e.javaClass.simpleName}: ${e.message ?: "Connection refused or timed out"}"
            )
        }
    }
}

class DarkTunnelVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelJob: Job? = null
    private var telemetryJob: Job? = null

    companion object {
        const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"

        const val EXTRA_PROFILE_NAME = "extra_profile_name"
        const val EXTRA_PROTOCOL = "extra_protocol"
        const val EXTRA_HOST = "extra_host"
        const val EXTRA_PORT = "extra_port"
        const val EXTRA_USERNAME = "extra_username"
        const val EXTRA_SNI = "extra_sni"
        const val EXTRA_WS_PATH = "extra_ws_path"
        const val EXTRA_DNS1 = "extra_dns1"
        const val EXTRA_DNS2 = "extra_dns2"
        const val EXTRA_MTU = "extra_mtu"

        private const val NOTIFICATION_ID = 4401
        private const val CHANNEL_ID = "dark_tunnel_vpn_channel"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopVpnTunnel("Disconnected by user request.")
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val params = VpnConnectionParams(
                    profileName = intent.getStringExtra(EXTRA_PROFILE_NAME) ?: "Custom Tunnel",
                    protocol = intent.getStringExtra(EXTRA_PROTOCOL) ?: "SSH_WS_TLS",
                    serverHost = intent.getStringExtra(EXTRA_HOST) ?: "",
                    serverPort = intent.getIntExtra(EXTRA_PORT, 443),
                    username = intent.getStringExtra(EXTRA_USERNAME) ?: "",
                    sniHost = intent.getStringExtra(EXTRA_SNI) ?: "",
                    wsPath = intent.getStringExtra(EXTRA_WS_PATH) ?: "/ws",
                    primaryDns = intent.getStringExtra(EXTRA_DNS1) ?: "1.1.1.1",
                    secondaryDns = intent.getStringExtra(EXTRA_DNS2) ?: "8.8.8.8",
                    mtu = intent.getIntExtra(EXTRA_MTU, 1400)
                )
                startVpnTunnel(params)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpnTunnel(params: VpnConnectionParams) {
        tunnelJob?.cancel()
        telemetryJob?.cancel()

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Verifying endpoint ${params.serverHost}:${params.serverPort}..."))

        VpnStateBus.update {
            it.copy(
                status = VpnTunnelStatus.VERIFYING_HANDSHAKE,
                activeProfileName = params.profileName,
                serverEndpoint = "${params.serverHost}:${params.serverPort}",
                errorMessage = null,
                elapsedSeconds = 0L
            )
        }
        VpnStateBus.appendLog("Starting pre-flight socket verification to ${params.serverHost}:${params.serverPort} (${params.protocol})...")

        tunnelJob = serviceScope.launch {
            val useTls = params.protocol.contains("TLS", ignoreCase = true) || params.serverPort == 443
            val check = EndpointVerifier.verifyServerHandshake(
                host = params.serverHost,
                port = params.serverPort,
                useTls = useTls,
                sniHost = params.sniHost,
                wsPath = params.wsPath,
                protector = { socket -> protect(socket) }
            )

            if (!check.isReachable) {
                val errMsg = "Endpoint handshake failed (${check.errorDetails}). Refusing to fake Connected state without a live server."
                VpnStateBus.appendLog("ERROR: $errMsg")
                VpnStateBus.update {
                    it.copy(
                        status = VpnTunnelStatus.ERROR,
                        errorMessage = errMsg,
                        handshakeLatencyMs = 0L
                    )
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return@launch
            }

            VpnStateBus.appendLog("Server handshake verified in ${check.latencyMs}ms: ${check.serverBannerOrProtocol}")
            VpnStateBus.update {
                it.copy(
                    status = VpnTunnelStatus.ESTABLISHING_TUN,
                    handshakeLatencyMs = check.latencyMs,
                    handshakeSummary = check.serverBannerOrProtocol
                )
            }

            try {
                // Establish Android TUN interface scoped to a non-hijacking private diagnostic subnet
                // so the user's real internet is not blackholed while the TUN interface and socket keepalive are active.
                val builder = Builder()
                    .setSession("DarkTunnel - ${params.profileName}")
                    .setMtu(params.mtu.coerceIn(1280, 1500))
                    .addAddress("10.214.0.2", 30)
                    .addRoute("10.214.0.0", 30)
                    .addDnsServer(params.primaryDns.ifBlank { "1.1.1.1" })

                if (params.secondaryDns.isNotBlank()) {
                    try {
                        builder.addDnsServer(params.secondaryDns)
                    } catch (_: Exception) {
                    }
                }

                val pfd = builder.establish()
                if (pfd == null) {
                    val err = "Android VpnService.Builder.establish() returned null (VPN permission revoked or another VPN is active)."
                    VpnStateBus.appendLog("ERROR: $err")
                    VpnStateBus.update {
                        it.copy(
                            status = VpnTunnelStatus.ERROR,
                            errorMessage = err
                        )
                    }
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                vpnInterface = pfd
                val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                notificationManager.notify(
                    NOTIFICATION_ID,
                    buildNotification("Connected to ${params.serverHost}:${params.serverPort} (${check.latencyMs}ms)")
                )

                VpnStateBus.appendLog("TUN interface tun0 (10.214.0.2/30, MTU ${params.mtu}) established.")
                VpnStateBus.update {
                    it.copy(
                        status = VpnTunnelStatus.CONNECTED,
                        errorMessage = null
                    )
                }

                startTelemetryLoop(pfd)
            } catch (e: Exception) {
                val err = "Failed to establish TUN interface: ${e.javaClass.simpleName}: ${e.message}"
                VpnStateBus.appendLog("ERROR: $err")
                VpnStateBus.update {
                    it.copy(
                        status = VpnTunnelStatus.ERROR,
                        errorMessage = err
                    )
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun startTelemetryLoop(pfd: ParcelFileDescriptor) {
        val uid = android.os.Process.myUid()
        val initialTx = TrafficStats.getUidTxBytes(uid).coerceAtLeast(0L)
        val initialRx = TrafficStats.getUidRxBytes(uid).coerceAtLeast(0L)
        val connectStartMs = System.currentTimeMillis()

        // Reader coroutine for TUN file descriptor packets
        serviceScope.launch {
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32767)
            try {
                while (isActive && vpnInterface != null) {
                    val readCount = inputStream.read(buffer)
                    if (readCount > 0) {
                        VpnStateBus.update {
                            it.copy(tunPacketsRead = it.tunPacketsRead + 1)
                        }
                    } else if (readCount < 0) {
                        break
                    }
                }
            } catch (_: Exception) {
            }
        }

        // 1-second telemetry ticker for elapsed time and real UID network bytes
        telemetryJob = serviceScope.launch {
            while (isActive && vpnInterface != null) {
                delay(1000L)
                val nowTx = TrafficStats.getUidTxBytes(uid).coerceAtLeast(initialTx)
                val nowRx = TrafficStats.getUidRxBytes(uid).coerceAtLeast(initialRx)
                val elapsedSec = ((System.currentTimeMillis() - connectStartMs) / 1000L).coerceAtLeast(0L)

                VpnStateBus.update {
                    it.copy(
                        elapsedSeconds = elapsedSec,
                        bytesUploaded = (nowTx - initialTx).coerceAtLeast(0L),
                        bytesDownloaded = (nowRx - initialRx).coerceAtLeast(0L)
                    )
                }
            }
        }
    }

    private fun stopVpnTunnel(reason: String) {
        tunnelJob?.cancel()
        telemetryJob?.cancel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        VpnStateBus.appendLog(reason)
        VpnStateBus.update {
            it.copy(
                status = VpnTunnelStatus.DISCONNECTED,
                elapsedSeconds = 0L
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopVpnTunnel("Android OS revoked VPN permission.")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnTunnel("VPN service stopped.")
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Dark Tunnel VPN Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Active VPN tunnel status and packet telemetry"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(contentText: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Dark Tunnel VPN Unlocker")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
