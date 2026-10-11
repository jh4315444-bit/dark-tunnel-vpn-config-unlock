package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkTunnelColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = ObsidianDeep,
    primaryContainer = SlateSurfaceElevated,
    onPrimaryContainer = NeonCyan,
    secondary = NeonGreen,
    onSecondary = ObsidianDeep,
    secondaryContainer = Color(0xFF0A2E23),
    onSecondaryContainer = NeonGreen,
    tertiary = ElectricAmber,
    onTertiary = ObsidianDeep,
    background = ObsidianDeep,
    onBackground = TextPrimaryDark,
    surface = MidnightNavy,
    onSurface = TextPrimaryDark,
    surfaceVariant = SlateSurface,
    onSurfaceVariant = TextSecondaryDark,
    outline = GlassBorder,
    error = CrimsonError,
    onError = ObsidianDeep
)

private val LightTunnelColorScheme = lightColorScheme(
    primary = DeepCyanLight,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD0F4FA),
    onPrimaryContainer = Color(0xFF00363E),
    secondary = DeepGreenLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD1FAE5),
    onSecondaryContainer = Color(0xFF003919),
    tertiary = Color(0xFFB45309),
    onTertiary = Color.White,
    background = LightBackground,
    onBackground = TextPrimaryLight,
    surface = LightSurface,
    onSurface = TextPrimaryLight,
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = TextSecondaryLight,
    outline = Color(0xFFCBD5E1),
    error = Color(0xFFDC2626),
    onError = Color.White
)

@Composable
fun DarkTunnelTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkTunnelColorScheme else LightTunnelColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
