package com.example.ui.components

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.crypto.ConfigFormatState
import com.example.ui.theme.CrimsonError
import com.example.ui.theme.ElectricAmber
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.NeonCyan
import com.example.ui.theme.NeonGreen
import com.example.ui.theme.VioletSyntax

@Composable
fun CyberCard(
    modifier: Modifier = Modifier,
    accentColor: Color = MaterialTheme.colorScheme.primary,
    content: @Composable () -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.92f)
        ),
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.32f)),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
}

@Composable
fun StatusBadge(
    text: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.16f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.6f))
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
        )
    }
}

@Composable
fun FormatStateBadge(state: ConfigFormatState) {
    val (label, color) = when (state) {
        ConfigFormatState.ENCRYPTED_CONTAINER -> "ENCRYPTED (KEY REQUIRED)" to ElectricAmber
        ConfigFormatState.COMPRESSED_ARCHIVE -> "COMPRESSED (GZIP)" to NeonCyan
        ConfigFormatState.ENCODED_TEXT -> "ENCODED (DECODABLE)" to NeonCyan
        ConfigFormatState.READABLE_JSON_OR_TEXT -> "READABLE PLAINTEXT" to NeonGreen
        ConfigFormatState.CORRUPTED_OR_INVALID -> "CORRUPTED / INVALID" to CrimsonError
    }
    StatusBadge(text = label, color = color)
}

@Composable
fun EntropyGaugeIndicator(
    entropy: Double,
    modifier: Modifier = Modifier
) {
    val normalized = (entropy / 8.0).coerceIn(0.0, 1.0).toFloat()
    val animatedProgress by animateFloatAsState(
        targetValue = normalized,
        animationSpec = tween(durationMillis = 700, easing = FastOutSlowInEasing),
        label = "entropy_gauge"
    )
    val gaugeColor = when {
        entropy >= 7.2 -> ElectricAmber
        entropy >= 5.2 -> NeonCyan
        else -> NeonGreen
    }

    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) {
            Canvas(modifier = Modifier.size(56.dp)) {
                drawArc(
                    color = gaugeColor.copy(alpha = 0.2f),
                    startAngle = 135f,
                    sweepAngle = 270f,
                    useCenter = false,
                    style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                )
                drawArc(
                    color = gaugeColor,
                    startAngle = 135f,
                    sweepAngle = 270f * animatedProgress,
                    useCenter = false,
                    style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                )
            }
            Text(
                text = "%.1f".format(entropy),
                style = MaterialTheme.typography.labelMedium,
                color = gaugeColor,
                fontWeight = FontWeight.Bold
            )
        }
        Column {
            Text(
                text = "Shannon Entropy: ${"%.2f".format(entropy)} / 8.00 bits",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = when {
                    entropy >= 7.2 -> "High randomness (Encrypted or Compressed)"
                    entropy >= 5.2 -> "Medium density (Base64 / Hex Encoded)"
                    else -> "Low entropy (Structured JSON / Plaintext)"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun SectionHeader(
    icon: ImageVector,
    title: String,
    subtitle: String,
    accentColor: Color = NeonCyan
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = accentColor.copy(alpha = 0.15f),
            border = BorderStroke(1.dp, accentColor.copy(alpha = 0.5f)),
            modifier = Modifier.size(44.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = accentColor,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Syntax highlighter VisualTransformation for JSON, VPN directives, and HTTP Payloads in the Config Editor.
 */
class ConfigSyntaxHighlightTransformation(
    private val keyColor: Color = NeonCyan,
    private val stringColor: Color = NeonGreen,
    private val numberBoolColor: Color = ElectricAmber,
    private val keywordColor: Color = VioletSyntax
) : VisualTransformation {

    override fun filter(text: AnnotatedString): TransformedText {
        val raw = text.text
        val annotated = buildAnnotatedString {
            append(raw)

            // Highlight JSON keys: "key":
            val keyRegex = Regex("\"([^\"]+)\"\\s*:")
            keyRegex.findAll(raw).forEach { match ->
                addStyle(
                    SpanStyle(color = keyColor, fontWeight = FontWeight.Bold),
                    match.range.first,
                    match.range.last + 1
                )
            }

            // Highlight string values: : "value"
            val strValRegex = Regex(":\\s*\"([^\"]*)\"")
            strValRegex.findAll(raw).forEach { match ->
                val quoteStart = raw.indexOf('"', match.range.first + 1)
                if (quoteStart >= 0) {
                    addStyle(
                        SpanStyle(color = stringColor),
                        quoteStart,
                        match.range.last + 1
                    )
                }
            }

            // Highlight numbers and booleans
            val numBoolRegex = Regex(":\\s*(true|false|null|-?\\d+(\\.\\d+)?)")
            numBoolRegex.findAll(raw).forEach { match ->
                val groupRange = match.groups[1]?.range
                if (groupRange != null) {
                    addStyle(
                        SpanStyle(color = numberBoolColor, fontWeight = FontWeight.Medium),
                        groupRange.first,
                        groupRange.last + 1
                    )
                }
            }

            // Highlight HTTP payload placeholders [crlf], [host], GET, CONNECT, Upgrade
            val tokenRegex = Regex("(\\[crlf\\]|\\[host\\]|\\[split\\]|GET|CONNECT|HTTP/1\\.1|Upgrade|websocket)")
            tokenRegex.findAll(raw).forEach { match ->
                addStyle(
                    SpanStyle(color = keywordColor, fontWeight = FontWeight.Bold),
                    match.range.first,
                    match.range.last + 1
                )
            }
        }
        return TransformedText(annotated, OffsetMapping.Identity)
    }
}

@Composable
fun CodePreviewBox(
    code: String,
    modifier: Modifier = Modifier
) {
    val highlighter = remember { ConfigSyntaxHighlightTransformation() }
    val cleanCode = code.trim()
    val highlighted = remember(cleanCode) {
        highlighter.filter(AnnotatedString(cleanCode)).text
    }
    val lineCount = remember(cleanCode) {
        cleanCode.lines().size.coerceAtLeast(1)
    }
    val lineNumbersText = remember(lineCount) {
        (1..lineCount).joinToString("\n") { it.toString().padStart(2, ' ') }
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF060A12),
        border = BorderStroke(1.dp, NeonCyan.copy(alpha = 0.35f))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            Text(
                text = lineNumbersText,
                fontFamily = JetBrainsMonoFontFamily,
                fontSize = 12.sp,
                lineHeight = 19.sp,
                color = NeonCyan.copy(alpha = 0.45f),
                modifier = Modifier.padding(end = 10.dp)
            )
            Box(
                modifier = Modifier
                    .weight(1f)
                    .horizontalScroll(rememberScrollState())
            ) {
                SelectionContainer {
                    Text(
                        text = highlighted,
                        fontFamily = JetBrainsMonoFontFamily,
                        fontSize = 12.5.sp,
                        lineHeight = 19.sp,
                        softWrap = false,
                        color = Color(0xFFE2E8F0)
                    )
                }
            }
        }
    }
}
