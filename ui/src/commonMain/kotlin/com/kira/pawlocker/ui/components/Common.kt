package com.kira.pawlocker.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kira.pawlocker.ui.platform.renderQrCode
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 状态胶囊。用 Tertiary / Error 容器色区分语义，而不是硬编码红黄绿 ——
 * 硬编码颜色在深色模式下会糊成一团。
 */
enum class StatusTone { Neutral, Active, Warning, Error }

@Composable
fun StatusPill(
    text: String,
    tone: StatusTone,
    modifier: Modifier = Modifier,
) {
    val scheme = MiuixTheme.colorScheme
    val (container, content) = when (tone) {
        StatusTone.Neutral -> scheme.secondaryContainer to scheme.onSecondaryContainer
        StatusTone.Active -> scheme.primaryContainer to scheme.onPrimaryContainer
        StatusTone.Warning -> scheme.tertiaryContainer to scheme.onTertiaryContainer
        StatusTone.Error -> scheme.errorContainer to scheme.onErrorContainer
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(999.dp))
            .background(container)
            .padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text(
            text = text,
            color = content,
            style = MiuixTheme.textStyles.footnote1,
            fontWeight = FontWeight.Medium,
        )
    }
}

/** 空态。图标 + 一句话 + 一个主操作。 */
@Composable
fun EmptyState(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth().padding(horizontal = 32.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MiuixTheme.colorScheme.onBackgroundVariant,
            modifier = Modifier.size(56.dp),
        )
        Spacer(Modifier.height(16.dp))
        Text(
            text = title,
            style = MiuixTheme.textStyles.title4,
            color = MiuixTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = description,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            textAlign = TextAlign.Center,
        )
        if (actionLabel != null && onAction != null) {
            Spacer(Modifier.height(20.dp))
            TextButton(
                text = actionLabel,
                onClick = onAction,
                colors = ButtonDefaults.textButtonColorsPrimary(),
            )
        }
    }
}

/** 「标签 / 值」一行，用在详情区。 */
@Composable
fun LabeledValue(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.width(96.dp),
        )
        Text(
            text = value,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
    }
}

/**
 * 二维码展示。
 *
 * Windows 端把它摆在配对页中央；Android 端用于「把这个码给别人看」的场景（暂未使用，
 * 但保留同一套渲染，避免两端出现两种观感）。
 */
@Composable
fun QrView(
    content: String,
    size: Int = 240,
    modifier: Modifier = Modifier,
) {
    val bitmap: ImageBitmap? = remember(content, size) { renderQrCode(content, size) }

    Card(modifier = modifier) {
        Box(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (bitmap != null) {
                Image(
                    bitmap = bitmap,
                    contentDescription = "配对二维码",
                    modifier = Modifier.size(size.dp).clip(RoundedCornerShape(8.dp)),
                )
            } else {
                Text(
                    text = "二维码生成失败，请使用下方的配对码手动输入",
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

/**
 * 6 位配对码的等宽展示。
 * 用较大字号 + 字间距，方便用户隔着一段距离从电脑屏幕读到手机里输。
 */
@Composable
fun PairingCodeDisplay(
    code: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        colors = top.yukonga.miuix.kmp.basic.CardDefaults.defaultColors(
            color = MiuixTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "配对码",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSecondaryContainerVariant,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = code,
                fontSize = 40.sp,
                fontWeight = FontWeight.SemiBold,
                color = MiuixTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}

/**
 * SAS（短认证串）比对条。
 *
 * 配对完成后两端显示同一组 emoji，用户肉眼扫一下就知道有没有中间人 ——
 * 这是整个配对流程里唯一需要「人眼」参与的一步，也是唯一无法被密码学替代的一步。
 */
@Composable
fun SasStrip(
    emoji: List<String>,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "请核对这里的图案与电脑屏幕上的是否一致",
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                emoji.forEach { symbol ->
                    Text(text = symbol, fontSize = 36.sp)
                }
            }
        }
    }
}

/** 统一的卡片组外壳：SmallTitle + Card，符合 Miuix 的分组约定。 */
@Composable
fun GroupCard(
    title: String? = null,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        if (title != null) {
            top.yukonga.miuix.kmp.basic.SmallTitle(text = title)
        }
        Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
            content()
        }
    }
}

/** 列表底部留白，避免最后一张卡片贴着导航栏。 */
val ListBottomPadding = PaddingValues(bottom = 24.dp)
