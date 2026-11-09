package com.escudo.security

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        Blocklist.load(this); Blocklist.loadAllow(this); Signatures.load(this); Prefs.load(this)
        if (Build.VERSION.SDK_INT >= 33)
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}.launch(Manifest.permission.POST_NOTIFICATIONS)
        // si las protecciones estaban activadas, volver a levantar el servicio
        if ((Stats.realtime || Stats.adblock) && VpnService.prepare(this) == null) startVpn(this)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Accent, background = Bg0, surface = CardBg,
                    onSurface = TextMain, onBackground = TextMain, onPrimary = Color.White
                )
            ) { App() }
        }
    }
}

// ---- Paleta ----
private val Bg0 = Color(0xFF07111F)
private val Bg1 = Color(0xFF0C2140)
private val CardBg = Color(0xFF10233F)
private val CardBorder = Color(0xFF1F3659)
private val TextMain = Color(0xFFF2F6FC)
private val TextMuted = Color(0xFF8FA3BF)
private val Accent = Color(0xFF3D8BFF)
private val Green = Color(0xFF2ECC71)
private val Red = Color(0xFFFF5A5F)
private val Amber = Color(0xFFFFB020)

private fun startVpn(c: Context) { c.startService(Intent(c, AdBlockVpnService::class.java)) }
private fun stopVpn(c: Context) {
    c.startService(Intent(c, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_STOP))
}

@Composable
fun App() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var results by remember { mutableStateOf<List<AppRisk>?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var updating by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("") }
    var revert by remember { mutableStateOf<(() -> Unit)?>(null) }

    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startVpn(ctx) else revert?.invoke()
    }

    // cambia el estado de las dos protecciones (comparten el mismo VPN local)
    val change: (Boolean, Boolean) -> Unit = { rt, ad ->
        val oldRt = Stats.realtime; val oldAd = Stats.adblock
        Prefs.save(ctx, rt, ad)
        if (rt || ad) {
            val i = VpnService.prepare(ctx)
            if (i != null) { revert = { Prefs.save(ctx, oldRt, oldAd) }; vpnPermission.launch(i) } else startVpn(ctx)
        } else stopVpn(ctx)
    }

    val scan: () -> Unit = {
        scope.launch {
            scanning = true
            results = withContext(Dispatchers.Default) { AppScanner.scan(ctx) }
            scanning = false
        }
    }

    Surface(color = Color.Transparent, contentColor = TextMain) {
        Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Bg1, Bg0)))) {
            Column(
                Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()
                    .verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Header()
                HeroCard(results, scanning, scan)

                SectionLabel("PROTECCIÓN")
                ProtectionCard(
                    icon = Icons.Default.Lock,
                    title = "Protección en tiempo real",
                    subtitle = "Analiza cada app nueva y bloquea sitios de phishing y malware.",
                    value = Stats.threats, valueLabel = "sitios peligrosos bloqueados",
                    checked = Stats.realtime,
                    onChange = { change(it, Stats.adblock) }
                )
                ProtectionCard(
                    icon = Icons.Default.Close,
                    title = "Bloqueador de anuncios",
                    subtitle = "Elimina anuncios y rastreadores en tus apps y en el navegador.",
                    value = Stats.ads, valueLabel = "anuncios y rastreadores bloqueados",
                    checked = Stats.adblock,
                    onChange = { change(Stats.realtime, it) }
                )

                SectionLabel("LISTA BLANCA")
                AllowListCard()

                OutlinedButton(
                    onClick = {
                        scope.launch {
                            updating = true
                            val ok = withContext(Dispatchers.IO) { Blocklist.update(ctx) && Signatures.update(ctx) }
                            msg = if (ok) "Listas actualizadas correctamente" else "No se pudo descargar alguna lista"
                            updating = false
                        }
                    },
                    enabled = !updating,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, CardBorder),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextMain),
                    modifier = Modifier.fillMaxWidth().height(48.dp)
                ) {
                    Icon(Icons.Default.Refresh, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(if (updating) "Descargando…" else "Actualizar listas de amenazas")
                }
                if (msg.isNotEmpty()) {
                    Text(msg, fontSize = 12.sp, color = TextMuted, modifier = Modifier.align(Alignment.CenterHorizontally))
                }

                Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(top = 4.dp)) {
                    Icon(Icons.Default.Info, null, tint = TextMuted, modifier = Modifier.size(16.dp).padding(top = 2.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "Usa un VPN local que solo filtra consultas DNS: tu tráfico no pasa por servidores nuestros. " +
                            "Si tenés «DNS privado» activo en Ajustes, desactivalo para que el filtro funcione.",
                        fontSize = 12.sp, lineHeight = 17.sp, color = TextMuted
                    )
                }
            }
        }
    }
}

@Composable
private fun Header() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(42.dp).clip(RoundedCornerShape(12.dp))
                .background(Brush.linearGradient(listOf(Accent, Color(0xFF2358C6)))),
            contentAlignment = Alignment.Center
        ) { Icon(Icons.Default.Lock, null, tint = Color.White, modifier = Modifier.size(22.dp)) }
        Spacer(Modifier.width(12.dp))
        Column {
            Text("Escudo", fontSize = 22.sp, fontWeight = FontWeight.Bold)
            Text("Seguridad para tu celular", fontSize = 12.sp, color = TextMuted)
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.5.sp,
        color = TextMuted, modifier = Modifier.padding(top = 6.dp, start = 4.dp)
    )
}

@Composable
private fun HeroCard(results: List<AppRisk>?, scanning: Boolean, onScan: () -> Unit) {
    var detail by remember { mutableStateOf(false) }
    val risky = results?.filter { it.level != Level.LOW }
    val target = when { risky == null -> Amber; risky.isEmpty() -> Green; else -> Red }
    val color by animateColorAsState(target, label = "status")
    val title = when {
        scanning -> "Analizando tu dispositivo…"
        risky == null -> "Sin analizar"
        risky.isEmpty() -> "Todo en orden"
        else -> "${risky.size} ${if (risky.size == 1) "elemento" else "elementos"} para revisar"
    }
    val n = results?.size ?: 0
    val subtitle = when {
        scanning -> "Esto puede tardar unos segundos"
        results == null -> "Hacé un análisis para conocer el estado de tu dispositivo"
        risky!!.isEmpty() -> "$n apps analizadas, sin amenazas"
        else -> "$n apps analizadas"
    }
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(28.dp)).background(CardBg)
            .border(1.dp, CardBorder, RoundedCornerShape(28.dp)).padding(22.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            Modifier.size(116.dp).clip(CircleShape)
                .background(Brush.radialGradient(listOf(color.copy(alpha = 0.28f), color.copy(alpha = 0.04f))))
                .border(3.dp, color, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                if (risky != null && risky.isNotEmpty()) Icons.Default.Warning else Icons.Default.CheckCircle,
                null, tint = color, modifier = Modifier.size(56.dp)
            )
        }
        Spacer(Modifier.height(16.dp))
        Text(title, fontSize = 21.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        Text(subtitle, fontSize = 13.sp, color = TextMuted)

        if (risky != null && risky.isNotEmpty() && !scanning) {
            Spacer(Modifier.height(16.dp))
            Column(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Bg0.copy(alpha = 0.55f)).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                risky.groupBy { it.type }.entries.sortedByDescending { it.value.size }.forEach { (type, list) ->
                    val worst = if (list.any { it.level == Level.HIGH }) Red else Amber
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(worst))
                        Spacer(Modifier.width(10.dp))
                        Text(type, Modifier.weight(1f), fontSize = 14.sp)
                        Text(list.size.toString(), fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = worst)
                    }
                }
            }
            TextButton(onClick = { detail = !detail }) {
                Text(if (detail) "Ocultar detalle" else "Ver detalle", color = Accent)
            }
            if (detail) {
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    risky.forEach { r ->
                        val c = if (r.level == Level.HIGH) Red else Amber
                        Column(
                            Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp))
                                .background(Bg0.copy(alpha = 0.55f)).padding(12.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(r.name, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                                    Text(r.type, fontSize = 12.sp, color = c)
                                }
                                Text("${r.level.label} · ${r.score}", fontSize = 12.sp, color = c)
                            }
                            r.reasons.forEach {
                                Text("• $it", fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(top = 3.dp))
                            }
                        }
                    }
                }
            }
        }

        if (scanning) LinearProgressIndicator(
            Modifier.fillMaxWidth().padding(top = 18.dp).clip(RoundedCornerShape(50)),
            color = Accent, trackColor = CardBorder
        )

        Spacer(Modifier.height(20.dp))
        Button(
            onClick = onScan, enabled = !scanning, shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color.White,
                disabledContainerColor = CardBorder, disabledContentColor = TextMuted),
            modifier = Modifier.fillMaxWidth().height(54.dp)
        ) {
            Icon(Icons.Default.Search, null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text(if (scanning) "Analizando…" else "Analizar ahora", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun ProtectionCard(
    icon: ImageVector, title: String, subtitle: String, value: Int, valueLabel: String,
    checked: Boolean, onChange: (Boolean) -> Unit
) {
    val tint by animateColorAsState(if (checked) Green else TextMuted, label = "tint")
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(CardBg)
            .border(1.dp, if (checked) Green.copy(alpha = 0.45f) else CardBorder, RoundedCornerShape(22.dp))
            .padding(18.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(tint.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) { Icon(icon, null, tint = tint, modifier = Modifier.size(26.dp)) }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(3.dp))
                Text(
                    if (checked) "ACTIVA" else "APAGADA", fontSize = 11.sp, fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp, color = tint
                )
            }
            Switch(
                checked = checked, onCheckedChange = onChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White, checkedTrackColor = Green,
                    uncheckedThumbColor = TextMuted, uncheckedTrackColor = Bg0, uncheckedBorderColor = CardBorder
                )
            )
        }
        Spacer(Modifier.height(12.dp))
        Text(subtitle, fontSize = 13.sp, lineHeight = 18.sp, color = TextMuted)
        Spacer(Modifier.height(14.dp))
        HorizontalDivider(color = CardBorder)
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.Bottom) {
            Text(value.toString(), fontSize = 26.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(8.dp))
            Text(valueLabel, fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(bottom = 4.dp))
        }
    }
}

@Composable
private fun AllowListCard() {
    val ctx = LocalContext.current
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(CardBg)
            .border(1.dp, CardBorder, RoundedCornerShape(22.dp)).padding(18.dp)
    ) {
        Text("Sitios permitidos", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        Text(
            "Si un sitio o una app deja de funcionar, agregá su dominio acá y nunca se va a bloquear.",
            fontSize = 13.sp, lineHeight = 18.sp, color = TextMuted
        )
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = text, onValueChange = { text = it; error = false },
                singleLine = true, isError = error, shape = RoundedCornerShape(12.dp),
                placeholder = { Text("ejemplo.com") },
                supportingText = { if (error) Text("Escribí un dominio válido") },
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(10.dp))
            Button(
                onClick = { if (Blocklist.addAllow(ctx, text)) text = "" else error = true },
                shape = RoundedCornerShape(12.dp), modifier = Modifier.height(56.dp)
            ) { Icon(Icons.Default.Add, "Agregar") }
        }
        Blocklist.allowList.forEach { d ->
            Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.CheckCircle, null, tint = Green, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(10.dp))
                Text(d, Modifier.weight(1f), fontSize = 14.sp)
                IconButton(onClick = { Blocklist.removeAllow(ctx, d) }) {
                    Icon(Icons.Default.Close, "Quitar", tint = TextMuted)
                }
            }
        }
    }
}
