package com.escudo.security

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Blocklist.load(this); Signatures.load(this); Prefs.load(this)
        if (Build.VERSION.SDK_INT >= 33)
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}.launch(Manifest.permission.POST_NOTIFICATIONS)
        // si las protecciones estaban activadas, volver a levantar el servicio
        if ((Stats.realtime || Stats.adblock) && VpnService.prepare(this) == null) startVpn(this)
        setContent { MaterialTheme(colorScheme = darkColorScheme()) { App() } }
    }
}

private val Green = Color(0xFF2ECC71)
private val Red = Color(0xFFE74C3C)
private val Amber = Color(0xFFF39C12)

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

    Column(
        Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text("Escudo", fontSize = 28.sp)

        ScanCard(results, scanning, scan)

        ProtectionCard(
            icon = Icons.Default.Lock,
            title = "Protección en tiempo real",
            subtitle = "Te avisa si una app nueva es riesgosa y bloquea sitios de phishing y malware",
            counter = "${Stats.threats} sitios peligrosos bloqueados",
            checked = Stats.realtime,
            onChange = { change(it, Stats.adblock) }
        )

        ProtectionCard(
            icon = Icons.Default.Close,
            title = "Bloqueador de anuncios",
            subtitle = "Bloquea anuncios y rastreadores en apps y navegador",
            counter = "${Stats.ads} anuncios y rastreadores bloqueados",
            checked = Stats.adblock,
            onChange = { change(Stats.realtime, it) }
        )

        TextButton(
            enabled = !updating,
            onClick = {
                scope.launch {
                    updating = true
                    val ok = withContext(Dispatchers.IO) { Blocklist.update(ctx) && Signatures.update(ctx) }
                    msg = if (ok) "Listas actualizadas" else "No se pudo descargar alguna lista"
                    updating = false
                }
            },
            modifier = Modifier.align(Alignment.CenterHorizontally)
        ) { Text(if (updating) "Descargando…" else "Actualizar listas de amenazas") }
        if (msg.isNotEmpty()) Text(msg, color = Color.Gray, modifier = Modifier.align(Alignment.CenterHorizontally))

        Text(
            "Usa un VPN local que solo filtra consultas DNS; tu tráfico no pasa por servidores nuestros. " +
                "Si tenés «DNS privado» activo en Ajustes, desactivalo para que el filtro funcione.",
            fontSize = 12.sp, color = Color.Gray
        )
    }
}

@Composable
fun ScanCard(results: List<AppRisk>?, scanning: Boolean, onScan: () -> Unit) {
    val risky = results?.filter { it.level != Level.LOW }
    val color = when { risky == null -> Amber; risky.isEmpty() -> Green; else -> Red }
    val title = when {
        risky == null -> "Todavía no analizaste tu dispositivo"
        risky.isEmpty() -> "Tu dispositivo está limpio"
        else -> "Se encontraron ${risky.size} elementos para revisar"
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                if (risky != null && risky.isNotEmpty()) Icons.Default.Warning else Icons.Default.CheckCircle,
                null, tint = color, modifier = Modifier.size(72.dp)
            )
            Spacer(Modifier.height(8.dp))
            Text(title, fontSize = 20.sp)
            if (results != null) {
                Spacer(Modifier.height(4.dp))
                Text("${results.size} apps analizadas", fontSize = 13.sp, color = Color.Gray)
                if (risky != null && risky.isNotEmpty()) {
                    Spacer(Modifier.height(10.dp))
                    risky.groupBy { it.type }.entries.sortedByDescending { it.value.size }.forEach { (type, list) ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                            Text(type, Modifier.weight(1f))
                            Text(list.size.toString(), color = Red)
                        }
                    }
                }
            }
            if (scanning) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 12.dp))
            Spacer(Modifier.height(16.dp))
            Button(onClick = onScan, enabled = !scanning, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Text(if (scanning) "Analizando…" else "Analizar ahora", fontSize = 16.sp)
            }
        }
    }
}

@Composable
fun ProtectionCard(
    icon: ImageVector, title: String, subtitle: String, counter: String,
    checked: Boolean, onChange: (Boolean) -> Unit
) {
    val c = if (checked) Green else Color.Gray
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = c, modifier = Modifier.size(40.dp))
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 18.sp)
                Text(if (checked) "ACTIVA" else "Apagada", fontSize = 12.sp, color = c)
                Spacer(Modifier.height(4.dp))
                Text(subtitle, fontSize = 12.sp, color = Color.LightGray)
                Text(counter, fontSize = 12.sp, color = Color.Gray)
            }
            Spacer(Modifier.width(8.dp))
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}
