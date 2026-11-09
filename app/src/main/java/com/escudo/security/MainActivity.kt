package com.escudo.security

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Blocklist.load(this); Signatures.load(this)
        if (Build.VERSION.SDK_INT >= 33)
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent { MaterialTheme(colorScheme = darkColorScheme()) { App() } }
    }
}

private val Green = Color(0xFF2ECC71)
private val Red = Color(0xFFE74C3C)
private val Amber = Color(0xFFF39C12)

@Composable
fun App() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableIntStateOf(0) }
    var results by remember { mutableStateOf<List<AppRisk>?>(null) }
    var scanning by remember { mutableStateOf(false) }

    val scan: () -> Unit = {
        scope.launch {
            scanning = true
            results = withContext(Dispatchers.Default) { AppScanner.scan(ctx) }
            scanning = false
        }
    }
    val tabs = listOf("Inicio" to Icons.Default.Home, "Escáner" to Icons.Default.Search, "Protección" to Icons.Default.Lock)

    Scaffold(bottomBar = {
        NavigationBar {
            tabs.forEachIndexed { i, (label, icon) ->
                NavigationBarItem(selected = tab == i, onClick = { tab = i },
                    icon = { Icon(icon, label) }, label = { Text(label) })
            }
        }
    }) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> HomeScreen(results, scanning, onScan = { tab = 1; scan() })
                1 -> ScanScreen(results, scanning, scan)
                else -> ProtectionScreen()
            }
        }
    }
}

@Composable
fun StatRow(label: String, value: String, color: Color = Color.White) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) { Text(label, Modifier.weight(1f)); Text(value, color = color) }
}

@Composable
fun HomeScreen(results: List<AppRisk>?, scanning: Boolean, onScan: () -> Unit) {
    val threats = results?.count { it.level != Level.LOW }
    val color = when { threats == null -> Amber; threats == 0 -> Green; else -> Red }
    Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Icon(if (threats == 0) Icons.Default.CheckCircle else Icons.Default.Warning, null, tint = color, modifier = Modifier.size(110.dp))
        Spacer(Modifier.height(12.dp))
        Text(when { threats == null -> "Todavía no escaneaste"; threats == 0 -> "Tu dispositivo está limpio"; else -> "$threats amenazas / apps para revisar" }, fontSize = 22.sp)
        Spacer(Modifier.height(24.dp))
        StatRow("Protección en tiempo real", if (Stats.running) "ACTIVA" else "Apagada", if (Stats.running) Green else Amber)
        StatRow("Anuncios y rastreadores bloqueados", Stats.ads.toString())
        StatRow("Sitios maliciosos / phishing bloqueados", Stats.threats.toString(), if (Stats.threats > 0) Red else Color.White)
        Spacer(Modifier.height(24.dp))
        Button(onClick = onScan, enabled = !scanning) { Text(if (scanning) "Escaneando…" else "Escanear ahora") }
    }
}

@Composable
fun ScanScreen(results: List<AppRisk>?, scanning: Boolean, onScan: () -> Unit) {
    val ctx = LocalContext.current
    // al volver de la pantalla de desinstalación, se vuelve a escanear
    val uninstall = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { onScan() }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Button(onClick = onScan, enabled = !scanning, modifier = Modifier.fillMaxWidth()) {
            Text(if (scanning) "Escaneando…" else "Escanear apps instaladas")
        }
        if (scanning) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
        Spacer(Modifier.height(8.dp))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(results ?: emptyList()) { r ->
                val c = when (r.level) { Level.HIGH -> Red; Level.MEDIUM -> Amber; Level.LOW -> Green }
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(r.name, fontSize = 16.sp)
                                Text(r.type, fontSize = 12.sp, color = c)
                            }
                            Text("${r.level.label} · ${r.score}", color = c)
                        }
                        r.reasons.forEach { Text("• $it", fontSize = 12.sp, color = Color.LightGray) }
                        if (r.level != Level.LOW) {
                            TextButton(onClick = {
                                uninstall.launch(Intent(Intent.ACTION_DELETE, Uri.parse("package:${r.pkg}")))
                            }) { Text("Eliminar / desinstalar", color = Red) }
                        }
                    }
                }
            }
        }
    }
}

private fun startVpn(c: Context) { c.startService(Intent(c, AdBlockVpnService::class.java)) }

@Composable
fun ProtectionScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var updating by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("") }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startVpn(ctx)
    }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Protección en tiempo real", Modifier.weight(1f), fontSize = 18.sp)
            Switch(checked = Stats.running, onCheckedChange = { on ->
                if (on) {
                    val i = VpnService.prepare(ctx)
                    if (i != null) launcher.launch(i) else startVpn(ctx)
                } else ctx.startService(Intent(ctx, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_STOP))
            })
        }
        Text("Bloquea anuncios (en apps y web), rastreadores, phishing y dominios de malware/ransomware, y te avisa si una app nueva es riesgosa apenas se instala.", fontSize = 13.sp, color = Color.Gray)
        StatRow("Anuncios y rastreadores bloqueados", Stats.ads.toString())
        StatRow("Sitios maliciosos / phishing bloqueados", Stats.threats.toString())
        StatRow("Dominios de anuncios en la lista", Blocklist.adsSize.toString())
        StatRow("Dominios de amenazas en la lista", Blocklist.threatsSize.toString())
        Button(enabled = !updating, onClick = {
            scope.launch {
                updating = true
                val ok = withContext(Dispatchers.IO) { Blocklist.update(ctx) && Signatures.update(ctx) }
                msg = if (ok) "Listas actualizadas" else "No se pudo descargar alguna lista"
                updating = false
            }
        }) { Text(if (updating) "Descargando…" else "Actualizar listas de amenazas") }
        if (msg.isNotEmpty()) Text(msg, color = Color.Gray)
        Text("Usa un VPN local que solo filtra consultas DNS; tu tráfico no pasa por servidores nuestros. Si tenés «DNS privado» activo en Ajustes, desactivalo para que el filtro funcione.", fontSize = 12.sp, color = Color.Gray)
    }
}
