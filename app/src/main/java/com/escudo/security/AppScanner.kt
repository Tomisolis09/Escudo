package com.escudo.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.net.URL
import java.security.MessageDigest

enum class Level(val label: String) { HIGH("Alto"), MEDIUM("Medio"), LOW("Bajo") }

data class AppRisk(
    val name: String, val pkg: String, val score: Int, val level: Level,
    val type: String, val reasons: List<String>
)

/** Base local de hashes SHA-256 de APKs maliciosos (uno por línea). */
object Signatures {
    /** Poné acá la URL de tu feed de hashes (por ejemplo, uno propio). Vacío = desactivado. */
    const val FEED_URL = ""
    @Volatile var hashes: Set<String> = emptySet()

    private fun file(c: Context) = File(c.filesDir, "malware_sha256.txt")

    fun load(c: Context) {
        val f = file(c)
        if (f.exists()) hashes = f.readLines().map { it.trim().lowercase() }.filter { it.length == 64 }.toSet()
    }

    fun update(c: Context): Boolean {
        if (FEED_URL.isEmpty()) return true
        return try {
            file(c).writeText(URL(FEED_URL).openStream().bufferedReader().readText()); load(c); true
        } catch (e: Exception) { false }
    }

    fun sha256(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s ->
            val b = ByteArray(65536)
            while (true) { val n = s.read(b); if (n < 0) break; md.update(b, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}

object AppScanner {
    private const val FLAGS = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
        PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS

    private val stores = listOf("com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket")

    private val adSdks = listOf(
        "com.google.android.gms.ads", "com.unity3d.ads", "com.applovin", "com.mopub", "com.ironsource",
        "com.vungle", "com.chartboost", "com.inmobi", "com.startapp", "com.adcolony",
        "com.facebook.ads", "com.bytedance.sdk.openadsdk"
    )

    private const val OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
    private const val ALL_FILES = "android.permission.MANAGE_EXTERNAL_STORAGE"
    private val smsPerms = listOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS")
    private val spyPerms = listOf("android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.READ_CONTACTS", "android.permission.ACCESS_BACKGROUND_LOCATION")

    private val weights = mapOf(
        OVERLAY to (20 to "Puede dibujar sobre otras apps"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to (15 to "Puede instalar otras apps"),
        "android.permission.READ_SMS" to (15 to "Lee tus SMS"),
        "android.permission.RECEIVE_SMS" to (10 to "Intercepta SMS entrantes"),
        "android.permission.SEND_SMS" to (10 to "Envía SMS"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to (10 to "Ubicación en segundo plano"),
        ALL_FILES to (10 to "Acceso total al almacenamiento"),
        "android.permission.READ_CALL_LOG" to (8 to "Lee el registro de llamadas"),
        "android.permission.RECORD_AUDIO" to (5 to "Usa el micrófono"),
        "android.permission.READ_CONTACTS" to (5 to "Lee tus contactos"),
        "android.permission.CAMERA" to (3 to "Usa la cámara")
    )

    fun scan(c: Context): List<AppRisk> {
        val pm = c.packageManager
        val a11y = enabledA11y(c); val admins = admins(c)
        @Suppress("DEPRECATION")
        return pm.getInstalledApplications(0)
            .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 && it.packageName != c.packageName }
            .mapNotNull { ai ->
                try {
                    @Suppress("DEPRECATION")
                    analyze(c, pm.getPackageInfo(ai.packageName, FLAGS), a11y, admins)
                } catch (e: Exception) { null }
            }.sortedByDescending { it.score }
    }

    /** Escaneo de una sola app (usado por la protección en tiempo real al instalar). */
    fun scanOne(c: Context, pkg: String): AppRisk? = try {
        @Suppress("DEPRECATION")
        analyze(c, c.packageManager.getPackageInfo(pkg, FLAGS), enabledA11y(c), admins(c))
    } catch (e: Exception) { null }

    private fun enabledA11y(c: Context): Set<String> =
        (c.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager)
            .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .map { it.resolveInfo.serviceInfo.packageName }.toSet()

    private fun admins(c: Context): Set<String> =
        (c.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager)
            .activeAdmins?.map { it.packageName }?.toSet() ?: emptySet()

    private fun analyze(c: Context, p: PackageInfo, a11y: Set<String>, admins: Set<String>): AppRisk? {
        val ai = p.applicationInfo ?: return null
        if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0 || p.packageName == c.packageName) return null
        val perms = p.requestedPermissions?.toSet() ?: emptySet()
        var score = 0; val why = mutableListOf<String>()

        val isA11y = p.packageName in a11y
        val isAdmin = p.packageName in admins
        if (isA11y) { score += 30; why += "Servicio de accesibilidad ACTIVO (puede leer y controlar la pantalla)" }
        if (isAdmin) { score += 25; why += "Es administrador del dispositivo (difícil de desinstalar)" }
        perms.forEach { weights[it]?.let { w -> score += w.first; why += w.second } }

        val sideload = installer(c.packageManager, p.packageName) !in stores
        if (sideload) { score += 20; why += "Instalada fuera de una tienda oficial" }

        val names = p.activities.orEmpty().map { it.name } + p.services.orEmpty().map { it.name } +
            p.receivers.orEmpty().map { it.name }
        val sdks = adSdks.filter { pre -> names.any { it.startsWith(pre) } }
        if (sdks.isNotEmpty()) why += "Integra ${sdks.size} SDK de publicidad"

        val known = Signatures.hashes.isNotEmpty() && Signatures.sha256(File(ai.sourceDir)) in Signatures.hashes
        val overlay = OVERLAY in perms
        val hasSms = smsPerms.any { it in perms }
        val type = when {
            known -> "Malware conocido"
            overlay && isA11y && hasSms -> "Troyano bancario"
            isAdmin && (ALL_FILES in perms || overlay) -> "Posible ransomware"
            (isA11y || hasSms || "android.permission.READ_CALL_LOG" in perms) && spyPerms.any { it in perms } -> "Spyware"
            sdks.size >= 3 || (overlay && sdks.isNotEmpty()) -> "Adware / PUP"
            sideload && score >= 30 -> "Aplicación sospechosa"
            score >= 30 -> "Permisos riesgosos"
            else -> "Sin amenazas"
        }
        if (type == "Adware / PUP") score += 15
        if (known) { score = 100; why.add(0, "Coincide con un malware conocido (hash SHA-256)") }
        val s = score.coerceAtMost(100)
        return AppRisk(c.packageManager.getApplicationLabel(ai).toString(), p.packageName, s,
            if (s >= 60) Level.HIGH else if (s >= 30) Level.MEDIUM else Level.LOW, type, why)
    }

    @Suppress("DEPRECATION")
    private fun installer(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    } catch (e: Exception) { null }
}
