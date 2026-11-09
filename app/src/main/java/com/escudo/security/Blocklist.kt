package com.escudo.security

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.net.URL

/** Dos categorías: anuncios/rastreadores (1) y sitios maliciosos/phishing (2). */
object Blocklist {
    // índices 1 y 2 son amenazas (malware / phishing)
    private val SOURCES = listOf(
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://phishing.army/download/phishing_army_blocklist.txt"
    )
    private val THREAT_IDX = setOf(1, 2)
    private val defaults = setOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com",
        "app-measurement.com", "unityads.unity3d.com", "applovin.com", "ads.mopub.com", "adcolony.com",
        "vungle.com", "chartboost.com", "taboola.com", "outbrain.com", "criteo.com", "adnxs.com",
        "scorecardresearch.com", "moatads.com", "amazon-adsystem.com", "ironsrc.com", "inmobi.com"
    )
    @Volatile private var ads: Set<String> = defaults
    @Volatile private var threats: Set<String> = emptySet()
    var adsSize by mutableIntStateOf(defaults.size)
    var threatsSize by mutableIntStateOf(0)

    private fun file(c: Context, i: Int) = File(c.filesDir, "list_$i.txt")

    fun load(c: Context) {
        val a = HashSet<String>(defaults); val t = HashSet<String>()
        SOURCES.indices.forEach { i ->
            val f = file(c, i)
            if (f.exists()) (if (i in THREAT_IDX) t else a).addAll(parse(f.readLines()))
        }
        ads = a; threats = t; adsSize = a.size; threatsSize = t.size
    }

    /** Descarga las listas. Llamar fuera del hilo principal. */
    fun update(c: Context): Boolean {
        var ok = false
        SOURCES.forEachIndexed { i, url ->
            try { file(c, i).writeText(URL(url).openStream().bufferedReader().readText()); ok = true } catch (_: Exception) {}
        }
        if (ok) load(c)
        return ok
    }

    private fun parse(lines: List<String>): List<String> = lines.mapNotNull { l ->
        val p = l.substringBefore('#').trim().split(Regex("\\s+"))
        val d = when {
            p.size >= 2 && (p[0] == "0.0.0.0" || p[0] == "127.0.0.1") -> p[1]
            p.size == 1 && p[0].contains('.') -> p[0]
            else -> return@mapNotNull null
        }
        d.lowercase().takeIf { it != "localhost" && it != "0.0.0.0" }
    }

    /** 0 = permitido, 1 = anuncio/rastreador, 2 = sitio malicioso/phishing */
    fun category(name: String): Int {
        var d = name
        while (true) {
            if (d in threats) return 2
            if (d in ads) return 1
            val i = d.indexOf('.')
            if (i < 0) return 0
            d = d.substring(i + 1)
        }
    }
}
