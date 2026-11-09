package com.escudo.security

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors

object Stats {
    var running by mutableStateOf(false)
    var ads by mutableIntStateOf(0)
    var threats by mutableIntStateOf(0)
}

/**
 * VPN local: solo captura las consultas DNS (ruta a 10.111.222.2/32).
 * Si el dominio está en la lista -> responde NXDOMAIN; si no, lo reenvía a 1.1.1.1.
 * Nada del tráfico sale hacia servidores de terceros más allá del DNS normal.
 */
class AdBlockVpnService : VpnService() {
    companion object { const val ACTION_STOP = "com.escudo.security.STOP" }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private val pool = Executors.newCachedThreadPool()

    /** Protección en tiempo real: analiza cada app apenas se instala. */
    private val pkgReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            if (i.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
            val pkg = i.data?.schemeSpecificPart ?: return
            pool.execute {
                AppScanner.scanOne(applicationContext, pkg)?.let {
                    if (it.level != Level.LOW) Alerts.notify(applicationContext, it)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stop(); return START_NOT_STICKY }
        start(); return START_STICKY
    }

    override fun onDestroy() { stop(); super.onDestroy() }

    private fun start() {
        if (running) return
        tun = Builder().setSession("Escudo")
            .addAddress("10.111.222.1", 24)
            .addDnsServer("10.111.222.2")
            .addRoute("10.111.222.2", 32)
            .establish() ?: return
        running = true; Stats.running = true
        val f = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(pkgReceiver, f, Context.RECEIVER_EXPORTED)
        else registerReceiver(pkgReceiver, f)
        Thread { loop(tun!!) }.start()
    }

    private fun stop() {
        running = false; Stats.running = false
        try { unregisterReceiver(pkgReceiver) } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        tun = null; stopSelf()
    }

    private fun loop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (running) {
                val n = input.read(buf)
                if (n <= 0) continue
                val pkt = buf.copyOf(n)
                pool.execute { handle(pkt, output) }
            }
        } catch (_: Exception) {}
    }

    private fun handle(pkt: ByteArray, out: FileOutputStream) {
        if (pkt.size < 28 || (pkt[0].toInt() shr 4) != 4 || pkt[9].toInt() != 17) return
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (u16(pkt, ihl + 2) != 53) return
        val dns = pkt.copyOfRange(ihl + 8, pkt.size)
        val q = parseQuestion(dns) ?: return
        val cat = Blocklist.category(q.first)
        val resp = if (cat != 0) {
            if (cat == 2) Stats.threats++ else Stats.ads++
            nxdomain(dns, q.second)
        } else forward(dns) ?: return
        val reply = buildReply(pkt, ihl, resp)
        synchronized(out) { try { out.write(reply) } catch (_: Exception) {} }
    }

    private fun forward(dns: ByteArray): ByteArray? = try {
        DatagramSocket().use { s ->
            protect(s); s.soTimeout = 4000
            s.send(DatagramPacket(dns, dns.size, InetAddress.getByName("1.1.1.1"), 53))
            val r = ByteArray(4096); val p = DatagramPacket(r, r.size)
            s.receive(p); r.copyOf(p.length)
        }
    } catch (_: Exception) { null }

    // ---- DNS / IP helpers ----
    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    /** Devuelve (dominio, fin de la sección de pregunta). */
    private fun parseQuestion(d: ByteArray): Pair<String, Int>? {
        if (d.size < 17) return null
        var i = 12; val sb = StringBuilder()
        while (i < d.size) {
            val l = d[i].toInt() and 0xFF
            if (l == 0) break
            if (l >= 0xC0 || i + 1 + l > d.size) return null
            sb.append(String(d, i + 1, l)).append('.'); i += l + 1
        }
        return Pair(sb.toString().trimEnd('.').lowercase(), i + 5)
    }

    private fun nxdomain(d: ByteArray, qEnd: Int): ByteArray {
        val r = d.copyOf(minOf(qEnd, d.size))
        r[2] = 0x81.toByte(); r[3] = 0x83.toByte()          // QR+RD, RA, RCODE=3
        for (i in 6..11) r[i] = 0                            // sin answers/authority/additional
        return r
    }

    private fun buildReply(pkt: ByteArray, ihl: Int, dns: ByteArray): ByteArray {
        val len = 28 + dns.size
        val o = ByteArray(len)
        o[0] = 0x45; o[2] = (len shr 8).toByte(); o[3] = len.toByte(); o[8] = 64; o[9] = 17
        System.arraycopy(pkt, 16, o, 12, 4); System.arraycopy(pkt, 12, o, 16, 4)
        val c = checksum(o, 20); o[10] = (c shr 8).toByte(); o[11] = c.toByte()
        o[20] = 0; o[21] = 53; o[22] = pkt[ihl]; o[23] = pkt[ihl + 1]
        val ul = 8 + dns.size; o[24] = (ul shr 8).toByte(); o[25] = ul.toByte()
        System.arraycopy(dns, 0, o, 28, dns.size)
        return o
    }

    private fun checksum(b: ByteArray, len: Int): Int {
        var sum = 0; var i = 0
        while (i < len) { sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF); i += 2 }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }
}
