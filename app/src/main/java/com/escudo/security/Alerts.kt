package com.escudo.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

object Alerts {
    /** Notificación fija que mantiene vivo el servicio de protección. */
    fun foreground(c: Context): Notification {
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("protection", "Protección activa", NotificationManager.IMPORTANCE_LOW))
        val pi = PendingIntent.getActivity(c, 1, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val on = listOfNotNull(
            if (Stats.realtime) "protección en tiempo real" else null,
            if (Stats.adblock) "bloqueador de anuncios" else null
        ).joinToString(" y ")
        return Notification.Builder(c, "protection")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Escudo está protegiendo tu dispositivo")
            .setContentText(on.replaceFirstChar { it.uppercase() } + " activa")
            .setContentIntent(pi).setOngoing(true).build()
    }

    fun notify(c: Context, r: AppRisk) {
        val nm = c.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("threats", "Amenazas", NotificationManager.IMPORTANCE_HIGH))
        val pi = PendingIntent.getActivity(c, 0, Intent(c, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(c, "threats")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Amenaza detectada: ${r.name}")
            .setContentText("${r.type} · riesgo ${r.score}/100. Tocá para revisar.")
            .setContentIntent(pi).setAutoCancel(true).build()
        nm.notify(r.pkg.hashCode(), n)
    }
}
