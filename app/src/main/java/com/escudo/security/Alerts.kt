package com.escudo.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

object Alerts {
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
