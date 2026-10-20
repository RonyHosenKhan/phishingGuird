package com.tamanna.phishguard.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationCompat
import com.tamanna.phishguard.R

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnNotif = findViewById<Button>(R.id.btnEnableNotificationListener)
        val btnAccess = findViewById<Button>(R.id.btnEnableAccessibility)
        val btnTest = findViewById<Button>(R.id.btnTestSampleNotification)

        btnNotif.setOnClickListener {
            // Open Android Notification Access Settings
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            Toast.makeText(this, "Please enable 'PhishGuard AI' toggle", Toast.LENGTH_LONG).show()
        }

        btnAccess.setOnClickListener {
            // Open Android Accessibility Settings
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            Toast.makeText(this, "Please enable 'PhishGuard Screen Inspector'", Toast.LENGTH_LONG).show()
        }

        btnTest.setOnClickListener {
            triggerSampleThreatAlert()
        }
    }

    private fun triggerSampleThreatAlert() {
        val channelId = "phishguard_threat_alerts"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "PhishGuard AI Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("PhishGuard AI: Phishing Attack Intercepted!")
            .setContentText("Threat from bKash (+8801999887766) - 96.9% Risk. Suspicious PIN verification link blocked.")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setAutoCancel(true)
            .build()

        manager.notify(101, notification)
        Toast.makeText(this, "Alert notification triggered!", Toast.LENGTH_SHORT).show()
    }
}
