package com.tamanna.phishguard.ui

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.tamanna.phishguard.R
import com.tamanna.phishguard.data.ThreatDatabase
import com.tamanna.phishguard.services.PhishGuardNotificationListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var tvStatus: TextView
    private lateinit var tvRecentLog: TextView
    private lateinit var database: ThreatDatabase
    private val scope = CoroutineScope(Dispatchers.IO)

    private val payloadReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val sender = intent?.getStringExtra("sender") ?: "Unknown"
            val text = intent?.getStringExtra("text") ?: ""
            val pkg = intent?.getStringExtra("package") ?: ""
            runOnUiThread {
                tvRecentLog.text = "⚡ Intercepted [${pkg.substringAfterLast('.')}]:\nFrom: $sender\nMessage: $text"
                refreshLogs()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        database = ThreatDatabase.getDatabase(this)

        tvStatus = findViewById(R.id.tvServiceStatus)
        tvRecentLog = findViewById(R.id.tvRecentLog)

        val btnNotif = findViewById<Button>(R.id.btnEnableNotificationListener)
        val btnAccess = findViewById<Button>(R.id.btnEnableAccessibility)
        val btnTest = findViewById<Button>(R.id.btnTestSampleNotification)

        // Request POST_NOTIFICATIONS permission on Android 13+ (API 33+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 101)
            }
        }

        btnNotif.setOnClickListener {
            // Open Android Notification Access Settings
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            Toast.makeText(this, "Enable 'PhishGuard AI' toggle", Toast.LENGTH_LONG).show()
        }

        btnAccess.setOnClickListener {
            // Open Android Accessibility Settings
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            Toast.makeText(this, "Enable 'PhishGuard Screen Inspector'", Toast.LENGTH_LONG).show()
        }

        btnTest.setOnClickListener {
            triggerSampleThreatAlert()
        }

        val filter = IntentFilter("com.tamanna.phishguard.NEW_PAYLOAD")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(payloadReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(payloadReceiver, filter)
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
        refreshLogs()
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(payloadReceiver)
    }

    private fun updateStatus() {
        val isEnabled = isNotificationServiceEnabled(this)
        if (isEnabled) {
            tvStatus.text = "🟢 Active Protection: ON\nMonitoring WhatsApp, SMS, Messenger & Gmail"
            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.threat_safe))
        } else {
            tvStatus.text = "🔴 Protection: OFF (Action Required)\nTap '1. Grant Notification Listener Access' to enable"
            tvStatus.setTextColor(ContextCompat.getColor(this, R.color.threat_critical))
        }
    }

    private fun refreshLogs() {
        scope.launch {
            val list = database.threatDao().getAllThreats()
            withContext(Dispatchers.Main) {
                if (list.isNotEmpty()) {
                    val latest = list.first()
                    tvRecentLog.text = "Latest Threat Intercepted:\n[${latest.sourceApp}] from ${latest.sender}\n${latest.payloadPreview}\nThreat: ${latest.threatCategory} (${latest.riskScore}%)"
                }
            }
        }
    }

    private fun isNotificationServiceEnabled(context: Context): Boolean {
        val pkgName = context.packageName
        val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        if (!TextUtils.isEmpty(flat)) {
            val names = flat.split(":".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            for (name in names) {
                val cn = ComponentName.unflattenFromString(name)
                if (cn != null && TextUtils.equals(pkgName, cn.packageName)) {
                    return true
                }
            }
        }
        return false
    }

    private fun triggerSampleThreatAlert() {
        val channelId = "phishguard_threat_alerts"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "PhishGuard AI Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                enableVibration(true)
            }
            manager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("🚨 PhishGuard AI: Phishing Attack Intercepted!")
            .setContentText("Threat from WhatsApp (+8801999887766) - 96.9% Risk. Suspicious PIN verification link blocked.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "⚠️ Phishing Attack Detected!\n" +
                "Source: WhatsApp (+8801999887766)\n" +
                "Risk Confidence: 96.9%\n" +
                "Recommendation: Block sender immediately. Do not share PIN or OTP."
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setAutoCancel(true)
            .build()

        manager.notify(101, notification)
        Toast.makeText(this, "Alert notification triggered!", Toast.LENGTH_SHORT).show()
    }
}
