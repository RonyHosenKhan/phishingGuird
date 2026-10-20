package com.tamanna.phishguard.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.app.NotificationCompat
import com.tamanna.phishguard.data.ThreatDatabase
import com.tamanna.phishguard.data.ThreatEntity
import com.tamanna.phishguard.ml.TFLiteInferenceEngine
import com.tamanna.phishguard.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * PhishGuard AI - Native Android Notification Listener Service
 * Intercepts notification payloads across SMS, WhatsApp, Messenger, and Gmail apps.
 * Extracts text bundles and embedded URLs, passing them to on-device TFLite models.
 * Compliant with 8th Semester Mobile Computing Lab Proposal specifications.
 */
class PhishGuardNotificationListener : NotificationListenerService() {

    private val TAG = "PhishGuardNotifService"
    private val CHANNEL_ID = "phishguard_threat_alerts"
    private lateinit var inferenceEngine: TFLiteInferenceEngine
    private lateinit var database: ThreatDatabase
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    // Target messaging and email package identifiers
    private val TARGET_PACKAGES = setOf(
        "com.google.android.apps.messaging", // Android Messages (SMS)
        "com.whatsapp",                      // WhatsApp
        "com.facebook.orca",                 // Messenger
        "com.google.android.gm",             // Gmail
        "com.microsoft.office.outlook"       // Outlook Email
    )

    override fun onCreate() {
        super.onCreate()
        inferenceEngine = TFLiteInferenceEngine(applicationContext)
        database = ThreatDatabase.getDatabase(applicationContext)
        createNotificationChannel()
        Log.i(TAG, "PhishGuard NotificationListenerService Started & Initialized.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName
        // Avoid intercepting our own alerts
        if (packageName == applicationContext.packageName) return

        if (!TARGET_PACKAGES.contains(packageName)) {
            return
        }

        val extras = sbn.notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: "Unknown Sender"
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: text

        val payload = if (bigText.isNotEmpty()) bigText else text
        if (payload.isBlank()) return

        Log.d(TAG, "Intercepted payload from [$packageName] ($title): $payload")

        // Run On-Device TFLite / Anomaly Inference asynchronously
        serviceScope.launch {
            val result = inferenceEngine.analyzePayload(
                appId = mapPackageToAppId(packageName),
                sender = title,
                text = payload
            )

            // If overall Risk Confidence exceeds threshold (>= 68%), trigger high-priority warning alert!
            if (result.riskConfidence >= 68.0) {
                Log.w(TAG, "THREAT DETECTED! Risk: ${result.riskConfidence}%, Category: ${result.threatCategory}")
                triggerWarningNotification(
                    sender = title,
                    threatCategory = result.threatCategory,
                    riskScore = result.riskConfidence,
                    recommendedAction = result.recommendedAction
                )
            }

            // Persist threat event to local SQLite Room database for audit trail
            database.threatDao().insertThreat(
                ThreatEntity(
                    timestamp = System.currentTimeMillis(),
                    sourceApp = mapPackageToAppId(packageName).uppercase(),
                    sender = title,
                    payloadPreview = payload.take(120),
                    threatCategory = result.threatCategory,
                    riskScore = result.riskConfidence,
                    isAnomaly = result.isAnomaly
                )
            )
        }
    }

    private fun mapPackageToAppId(pkg: String): String {
        return when (pkg) {
            "com.whatsapp" -> "whatsapp"
            "com.facebook.orca" -> "messenger"
            "com.google.android.gm", "com.microsoft.office.outlook" -> "email"
            else -> "sms"
        }
    }

    private fun triggerWarningNotification(
        sender: String,
        threatCategory: String,
        riskScore: Double,
        recommendedAction: String
    ) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("PhishGuard AI: $threatCategory Detected!")
            .setContentText("Threat from $sender (${riskScore.toInt()}% Risk). $recommendedAction")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "Potential Phishing Threat Intercepted from $sender.\n" +
                "Risk Confidence: $riskScore%\n" +
                "Recommendation: $recommendedAction"
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify((System.currentTimeMillis() % 10000).toInt(), notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhishGuard AI Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority alerts for intercepted phishing and smishing threats."
                enableVibration(true)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }
}
