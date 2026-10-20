package com.tamanna.phishguard.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.RingtoneManager
import android.os.Build
import android.os.Bundle
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
 * PhishGuard AI - Robust On-Device Notification Listener Service
 * Supports WhatsApp (MessagingStyle), WhatsApp Business, Telegram, SMS, Messenger, Gmail, etc.
 */
class PhishGuardNotificationListener : NotificationListenerService() {

    private val TAG = "PhishGuardNotif"
    private val CHANNEL_ID = "phishguard_threat_alerts"
    private lateinit var inferenceEngine: TFLiteInferenceEngine
    private lateinit var database: ThreatDatabase
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    // Known communication packages
    private val TARGET_PACKAGES = setOf(
        "com.whatsapp",                      // WhatsApp
        "com.whatsapp.w4b",                  // WhatsApp Business
        "com.google.android.apps.messaging", // Android Messages (SMS)
        "com.samsung.android.messaging",     // Samsung Messages
        "com.android.mms",                   // Default SMS (Xiaomi/Oppo/Vivo)
        "com.facebook.orca",                 // Messenger
        "org.telegram.messenger",           // Telegram
        "com.google.android.gm",             // Gmail
        "com.microsoft.office.outlook"       // Outlook
    )

    override fun onCreate() {
        super.onCreate()
        inferenceEngine = TFLiteInferenceEngine(applicationContext)
        database = ThreatDatabase.getDatabase(applicationContext)
        createNotificationChannel()
        Log.i(TAG, "PhishGuard NotificationListenerService Started.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName
        // Do not intercept our own notifications
        if (packageName == applicationContext.packageName) return

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        // Extract title (Sender)
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TITLE_BIG)?.toString()
            ?: "Unknown Sender"

        // Extract message payload robustly (WhatsApp MessagingStyle, InboxStyle, BigText, or standard Text)
        var messageBody = ""

        // 1. WhatsApp MessagingStyle (EXTRA_MESSAGES contains array of Parcelable Bundles)
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        if (messages != null && messages.isNotEmpty()) {
            val sb = StringBuilder()
            for (item in messages) {
                if (item is Bundle) {
                    val text = item.getCharSequence("text")
                    if (!text.isNullOrBlank()) {
                        sb.append(text).append(" ")
                    }
                }
            }
            if (sb.isNotBlank()) {
                messageBody = sb.toString().trim()
            }
        }

        // 2. EXTRA_TEXT_LINES (InboxStyle in older WhatsApp/Email notifications)
        if (messageBody.isBlank()) {
            val lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
            if (lines != null && lines.isNotEmpty()) {
                messageBody = lines.joinToString(" ") { it.toString() }
            }
        }

        // 3. EXTRA_BIG_TEXT
        if (messageBody.isBlank()) {
            messageBody = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""
        }

        // 4. Standard EXTRA_TEXT
        if (messageBody.isBlank()) {
            messageBody = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        }

        if (messageBody.isBlank()) {
            Log.d(TAG, "Empty body from $packageName, skipping.")
            return
        }

        val isTargetApp = TARGET_PACKAGES.contains(packageName)
        val hasUrl = messageBody.contains("http://") || messageBody.contains("https://") ||
                     messageBody.contains(".tk") || messageBody.contains(".xyz")

        // Intercept if it's a known communication app OR any app delivering a web link
        if (!isTargetApp && !hasUrl) {
            return
        }

        Log.i(TAG, "INTERCEPTED [$packageName] from '$title': $messageBody")

        // Broadcast to MainActivity if it's currently open
        val broadcastIntent = Intent("com.tamanna.phishguard.NEW_PAYLOAD").apply {
            putExtra("sender", title)
            putExtra("text", messageBody)
            putExtra("package", packageName)
        }
        sendBroadcast(broadcastIntent)

        // Run On-Device ML & Anomaly Detection
        serviceScope.launch {
            val result = inferenceEngine.analyzePayload(
                appId = mapPackageToAppId(packageName),
                sender = title,
                text = messageBody
            )

            Log.i(TAG, "Inference Result: Risk=${result.riskConfidence}%, Category=${result.threatCategory}")

            // If overall Risk Confidence exceeds threshold (>= 68%), trigger high-priority warning alert!
            if (result.riskConfidence >= 68.0) {
                triggerWarningNotification(
                    sender = title,
                    threatCategory = result.threatCategory,
                    riskScore = result.riskConfidence,
                    recommendedAction = result.recommendedAction,
                    sourceApp = mapPackageToAppId(packageName).uppercase()
                )
            }

            // Persist to local database
            database.threatDao().insertThreat(
                ThreatEntity(
                    timestamp = System.currentTimeMillis(),
                    sourceApp = mapPackageToAppId(packageName).uppercase(),
                    sender = title,
                    payloadPreview = messageBody.take(150),
                    threatCategory = result.threatCategory,
                    riskScore = result.riskConfidence,
                    isAnomaly = result.isAnomaly
                )
            )
        }
    }

    private fun mapPackageToAppId(pkg: String): String {
        return when {
            pkg.contains("whatsapp") -> "whatsapp"
            pkg.contains("messaging") || pkg.contains("mms") -> "sms"
            pkg.contains("telegram") -> "telegram"
            pkg.contains("orca") -> "messenger"
            pkg.contains("gm") || pkg.contains("outlook") -> "email"
            else -> "app"
        }
    }

    private fun triggerWarningNotification(
        sender: String,
        threatCategory: String,
        riskScore: Double,
        recommendedAction: String,
        sourceApp: String
    ) {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("🚨 PhishGuard AI: $threatCategory Intercepted!")
            .setContentText("Threat from $sourceApp ($sender) - ${riskScore.toInt()}% Risk.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "⚠️ $threatCategory Detected from $sourceApp!\n" +
                "Sender: $sender\n" +
                "Risk Confidence: $riskScore%\n" +
                "Action: $recommendedAction"
            ))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setSound(soundUri)
            .setVibrate(longArrayOf(0, 400, 200, 400))
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify((System.currentTimeMillis() % 100000).toInt(), notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhishGuard AI Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority alerts for intercepted phishing and smishing threats."
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 400, 200, 400)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setSound(soundUri, null)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }
}
