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
import android.os.Handler
import android.os.Looper
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import com.tamanna.phishguard.R
import com.tamanna.phishguard.data.ThreatDatabase
import com.tamanna.phishguard.data.ThreatEntity
import com.tamanna.phishguard.ml.TFLiteInferenceEngine
import com.tamanna.phishguard.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * PhishGuard AI - Robust On-Device Notification Listener Service
 * Supports WhatsApp (MessagingStyle & direct text), SMS, Messenger, Telegram, Gmail, etc.
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
        Log.i(TAG, "PhishGuard NotificationListenerService Created.")
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "🟢 PhishGuard NotificationListenerService CONNECTED & BOUND BY ANDROID OS!")
        val broadcastIntent = Intent("com.tamanna.phishguard.STATUS_UPDATE").apply {
            putExtra("isBound", true)
            setPackage(applicationContext.packageName)
        }
        sendBroadcast(broadcastIntent)
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "🔴 PhishGuard NotificationListenerService DISCONNECTED BY OS!")
        val broadcastIntent = Intent("com.tamanna.phishguard.STATUS_UPDATE").apply {
            putExtra("isBound", false)
            setPackage(applicationContext.packageName)
        }
        sendBroadcast(broadcastIntent)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        try {
            val packageName = sbn.packageName ?: return
            // Do not intercept our own notifications
            if (packageName == applicationContext.packageName) return

            val notification = sbn.notification ?: return
            val extras = notification.extras ?: return

            // Extract sender (Title)
            val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
                ?: extras.getCharSequence(Notification.EXTRA_TITLE_BIG)?.toString()
                ?: extras.getCharSequence("android.conversationTitle")?.toString()
                ?: "Unknown Sender"

            // Extract message body using prioritized robust methods
            var messageBody = ""

            // 1. Direct text check (Standard Android & WhatsApp single notification)
            val directBigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            val directText = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()

            if (!directBigText.isNullOrBlank()) {
                messageBody = directBigText
            } else if (!directText.isNullOrBlank()) {
                messageBody = directText
            }

            // 2. AndroidX MessagingStyle extraction (Multi-message WhatsApp & RCS)
            if (messageBody.isBlank()) {
                try {
                    val messagingStyle = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(notification)
                    if (messagingStyle != null && messagingStyle.messages.isNotEmpty()) {
                        val sb = StringBuilder()
                        for (msg in messagingStyle.messages) {
                            if (!msg.text.isNullOrBlank()) {
                                sb.append(msg.text).append(" ")
                            }
                        }
                        if (sb.isNotBlank()) {
                            messageBody = sb.toString().trim()
                        }
                    }
                } catch (e: Exception) {
                    // Fall through
                }
            }

            // 3. EXTRA_MESSAGES Parcelable bundle inspection
            if (messageBody.isBlank()) {
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
            }

            // 4. EXTRA_TEXT_LINES (InboxStyle in older WhatsApp/Email notifications)
            if (messageBody.isBlank()) {
                val lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
                if (lines != null && lines.isNotEmpty()) {
                    messageBody = lines.joinToString(" ") { it.toString() }
                }
            }

            // 5. Fallback: Check all CharSequence extras
            if (messageBody.isBlank()) {
                messageBody = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
                    ?: extras.getCharSequence(Notification.EXTRA_SUMMARY_TEXT)?.toString()
                    ?: ""
            }

            if (messageBody.isBlank()) {
                Log.d(TAG, "Empty body from $packageName, skipping.")
                return
            }

            val pkgLower = packageName.lowercase()
            val textLower = messageBody.lowercase()

            val isCommApp = pkgLower.contains("whatsapp") || pkgLower.contains("messaging") ||
                            pkgLower.contains("mms") || pkgLower.contains("orca") ||
                            pkgLower.contains("telegram") || pkgLower.contains("mail") ||
                            TARGET_PACKAGES.contains(packageName)

            val hasThreatCue = textLower.contains("http") || textLower.contains("www.") ||
                               textLower.contains(".tk") || textLower.contains(".xyz") ||
                               textLower.contains("bkash") || textLower.contains("nagad") ||
                               textLower.contains("pin") || textLower.contains("otp") ||
                               textLower.contains("bank") || textLower.contains("verify")

            // Intercept if it's from a known communication app OR any app delivering suspicious cues
            if (!isCommApp && !hasThreatCue) {
                return
            }

            Log.i(TAG, "⚡ INTERCEPTED [$packageName] from '$title': $messageBody")

            // Broadcast to MainActivity with explicit package
            val broadcastIntent = Intent("com.tamanna.phishguard.NEW_PAYLOAD").apply {
                putExtra("sender", title)
                putExtra("text", messageBody)
                putExtra("package", packageName)
                setPackage(applicationContext.packageName)
            }
            sendBroadcast(broadcastIntent)

            // Run On-Device ML & Anomaly Detection
            serviceScope.launch {
                try {
                    val result = inferenceEngine.analyzePayload(
                        appId = mapPackageToAppId(packageName),
                        sender = title,
                        text = messageBody
                    )

                    Log.i(TAG, "Inference Result: Risk=${result.riskConfidence}%, Category=${result.threatCategory}")

                    // Trigger warning alert for suspicious spam and phishing attacks (>= 35%)
                    if (result.riskConfidence >= 35.0) {
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
                } catch (e: Exception) {
                    Log.e(TAG, "Error during inference/persistence: ${e.message}", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in onNotificationPosted: ${e.message}", e)
        }
    }

    private fun mapPackageToAppId(pkg: String): String {
        val lower = pkg.lowercase()
        return when {
            lower.contains("whatsapp") -> "whatsapp"
            lower.contains("messaging") || lower.contains("mms") -> "sms"
            lower.contains("telegram") -> "telegram"
            lower.contains("orca") -> "messenger"
            lower.contains("gm") || lower.contains("outlook") -> "email"
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
        createNotificationChannel()

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val soundUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_phishguard_logo)
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
            .setVibrate(longArrayOf(0, 500, 200, 500))
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify((System.currentTimeMillis() % 100000).toInt(), notification)

        // Show immediate on-screen Toast overlay
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(
                applicationContext,
                "🚨 PhishGuard AI: Phishing threat intercepted from $sourceApp!",
                Toast.LENGTH_LONG
            ).show()
        }
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
                vibrationPattern = longArrayOf(0, 500, 200, 500)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                setSound(soundUri, null)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }
}
