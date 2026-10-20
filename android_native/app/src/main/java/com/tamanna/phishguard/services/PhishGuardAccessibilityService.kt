package com.tamanna.phishguard.services

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.tamanna.phishguard.ml.TFLiteInferenceEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * PhishGuard AI - Native Android Accessibility Service
 * Inspects screen content and UI elements for deep-link URLs and clipboard interactions in real time.
 * Compliant with 8th Semester Mobile Computing Lab Proposal specifications.
 */
class PhishGuardAccessibilityService : AccessibilityService() {

    private val TAG = "PhishGuardAccessService"
    private lateinit var inferenceEngine: TFLiteInferenceEngine
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    override fun onServiceConnected() {
        super.onServiceConnected()
        inferenceEngine = TFLiteInferenceEngine(applicationContext)

        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_VIEW_CLICKED or
                         AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                         AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            notificationTimeout = 100
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        }
        serviceInfo = info
        Log.i(TAG, "PhishGuard AccessibilityService Connected & Configured.")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return

        val rootNode = rootInActiveWindow ?: return

        // Traverse UI tree to inspect URLs in browser address bars or messaging link previews
        serviceScope.launch {
            scanNodesForUrls(rootNode)
        }
    }

    private fun scanNodesForUrls(node: AccessibilityNodeInfo?) {
        if (node == null) return

        val text = node.text?.toString() ?: ""
        val contentDesc = node.contentDescription?.toString() ?: ""

        val candidate = if (text.isNotEmpty()) text else contentDesc
        if (candidate.startsWith("http://") || candidate.startsWith("https://") || candidate.contains(".tk") || candidate.contains(".xyz")) {
            Log.d(TAG, "Accessibility detected on-screen URL: $candidate")
            val result = inferenceEngine.analyzePayload(appId = "browser", sender = "Screen UI", text = "", url = candidate)
            if (result.riskConfidence >= 68.0) {
                Log.w(TAG, "DANGEROUS DEEP-LINK ON SCREEN: $candidate (Risk: ${result.riskConfidence}%)")
            }
        }

        // Recursively inspect children nodes
        for (i in 0 until node.childCount) {
            scanNodesForUrls(node.getChild(i))
        }
    }

    override fun onInterrupt() {
        Log.w(TAG, "PhishGuard AccessibilityService Interrupted.")
    }
}
