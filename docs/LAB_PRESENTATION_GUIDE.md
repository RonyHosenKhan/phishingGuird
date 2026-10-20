# PhishGuard AI - Mobile Computing Lab Presentation & Demo Guide
**Course:** Mobile Computing Lab (8th Semester)  
**Student Name:** Tamanna Akter  
**Roll No:** 21CSE012  
**Project Title:** PhishGuard AI - On-Device AI-Powered Real-Time Phishing and Threat Detection System

---

## 🎯 How to Present to Your Professor (Sir)

### Step 1: Opening Statement (বাংলা ও English)
> "Good morning / Assalamu Alaikum Sir. I am **Tamanna Akter (Roll: 21CSE012)**. Today I am presenting my 8th Semester Mobile Computing Lab project titled **PhishGuard AI**."
> 
> "Sir, traditional anti-phishing apps send private SMS, OTPs, and personal emails to external cloud servers, which violates user privacy and creates latency. **PhishGuard AI** is an **on-device, zero-cloud security architecture** designed for Android. It operates 100% locally on the device using lightweight AI models, intercepting threats in real-time across SMS, WhatsApp, Messenger, Gmail, and web URLs without leaking a single byte of sensitive data to the internet."

---

### Step 2: Live Demo Sequence (Screen Demonstration)

#### Action 1: Show the Real-Time Shield (Dashboard)
1. Open the web simulator in your browser at `http://127.0.0.1:8000`.
2. Show the Android 15 phone frame and explain:
   - **Status Bar**: Live time, 5G connection, battery indicator.
   - **Background Listeners**:
     - `NotificationListenerService`: Actively intercepts system notifications from SMS, WhatsApp, Messenger, and Gmail.
     - `AccessibilityService`: Inspects on-screen links and browser address bars.
   - **Privacy Lock**: 100% on-device local inference.

#### Action 2: Demonstrate Phishing Detection (bKash Fake PIN Scam)
1. Switch to the **Scanner** tab.
2. Under **"1-Click Lab Presentation Scenarios"**, select:
   👉 **`📱 bKash Fake PIN Verification (SMS Smishing)`**
3. Point out to Sir:
   - Notice the SMS sender: `+8801999887766`
   - Notice the text: *"bKash Alert: Your account has been suspended due to security violation! Immediately verify your PIN within 24 hours to reactivate: http://bkash-verify-pin-update.tk/login.php"*
4. Click **"Analyze On-Device"**.
5. **Observe the Result:**
   - 🔊 Audio alert sounds!
   - 🚨 Android **Heads-Up Notification Banner** drops down from the status bar:  
     `"PhishGuard AI Alert: Phishing Attack Detected! (96.9% Risk)"`
   - Circular Gauge transitions to glowing **Crimson Red (96.9%)**.
   - Show the **3 AI Models Inspection Breakdown**:
     - **Random Forest**: Caught the suspicious `.tk` top-level domain and missing HTTPS.
     - **Quantized MobileBERT**: Detected brand impersonation (`bKash`) and psychological coercion (`suspended`, `PIN`, `verify`).
     - **Deep Autoencoder**: Anomaly spike indicator flagged novel token combinations.

#### Action 3: Demonstrate Zero-Day Anomaly Detection (Novel Attack)
1. In the preset dropdown, select:  
   👉 **`🧠 Novel Zero-Day Anomaly (Autoencoder Spike)`**
2. Explain to Sir:
   > "Sir, supervised models only know attacks they've seen before. Here, an attacker generated an obfuscated, high-entropy URL with unusual syntax. When passed to our **Deep Autoencoder**, the reconstruction loss (MSE) shoots up to **0.2882**, well above our calibrated threshold of **0.0729**. The autoencoder flags this as a **Zero-Day Anomaly** without needing prior signature updates!"

#### Action 4: Demonstrate Legitimate Communication (Safe Verification)
1. In the preset dropdown, select:  
   👉 **`✅ Legitimate Wikipedia Article`** or **`💬 Normal Classmate SMS`**
2. Click **"Analyze On-Device"**.
3. Point out that the risk score drops to **0% - 4% (Emerald Green)**, confirming zero false alarms on safe personal chats and trusted HTTPS portals.

#### Action 5: Show the Local SQLite / Room Database (Audit DB)
1. Click the **Audit DB** tab.
2. Show Sir the real-time tabular history of intercepted threats:
   - Timestamp, source app, sender, risk confidence %, and categorization.
   - Click **"Export CSV"** to demonstrate log downloading.
   - Click **"Print Lab Report"** to show a formatted evaluation report ready for grading!

#### Action 6: Switch to "Lab Projector View"
1. In the top navigation bar, click **"Lab Projector View"**.
2. Show Sir the full-screen side telemetry dashboard displaying:
   - **Test Accuracy (98.4%)**
   - **F1-Score (97.8%)**
   - **Precision (98.1%)**
   - **Inference Latency (12.8 ms)**
   - Live feature attribution vector table.

---

### Step 3: Closing Summary
> "Sir, in conclusion, PhishGuard AI successfully bridges mobile system services (`NotificationListenerService` and `AccessibilityService`) with lightweight on-device AI (`Random Forest`, `Quantized MobileBERT`, and `Autoencoder Anomaly Detection`). It achieves **98.4% accuracy** in less than **15 milliseconds** entirely on-device, providing total privacy and real-time defense against mobile phishing."
