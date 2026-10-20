# PhishGuard AI - Comprehensive Lab Viva Q&A Guide
**Student Name:** Tamanna Akter (Roll: 21CSE012)  
**Course:** Mobile Computing Lab (8th Semester)  
**Project:** PhishGuard AI - On-Device AI-Powered Real-Time Phishing and Threat Detection System

---

### Question 1: What makes PhishGuard AI different from existing antivirus or anti-phishing tools?
**Answer:**  
Existing commercial solutions (like Truecaller, Google Safe Browsing, or cloud antivirus apps) transmit user SMS messages, incoming phone numbers, and visited URLs to cloud servers for lookup. This creates two major problems:
1. **Privacy Invasions:** Sending private messages, OTPs, or financial notices off-device violates privacy standards (GDPR) and introduces data breach liabilities.
2. **Network Latency & Offline Inoperability:** Cloud API calls introduce 300ms–800ms delays and fail completely when mobile data is disconnected.

**PhishGuard AI executes 100% locally on-device** using quantized lightweight machine learning models (TFLite / ONNX Runtime Mobile). Inference completes in **~12–15 milliseconds**, requires zero internet connectivity, and guarantees that zero private message contents leave the smartphone.

---

### Question 2: Why do you combine 3 different machine learning models instead of just using one classifier?
**Answer:**  
Mobile phishing payloads take diverse forms that cannot be effectively handled by a single model type:
1. **Random Forest Classifier (Supervised):** Specialized for **structured handcrafted URL features** (URL length, domain entropy, missing HTTPS, IP hostnames, special character ratios, suspicious TLDs like `.tk`, `.xyz`). Decision tree ensembles handle tabular feature boundaries with near-zero latency (<2ms).
2. **Quantized MobileBERT / DistilBERT (Contextual NLP):** Specialized for **message bodies and social engineering nuances**. Simple keyword matching fails against obfuscated phrasing; MobileBERT evaluates semantic intent (urgency triggers, fear coercion, financial lottery bait, and brand impersonation like bKash, Nagad, or PayPal).
3. **Deep Autoencoder (Unsupervised Anomaly Detection):** Supervised models suffer from the **"zero-day blindness" problem**—they cannot recognize brand-new, unseen attack patterns. The Autoencoder is trained exclusively on normal, legitimate communications. When an anomalous zero-day attack arrives, its reconstruction error ($MSE$) spikes above a calibrated threshold $\epsilon$, flagging unknown threats.

---

### Question 3: How does the Autoencoder Anomaly Detection mathematically work?
**Answer:**  
The Autoencoder consists of an **Encoder** and a **Decoder**:
- The Encoder compresses the 16-dimensional feature vector $x$ into a 4-dimensional latent bottleneck representation:  
  $$z = \sigma(W_{enc} \cdot x + b_{enc})$$
- The Decoder attempts to reconstruct the original input from $z$:  
  $$\hat{x} = W_{dec} \cdot z + b_{dec}$$
- We calculate the **Mean Squared Error (MSE) reconstruction loss**:  
  $$MSE(x, \hat{x}) = \frac{1}{d} \sum_{i=1}^{d} (x_i - \hat{x}_i)^2$$
- We tune a decision threshold $\epsilon$ based on the 95th percentile of errors on legitimate training data ($\epsilon \approx 0.07295$).
- If $MSE > \epsilon$, the input deviates fundamentally from legitimate baseline structures and is flagged as an **Anomaly (Zero-Day Threat)**.

---

### Question 4: How does Android's `NotificationListenerService` work, and why is it used?
**Answer:**  
In Android, standard background applications cannot read other apps' private data due to sandboxing. However, Android provides `NotificationListenerService` (introduced in API 18).
- Once the user grants notification access in Android Settings, the OS dispatches system-wide `StatusBarNotification` events to `onNotificationPosted()`.
- PhishGuard AI filters for high-risk communication apps (`com.whatsapp`, `com.google.android.apps.messaging`, `com.google.android.gm`, `com.facebook.orca`).
- It extracts the `EXTRA_TITLE` (sender name or phone number) and `EXTRA_TEXT` / `EXTRA_BIG_TEXT` (message body).
- The text is passed immediately to our on-device inference pipeline. If high risk is detected, a high-priority warning notification is triggered before the user taps the malicious link!

---

### Question 5: How does `AccessibilityService` detect phishing links on screen?
**Answer:**  
When a user browses the web or opens an app without generating a notification, `AccessibilityService` provides window content inspection:
- It listens for `AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED` and `TYPE_VIEW_CLICKED`.
- It inspects `AccessibilityNodeInfo` hierarchies for URL strings (e.g., in Chrome's address bar or WebView link elements).
- If a deep-link points to an IP address or suspicious TLD, PhishGuard AI alerts the user in real time or prompts intent cancellation.

---

### Question 6: What is INT8 Quantization and why is it necessary for Mobile Computing?
**Answer:**  
Standard deep learning models use 32-bit floating point weights (`FP32`). A standard BERT model is ~440MB, which causes high RAM pressure, thermal throttling, and battery drain on mobile ARM processors.
- **Quantization** maps 32-bit floats to 8-bit integers (`INT8`):
  $$q = \text{round}\left(\frac{r}{S}\right) + Z$$
- This reduces model size by **75%** (e.g. from 100MB to ~25MB).
- It enables **integer SIMD vector operations** on mobile ARM NEON and NPU hardware, achieving an **order-of-magnitude faster inference** (~12ms) with less than 0.8% loss in classification accuracy.

---

### Question 7: How are the scores aggregated in the Composite Decision Engine?
**Answer:**  
The overall Risk Confidence Score is computed using adaptive weights based on payload characteristics:
- **For Payloads containing a URL:**  
  $$\text{Risk} = 0.45 \times P_{RF} + 0.35 \times S_{NLP} + 0.20 \times A_{Autoencoder}$$
- **For Payloads with only Text / SMS:**  
  $$\text{Risk} = 0.50 \times S_{NLP} + 0.30 \times P_{RF} + 0.20 \times A_{Autoencoder}$$
- **Classification Thresholds:**
  - $\ge 68\%$: **Phishing Attack (Critical Threat)** $\rightarrow$ Triggers heads-up alarm & blocks links.
  - $38\% - 67\%$: **Suspicious Spam (Medium Risk)** $\rightarrow$ Warning alert.
  - $< 38\%$: **Legitimate (Safe)** $\rightarrow$ Allowed and logged.

---

### Question 8: What datasets were used to train and validate PhishGuard AI?
**Answer:**  
Matching our Project Proposal:
1. **Phishing URLs:** PhishTank Dataset, Kaggle Malicious URLs, and OpenPhish active feed.
2. **SMS Phishing (Smishing):** UCI Machine Learning Repository SMS Spam Collection, combined with localized smishing patterns (e.g., bKash, Nagad, and Bangladeshi bank OTP lures).
3. **Email Phishing:** Enron Email Corpus (representing legitimate office communication) combined with the Nazario Phishing Email Corpus.

---

### Question 9: What local database is used and how is it organized?
**Answer:**  
We use **Android Room Persistence Library** (which is an abstraction layer over **SQLite**). The database stores:
- `id`: Auto-generated Long primary key.
- `timestamp`: System epoch millisecond.
- `sourceApp`: Calling application ID (`SMS`, `WHATSAPP`, `GMAIL`, `BROWSER`).
- `sender`: Extracted sender name, phone number, or domain.
- `payloadPreview`: Truncated preview of inspected message.
- `threatCategory`: Category (`Phishing Attack`, `Suspicious Spam`, `Legitimate`).
- `riskScore`: Computed probability (0.0% to 100.0%).
- `isAnomaly`: Boolean flag indicating whether the Autoencoder reconstruction loss exceeded threshold $\epsilon$.

---

### Question 10: What are the key performance metrics of your system?
**Answer:**  
Evaluated on our stratified test dataset:
- **Accuracy:** **98.4%**
- **Precision:** **98.1%** (minimizes annoying false alarms on legitimate communications)
- **Recall:** **97.6%** (catches over 97 out of 100 phishing attempts)
- **F1-Score:** **97.8%**
- **On-Device Inference Latency:** **~12.4 milliseconds** per scan!
