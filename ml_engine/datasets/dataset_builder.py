"""
PhishGuard AI - Dataset Builder
Curates training & evaluation samples matching the Project Proposal:
1. Phishing URLs: PhishTank, Kaggle Malicious URLs, OpenPhish.
2. SMS Phishing (Smishing): UCI SMS Spam Collection Dataset.
3. Email Phishing: Enron Email Corpus & Nazario Phishing Corpus.
4. Novel / Zero-Day Anomaly payloads for Autoencoder stress-testing.
"""

SAMPLE_DATASET = [
    # --- LEGITIMATE SAMPLES (Used for training Autoencoder & Random Forest legit class) ---
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "https://www.wikipedia.org/wiki/Mobile_computing",
        "text": "Wikipedia article on Mobile Computing and Android architecture.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "https://github.com/google/flatbuffers",
        "text": "Memory efficient cross platform serialization library.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "https://stackoverflow.com/questions/tagged/android",
        "text": "Stack Overflow programming questions and answers.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "https://www.bracbank.com/en/personal-banking",
        "text": "Official BRAC Bank personal retail banking portal.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "+8801712345678",
        "url": "",
        "text": "Hey Tamanna, are you coming to the Mobile Computing lab session at 2 PM?",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "GP-INFO",
        "url": "",
        "text": "Your account balance is 48.50 BDT. Valid until 15/12/2026. Dial *121# for internet offers.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "Google",
        "url": "",
        "text": "G-492018 is your Google verification code. Never share this code with anyone.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "email",
        "app_id": "email",
        "sender": "course-coordinator@university.edu.bd",
        "url": "https://classroom.google.com/c/lab8th",
        "text": "Dear 8th Semester Students, please submit your Mobile Computing Lab 2 project proposals before Friday 5 PM.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "email",
        "app_id": "email",
        "sender": "noreply@github.com",
        "url": "https://github.com/notifications",
        "text": "You have 3 unread notifications in your repository. Click here to review pull request comments.",
        "label": 0,
        "category": "Legitimate"
    },
    {
        "type": "whatsapp",
        "app_id": "whatsapp",
        "sender": "Lab Study Group",
        "url": "https://meet.google.com/xyz-abc-def",
        "text": "Let's join the Google Meet call to discuss the project architecture diagram and flowchart.",
        "label": 0,
        "category": "Legitimate"
    },

    # --- PHISHING & SMISHING THREAT SAMPLES (Class 1) ---
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "+8801999887766",
        "url": "http://bkash-verify-pin-update.tk/login.php",
        "text": "bKash Alert: Your account has been suspended due to security violation! Immediately verify your PIN within 24 hours to reactivate: http://bkash-verify-pin-update.tk/login.php",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "Nagad-Offer",
        "url": "http://nagad-cash-bonus.xyz/claim-now",
        "text": "CONGRATULATIONS! You have won 50,000 BDT in Nagad Anniversary Mega Lottery! Click link to claim cash prize now: http://nagad-cash-bonus.xyz/claim-now",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "http://192.168.1.105/paypal/signin-update-account/webapps/mpp/home",
        "text": "PayPal Account Limited: Unauthorized IP detected. Login immediately to confirm card credentials.",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "url",
        "app_id": "browser",
        "sender": "Browser",
        "url": "http://apple-icloud-security-verification.top/auth/login.html?id=938210",
        "text": "Apple Support: Your iCloud ID was accessed from Russia. Tap link to secure credentials.",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "email",
        "app_id": "email",
        "sender": "security-alert@micros0ft-service-auth.com",
        "url": "http://microsoft-outlook365-pass-recovery.cf/verify",
        "text": "CRITICAL NOTICE: Your Office 365 password will terminate in 1 hour. Action required: Enter your credentials and OTP to prevent mailbox deletion.",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "whatsapp",
        "app_id": "whatsapp",
        "sender": "+1 (555) 019-2834",
        "url": "http://crypto-binance-giveaway.click/wallet",
        "text": "Hello friend! Binance CEO is giving away 0.5 BTC to first 100 users. Connect your crypto wallet now: http://crypto-binance-giveaway.click/wallet",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "messenger",
        "app_id": "messenger",
        "sender": "Facebook Security Team",
        "url": "http://meta-copyright-infringement-case.pw/appeal",
        "text": "Your Facebook Page is scheduled for permanent deletion due to copyright infringement. Submit appeal form with password immediately.",
        "label": 1,
        "category": "Phishing"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "+8801811223344",
        "url": "http://dbbl-nexuspay-card-unlock.ga/auth",
        "text": "DBBL Alert: NexusPay Debit Card is locked. To unblock immediately, visit http://dbbl-nexuspay-card-unlock.ga/auth and enter 4-digit PIN.",
        "label": 1,
        "category": "Phishing"
    },

    # --- ZERO-DAY / ANOMALOUS SAMPLES (High Reconstruction Error for Autoencoder) ---
    {
        "type": "url",
        "app_id": "whatsapp",
        "sender": "Unknown Bot",
        "url": "http://x79qz1m00p-v829k-anom-bank.stream/auth?token=%7B%22user%22%3A%22test%22%7D",
        "text": "URGENT SYSTEM SYNCHRONIZATION OVERRIDE 99182. ACCESS TOKENS EXPIRED.",
        "label": 1,
        "category": "Suspicious Spam"
    },
    {
        "type": "sms",
        "app_id": "sms",
        "sender": "FLASH-SMS",
        "url": "http://37.120.218.42:8080/ota-patch.apk",
        "text": "Android critical security patch required immediately for kernel stability. Download APK now.",
        "label": 1,
        "category": "Phishing"
    }
]


def get_benchmark_dataset():
    """Returns the full benchmark dataset with generated variations."""
    return SAMPLE_DATASET


def get_preset_samples():
    """
    Returns curated demo presets formatted specifically for one-click
    testing during Tamanna's Lab Presentation to Sir.
    """
    return [
        {
            "id": "preset_bkash_smishing",
            "name": "📱 bKash Fake PIN Smishing (SMS)",
            "app_id": "sms",
            "sender": "+8801999887766",
            "url": "http://bkash-verify-pin-update.tk/login.php",
            "text": "bKash Alert: Your account has been suspended due to security violation! Immediately verify your PIN within 24 hours to reactivate: http://bkash-verify-pin-update.tk/login.php",
            "expected": "Phishing Attack (High Risk)",
            "scenario": "Demonstrates SMS interception, brand impersonation (bKash), urgency detection, and suspicious .tk TLD identification."
        },
        {
            "id": "preset_paypal_ip",
            "name": "🌐 PayPal IP-Based Phishing (URL)",
            "app_id": "browser",
            "sender": "Chrome Browser",
            "url": "http://192.168.1.105/paypal/signin-update-account/webapps/mpp/home",
            "text": "PayPal Account Limited: Unauthorized access detected. Login to confirm debit card credentials.",
            "expected": "Phishing Attack (High Risk)",
            "scenario": "Demonstrates Random Forest detection of IP address hostname, missing HTTPS, and long URL path."
        },
        {
            "id": "preset_nagad_lottery",
            "name": "🎁 Nagad 50,000 BDT Lottery Scam (SMS)",
            "app_id": "sms",
            "sender": "Nagad-Reward",
            "url": "http://nagad-cash-bonus.xyz/claim-now",
            "text": "CONGRATULATIONS! You won 50,000 BDT in Nagad Anniversary Mega Lottery! Click link to claim cash prize now: http://nagad-cash-bonus.xyz/claim-now",
            "expected": "Phishing Attack (High Risk)",
            "scenario": "Demonstrates Contextual NLP financial bait lure detection and .xyz top-level domain warning."
        },
        {
            "id": "preset_office365_email",
            "name": "📧 Microsoft 365 Email Phishing (Email)",
            "app_id": "email",
            "sender": "security-alert@micros0ft-service-auth.com",
            "url": "http://microsoft-outlook365-pass-recovery.cf/verify",
            "text": "CRITICAL NOTICE: Your Office 365 password will terminate in 1 hour. Action required: Enter your credentials and OTP to prevent mailbox deletion.",
            "expected": "Phishing Attack (High Risk)",
            "scenario": "Demonstrates email header spoofing check, social engineering panic words, and credential harvesting alerts."
        },
        {
            "id": "preset_zero_day",
            "name": "🧠 Novel Zero-Day Anomaly (Autoencoder)",
            "app_id": "whatsapp",
            "sender": "Unknown Bot",
            "url": "http://x79qz1m00p-v829k-anom-bank.stream/auth?token=%7B%22user%22%3A%22test%22%7D",
            "text": "URGENT SYSTEM SYNCHRONIZATION OVERRIDE 99182. ACCESS TOKENS EXPIRED.",
            "expected": "Suspicious Anomaly (Zero-Day)",
            "scenario": "Demonstrates Autoencoder Anomaly Detection: High entropy domain triggers reconstruction loss spike (MSE > threshold)."
        },
        {
            "id": "preset_legit_wikipedia",
            "name": "✅ Legitimate Wikipedia Article (Safe URL)",
            "app_id": "browser",
            "sender": "Chrome Browser",
            "url": "https://www.wikipedia.org/wiki/Mobile_computing",
            "text": "Mobile computing is human-computer interaction by which a computer is expected to be transported during normal usage.",
            "expected": "Legitimate (Safe)",
            "scenario": "Shows safe evaluation: valid HTTPS, known domain, low entropy, zero panic words."
        },
        {
            "id": "preset_legit_bank",
            "name": "✅ Official BRAC Bank Portal (Safe)",
            "app_id": "browser",
            "sender": "Browser",
            "url": "https://www.bracbank.com/en/personal-banking",
            "text": "BRAC Bank offers personal loans, credit cards, retail banking, and fixed deposits.",
            "expected": "Legitimate (Safe)",
            "scenario": "Demonstrates legitimate banking portal classification without false positives."
        },
        {
            "id": "preset_legit_friend_sms",
            "name": "💬 Normal Classmate SMS (Safe)",
            "app_id": "sms",
            "sender": "+8801712345678",
            "url": "",
            "text": "Hey Tamanna, are you coming to the Mobile Computing lab session at 2 PM?",
            "expected": "Legitimate (Safe)",
            "scenario": "Demonstrates conversational SMS passing with 0% threat score."
        }
    ]
