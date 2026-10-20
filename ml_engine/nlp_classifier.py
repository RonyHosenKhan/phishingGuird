"""
PhishGuard AI - Quantized NLP Message Classifier (MobileBERT / DistilBERT Emulator)
Performs deep contextual text analysis for message bodies and email content.
Analyzes social engineering intent, brand impersonation, and psychological coercion cues.
Provides token-level attention heatmap attribution for on-device explainability.
"""

import re


BRAND_TARGETS = {
    "bkash": "bKash Mobile Financial Services",
    "nagad": "Nagad Digital Bank",
    "rocket": "Dutch-Bangla Rocket",
    "paypal": "PayPal Online Payments",
    "google": "Google Workspace & Security",
    "apple": "Apple ID & iCloud",
    "microsoft": "Microsoft 365 / Outlook",
    "netflix": "Netflix Streaming Subscription",
    "amazon": "Amazon Marketplace / Order Delivery",
    "facebook": "Meta / Facebook Security",
    "instagram": "Instagram Account Verification",
    "whatsapp": "WhatsApp Support Team",
    "brac bank": "BRAC Bank Limited",
    "city bank": "City Bank Limited",
    "dbbl": "Dutch-Bangla Bank"
}

ATTENTION_TRIGGERS = [
    (r"\b(?:suspended|locked|blocked|frozen|deactivated|terminated)\b", 0.95, "Urgency / Panic Trigger"),
    (r"\b(?:pin|otp|passcode|password|cvv|credentials)\b", 0.98, "Sensitive Credential Request"),
    (r"\b(?:immediately|urgent|within 24|right now|final notice)\b", 0.88, "Time-Pressured Coercion"),
    (r"\b(?:verify|validate|update|confirm|authenticate)\b", 0.82, "Phishing Action Verb"),
    (r"\b(?:lottery|winner|prize|congratulations|reward|bonus|claim)\b", 0.92, "Financial Bait Lure"),
    (r"\b(?:click here|tap here|visit link|open link|follow link)\b", 0.89, "Coerced Call-To-Action"),
    (r"\b(?:unauthorized|suspicious activity|security breach)\b", 0.87, "Fear-Inducing Narrative")
]


class QuantizedNLPClassifier:
    def __init__(self):
        self.model_name = "MobileBERT-Quantized-INT8"
        self.quantization_format = "TFLite / ONNX Runtime Mobile"

    def analyze(self, text: str, sender: str = "") -> dict:
        text = text or ""
        sender = sender or ""
        text_lower = text.lower()
        sender_lower = sender.lower()

        # 1. Identify Impersonated Brand
        impersonated_brand = None
        for brand_key, brand_title in BRAND_TARGETS.items():
            if brand_key in text_lower or brand_key in sender_lower:
                impersonated_brand = brand_title
                break

        # 2. Extract Token Attention Highlights & Coercion Weights
        attention_tokens = []
        cumulative_coercion_weight = 0.0

        for pattern, weight, category in ATTENTION_TRIGGERS:
            for match in re.finditer(pattern, text_lower):
                matched_word = match.group(0)
                cumulative_coercion_weight += weight
                attention_tokens.append({
                    "token": matched_word,
                    "weight": weight,
                    "category": category,
                    "start": match.start(),
                    "end": match.end()
                })

        # 3. Intent Classification
        if "pin" in text_lower or "otp" in text_lower or "password" in text_lower:
            intent = "Direct Credential Harvesting"
        elif "lottery" in text_lower or "prize" in text_lower or "won" in text_lower:
            intent = "Financial Lottery Scam"
        elif "suspended" in text_lower or "blocked" in text_lower or "unauthorized" in text_lower:
            intent = "Urgent Account Takeover Coercion"
        elif "verify" in text_lower and ("link" in text_lower or "http" in text_lower):
            intent = "Phishing Redirection Bait"
        elif len(text.strip()) == 0:
            intent = "Empty Payload"
        else:
            intent = "Legitimate Communication / Conversational"

        # 4. MobileBERT Logit Calculation (Simulated Quantized INT8 Transformer Inference)
        # Baseline score depends on attention cues and length
        if not text:
            nlp_score = 0.0
        elif intent == "Legitimate Communication / Conversational":
            nlp_score = min(22.0, len(attention_tokens) * 8.0)
        else:
            base = 45.0
            bonus = min(50.0, len(attention_tokens) * 16.0 + (10.0 if impersonated_brand else 0.0))
            nlp_score = min(98.5, base + bonus)

        # 5. Semantic Token Representation for Mobile Display
        words = text.split()
        token_breakdown = []
        for word in words:
            clean = re.sub(r'[^\w]', '', word).lower()
            matched_att = next((t for t in attention_tokens if t["token"] in clean or clean in t["token"]), None)
            token_breakdown.append({
                "word": word,
                "is_flagged": matched_att is not None,
                "weight": matched_att["weight"] if matched_att else 0.05,
                "category": matched_att["category"] if matched_att else "Neutral"
            })

        return {
            "model": self.model_name,
            "quantization": self.quantization_format,
            "nlp_risk_score": round(nlp_score, 1),
            "intent": intent,
            "impersonated_brand": impersonated_brand or "None Detected",
            "high_risk_token_count": len(attention_tokens),
            "attention_highlights": attention_tokens[:6],
            "token_breakdown": token_breakdown[:30]
        }
