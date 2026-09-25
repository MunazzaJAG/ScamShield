import re
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__)
CORS(app)


# ============================================================
# CONFIGURATION
# ============================================================

# Classification thresholds
SAFE_THRESHOLD = 20
SUSPICIOUS_THRESHOLD = 40
SPAM_THRESHOLD = 70


# ============================================================
# 1. HIGH-RISK SCAM PHRASES
# ============================================================
# These are phrases that are much stronger indicators of scams
# than generic words such as "verify", "account", etc.

HIGH_RISK_PHRASES = {
    "send money": 30,
    "transfer funds": 30,
    "gift card payment": 35,
    "crypto payment": 35,
    "share your otp": 35,
    "reply with the otp": 35,
    "send your otp": 35,
    "give me your otp": 35,
    "share your password": 35,
    "share your pin": 35,
    "share your cvv": 35,
    "share your banking details": 35,
    "guaranteed profit": 30,
    "guaranteed returns": 30,
    "guaranteed weekly profit": 35,
    "earn guaranteed": 30,
    "professional crypto trader": 30,
    "investment program": 20,
    "weekly profit": 25,
    "you won": 20,
    "claim your prize": 25,
    "claim prize": 25,
    "claim your reward": 25,
    "lottery winner": 30,
    "jackpot": 20,
    "selected as the winner": 30,
    "national lucky draw": 30,
}


# ============================================================
# 2. MEDIUM-RISK PHRASES
# ============================================================

MEDIUM_RISK_PHRASES = {
    "urgent": 5,
    "act now": 10,
    "immediately": 8,
    "final warning": 12,
    "limited time": 5,
    "last chance": 10,
    "verify now": 12,
    "avoid permanent closure": 15,
    "account suspension": 15,
    "account suspended": 15,
    "account will be blocked": 20,
    "prevent data loss": 15,
    "security breach": 15,
    "unauthorized access": 15,
    "device has been infected": 20,
    "infected with a virus": 20,
    "virus detected": 15,
    "malware": 15,
    "hacked": 15,
}


# ============================================================
# 3. CONTEXT-SENSITIVE PHRASES
# ============================================================
# These words are NOT automatically suspicious.
# They become suspicious only when combined with dangerous
# context.

VERIFICATION_WORDS = [
    "verify",
    "verification",
    "kyc",
    "kyc update",
    "kyc verification",
    "confirm your identity",
]

FINANCIAL_CONTEXT = [
    "bank",
    "bank account",
    "payment",
    "credit card",
    "debit card",
    "wallet",
    "money",
    "funds",
    "transaction",
    "otp",
    "password",
    "pin",
    "cvv",
]

ACCOUNT_CONTEXT = [
    "account",
    "login",
    "sign in",
    "password",
    "bank",
    "wallet",
]

THREAT_CONTEXT = [
    "suspended",
    "blocked",
    "closed",
    "closure",
    "terminated",
    "disabled",
    "unauthorized",
    "security breach",
]


# ============================================================
# 4. URL DETECTION
# ============================================================

SHORTENED_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "is.gd",
    "t.co",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
}

BLACKLISTED_PATTERNS = [
    "free-login",
    "verify-account",
    "secure-bank",
    "login-verification",
    "bank-login",
    "account-update",
    "parcel-update",
    "track-parcel",
    "secured-update",
    "phishing",
    "support-microsoft",
]


# ============================================================
# 5. INSTITUTION / BRAND IMPERSONATION
# ============================================================

INSTITUTIONS = [
    "bank",
    "government",
    "amazon",
    "paypal",
    "microsoft",
    "apple",
    "google",
    "customs",
    "police",
    "irs",
    "tax department",
]


# ============================================================
# 6. FEAR / THREAT PHRASES
# ============================================================

FEAR_PHRASES = {
    "your device has been infected": 20,
    "device has been infected": 20,
    "virus detected": 15,
    "infected with a virus": 20,
    "call support immediately": 20,
    "your account will be blocked": 25,
    "avoid permanent closure": 20,
    "data loss": 10,
    "unauthorized access": 15,
    "hacked": 15,
    "malware": 15,
    "security breach": 15,
    "prevent data loss": 15,
    "security support immediately": 20,
}


# ============================================================
# 7. REWARD / LOTTERY
# ============================================================

REWARD_PHRASES = {
    "you won": 20,
    "congratulations winner": 25,
    "claim reward": 20,
    "free prize": 20,
    "jackpot": 20,
    "lottery winner": 30,
    "national lucky draw": 30,
    "selected as the winner": 30,
    "claim your prize": 25,
    "claim your reward": 25,
}


# ============================================================
# 8. LEGITIMATE MESSAGE CONTEXT
# ============================================================
# These patterns help identify normal messages such as:
#
# - Doctor appointments
# - Delivery notifications
# - Reservations
# - Order confirmations
# - Meetings
# - Routine reminders
#
# These DO NOT automatically make a message safe.
# They simply provide legitimate context.

LEGITIMATE_CONTEXTS = {
    "appointment": [
        "appointment",
        "checkup",
        "check-up",
        "doctor",
        "dr.",
        "dentist",
        "dental",
        "clinic",
        "hospital",
        "reschedule",
        "appointment reminder",
    ],

    "delivery": [
        "delivery",
        "package",
        "shipment",
        "tracking",
        "tracking number",
        "courier",
        "delivered",
    ],

    "reservation": [
        "reservation",
        "booking",
        "booked",
        "table",
        "restaurant reservation",
        "hotel reservation",
        "check-in",
        "check in",
    ],

    "transaction": [
        "receipt",
        "invoice",
        "purchase",
        "order confirmation",
        "transaction",
        "payment received",
        "payment successful",
    ],

    "meeting": [
        "meeting",
        "calendar",
        "conference",
        "appointment",
        "scheduled",
        "reminder",
    ],

    "education": [
        "class",
        "lecture",
        "assignment",
        "exam",
        "school",
        "college",
        "university",
        "teacher",
        "professor",
    ],
}


# ============================================================
# 9. MARKETING / SPAM PATTERNS
# ============================================================
# Marketing messages are not necessarily scams.
# They should generally be classified as SPAM.

MARKETING_PHRASES = {
    "20% off": 10,
    "10% off": 10,
    "30% off": 10,
    "40% off": 10,
    "50% off": 10,
    "discount": 8,
    "special offer": 10,
    "exclusive offer": 10,
    "limited time offer": 12,
    "shop now": 10,
    "buy now": 10,
    "sale": 8,
    "promo": 8,
    "promotional": 8,
    "use code": 8,
    "coupon": 8,
    "free shipping": 8,
    "text stop to opt-out": 10,
    "text stop to opt out": 10,
    "unsubscribe": 8,
}


# ============================================================
# 10. PREPROCESSING
# ============================================================

def preprocess_message(text):
    """
    Normalize the message while preserving URLs separately.
    """

    text = str(text)

    text_lower = text.lower()

    # --------------------------------------------------------
    # Extract full URLs
    # --------------------------------------------------------

    url_pattern = re.compile(
        r'https?://[^\s]+',
        re.IGNORECASE
    )

    urls = url_pattern.findall(text_lower)

    # --------------------------------------------------------
    # Extract bare domains
    # --------------------------------------------------------

    bare_domain_pattern = re.compile(
        r'(?<!\w)'
        r'[\w\-]+\.'
        r'(?:com|net|org|io|xyz|info|co|in|uk)'
        r'(?:/[^\s]*)?',
        re.IGNORECASE
    )

    bare_domains = bare_domain_pattern.findall(text_lower)

    all_urls = urls + bare_domains

    # --------------------------------------------------------
    # Remove punctuation for phrase matching
    # --------------------------------------------------------

    text_no_punct = re.sub(
        r'[^\w\s]',
        ' ',
        text_lower
    )

    tokens = text_no_punct.split()

    processed_text = " ".join(tokens)

    return processed_text, tokens, all_urls


# ============================================================
# 11. PHRASE MATCHING
# ============================================================

def phrase_exists(text, phrase):
    """
    Checks whether a phrase exists as a complete phrase.

    Using word boundaries prevents things like:
        "bank" matching "banking"
    unintentionally.
    """

    escaped_phrase = re.escape(phrase.lower())

    pattern = rf'(?<!\w){escaped_phrase}(?!\w)'

    return re.search(
        pattern,
        text.lower()
    ) is not None


# ============================================================
# 12. LEGITIMATE CONTEXT DETECTION
# ============================================================

def detect_legitimate_context(text):
    """
    Returns legitimate contexts that have multiple matching signals.
    """

    detected_contexts = []

    for context, phrases in LEGITIMATE_CONTEXTS.items():

        matches = 0

        for phrase in phrases:
            if phrase_exists(text, phrase):
                matches += 1

        # Require at least two related signals.
        if matches >= 2:
            detected_contexts.append(context)

    return detected_contexts


# ============================================================
# 13. URL ANALYSIS
# ============================================================

def analyze_urls(urls):
    """
    Analyze URLs and return:
        score
        reasons
        suspicious_link
    """

    score = 0
    reasons = []
    suspicious_link = False

    for url in urls:

        clean_url = url.rstrip(".,!?;:)]}")

        # ----------------------------------------------------
        # Extract hostname
        # ----------------------------------------------------

        try:

            parsed = urlparse(clean_url)

            hostname = parsed.netloc.lower()

            # Bare domains don't have a scheme, so parse again
            if not hostname:
                hostname = parsed.path.split("/")[0].lower()

            hostname = hostname.removeprefix("www.")

        except Exception:
            hostname = ""

        # ----------------------------------------------------
        # Shortened URL
        # ----------------------------------------------------

        if hostname in SHORTENED_DOMAINS:

            score += 15
            suspicious_link = True

            reasons.append(
                "Suspicious shortened link detected"
            )

        # ----------------------------------------------------
        # Suspicious URL pattern
        # ----------------------------------------------------

        url_lower = clean_url.lower()

        for pattern in BLACKLISTED_PATTERNS:

            if pattern in url_lower:

                score += 40
                suspicious_link = True

                reasons.append(
                    "Suspicious phishing URL pattern detected"
                )

                break

    return score, reasons, suspicious_link


# ============================================================
# 14. CONTEXT-SENSITIVE VERIFICATION DETECTION
# ============================================================

def analyze_verification_context(text):
    """
    'verify' by itself is not suspicious.

    Examples:

        Verify your appointment.
            -> normal

        Verify your bank account immediately.
            -> suspicious
    """

    score = 0
    reasons = []

    has_verification = any(
        phrase_exists(text, phrase)
        for phrase in VERIFICATION_WORDS
    )

    if not has_verification:
        return score, reasons

    has_financial_context = any(
        phrase_exists(text, phrase)
        for phrase in FINANCIAL_CONTEXT
    )

    has_account_context = any(
        phrase_exists(text, phrase)
        for phrase in ACCOUNT_CONTEXT
    )

    has_threat = any(
        phrase_exists(text, phrase)
        for phrase in THREAT_CONTEXT
    )

    # --------------------------------------------------------
    # Verification + financial/account context
    # --------------------------------------------------------

    if has_financial_context and has_account_context:

        score += 20

        reasons.append(
            "Verification request involves account or financial information"
        )

    # --------------------------------------------------------
    # Verification + threat
    # --------------------------------------------------------

    if has_threat:

        score += 20

        reasons.append(
            "Verification request combined with an account threat"
        )

    return score, reasons


# ============================================================
# 15. COMBINATION / BEHAVIOR DETECTION
# ============================================================

def analyze_combinations(text):
    """
    Detect combinations that are much more suspicious than
    individual words.
    """

    score = 0
    reasons = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    urgency = any(
        phrase_exists(text, phrase)
        for phrase in [
            "urgent",
            "act now",
            "immediately",
            "final warning",
            "last chance",
            "verify now",
        ]
    )

    # --------------------------------------------------------
    # Financial request
    # --------------------------------------------------------

    financial = any(
        phrase_exists(text, phrase)
        for phrase in [
            "send money",
            "transfer funds",
            "gift card payment",
            "crypto payment",
            "share your otp",
            "reply with the otp",
            "share your password",
            "share your pin",
            "share your cvv",
        ]
    )

    # --------------------------------------------------------
    # Threat
    # --------------------------------------------------------

    threat = any(
        phrase_exists(text, phrase)
        for phrase in [
            "account will be blocked",
            "account suspended",
            "permanent closure",
            "avoid permanent closure",
            "data loss",
            "security breach",
        ]
    )

    # --------------------------------------------------------
    # Urgency + financial request
    # --------------------------------------------------------

    if urgency and financial:

        score += 25

        reasons.append(
            "Urgency combined with a financial or credential request"
        )

    # --------------------------------------------------------
    # Urgency + threat
    # --------------------------------------------------------

    if urgency and threat:

        score += 25

        reasons.append(
            "Urgency combined with a threat"
        )

    # --------------------------------------------------------
    # Financial + threat
    # --------------------------------------------------------

    if financial and threat:

        score += 30

        reasons.append(
            "Financial or credential request combined with an account threat"
        )

    return score, reasons


# ============================================================
# 16. MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_message(text):
    if not isinstance(text, str):
        text = str(text)

    if not text.strip():
        return {
            "classification": "Safe",
            "risk_score": 0,
            "reasons": ["Empty message"],
        }

    processed_text, tokens, urls = preprocess_message(text)

    risk_score = 0
    reasons = []

    # ========================================================
    # 1. DETECT LEGITIMATE CONTEXT FIRST
    # ========================================================

    legitimate_contexts = detect_legitimate_context(
        processed_text
    )

    is_routine_message = len(legitimate_contexts) > 0

    # ========================================================
    # 2. DETECT STRONG SCAM SIGNALS
    # ========================================================

    strong_scam_signals = 0

    # --------------------------------------------------------
    # OTP / credential theft
    # --------------------------------------------------------

    credential_phrases = [
        "share your otp",
        "reply with the otp",
        "send your otp",
        "give me your otp",
        "share your password",
        "share your pin",
        "share your cvv",
        "share your banking details",
    ]

    credential_matches = []

    for phrase in credential_phrases:
        if phrase_exists(processed_text, phrase):
            credential_matches.append(phrase)

    if credential_matches:
        risk_score += 35
        strong_scam_signals += 1

        reasons.append(
            "Request for sensitive credentials or OTP detected"
        )

    # --------------------------------------------------------
    # Direct financial requests
    # --------------------------------------------------------

    financial_phrases = [
        "send money",
        "transfer funds",
        "gift card payment",
        "crypto payment",
        "pay immediately",
        "make a payment",
        "send payment",
    ]

    financial_matches = []

    for phrase in financial_phrases:
        if phrase_exists(processed_text, phrase):
            financial_matches.append(phrase)

    if financial_matches:
        risk_score += 30
        strong_scam_signals += 1

        reasons.append(
            "Direct financial request detected"
        )

    # ========================================================
    # 3. SUSPICIOUS URL ANALYSIS
    # ========================================================

    url_score, url_reasons, has_suspicious_link = (
        analyze_urls(urls)
    )

    if has_suspicious_link:
        risk_score += url_score
        strong_scam_signals += 1
        reasons.extend(url_reasons)

    # ========================================================
    # 4. THREAT ANALYSIS
    # ========================================================

    threat_phrases = [
        "account will be blocked",
        "account will be suspended",
        "account suspended",
        "avoid permanent closure",
        "permanent closure",
        "your device has been infected",
        "device has been infected",
        "virus detected",
        "security breach",
        "unauthorized access",
        "your account will be closed",
        "your account will be terminated",
    ]

    threat_matches = []

    for phrase in threat_phrases:
        if phrase_exists(processed_text, phrase):
            threat_matches.append(phrase)

    if threat_matches:
        risk_score += 20
        strong_scam_signals += 1

        reasons.append(
            "Threat or fear-based language detected"
        )

    # ========================================================
    # 5. URGENCY
    # ========================================================

    urgency_phrases = [
        "act now",
        "immediately",
        "final warning",
        "last chance",
        "verify now",
        "urgent",
        "respond immediately",
    ]

    urgency_detected = False

    for phrase in urgency_phrases:
        if phrase_exists(processed_text, phrase):
            urgency_detected = True
            break

    # IMPORTANT:
    #
    # Urgency alone is NOT enough to make something suspicious.
    #
    # "Please respond immediately to confirm your appointment"
    # can be legitimate.
    #
    # Urgency becomes meaningful when combined with a strong
    # scam signal.

    if urgency_detected and strong_scam_signals > 0:

        risk_score += 15

        reasons.append(
            "Urgency combined with suspicious activity"
        )

    # ========================================================
    # 6. VERIFICATION ANALYSIS
    # ========================================================

    verification_detected = any(
        phrase_exists(processed_text, phrase)
        for phrase in [
            "verify",
            "verification",
            "verify now",
            "kyc",
            "kyc verification",
            "confirm your identity",
        ]
    )

    financial_context = any(
        phrase_exists(processed_text, phrase)
        for phrase in [
            "bank",
            "bank account",
            "payment",
            "credit card",
            "debit card",
            "wallet",
            "otp",
            "password",
            "pin",
            "cvv",
        ]
    )

    account_context = any(
        phrase_exists(processed_text, phrase)
        for phrase in [
            "account",
            "login",
            "sign in",
            "bank",
            "wallet",
        ]
    )

    # Verification is suspicious ONLY when it concerns
    # sensitive account/financial information.

    if (
        verification_detected
        and financial_context
        and account_context
    ):

        risk_score += 20
        strong_scam_signals += 1

        reasons.append(
            "Verification request involves sensitive account or financial information"
        )

    # ========================================================
    # 7. REWARD / LOTTERY
    # ========================================================

    reward_phrases = [
        "you won",
        "claim your prize",
        "claim your reward",
        "lottery winner",
        "jackpot",
        "selected as the winner",
        "free prize",
        "congratulations winner",
    ]

    reward_detected = any(
        phrase_exists(processed_text, phrase)
        for phrase in reward_phrases
    )

    if reward_detected:

        risk_score += 25
        strong_scam_signals += 1

        reasons.append(
            "Reward or lottery language detected"
        )

    # ========================================================
    # 8. INVESTMENT / CRYPTO SCAM
    # ========================================================

    crypto_phrases = [
        "guaranteed profit",
        "guaranteed returns",
        "guaranteed weekly profit",
        "earn guaranteed",
        "weekly profit",
        "professional crypto trader",
        "crypto investment",
        "investment program",
        "40% weekly",
        "40 percent weekly",
    ]

    crypto_detected = any(
        phrase_exists(processed_text, phrase)
        for phrase in crypto_phrases
    )

    if crypto_detected:

        risk_score += 35
        strong_scam_signals += 1

        reasons.append(
            "Potential investment or crypto fraud language detected"
        )

    # ========================================================
    # 9. INSTITUTION IMPERSONATION
    # ========================================================

    institution_detected = any(
        phrase_exists(processed_text, institution)
        for institution in INSTITUTIONS
    )

    # Institution alone is NOT suspicious.
    #
    # Example:
    # "Your appointment at Microsoft tomorrow..."
    #
    # should not automatically become suspicious.
    #
    # Institution + threat/credential request/link is different.

    if institution_detected:

        if (
            has_suspicious_link
            or credential_matches
            or threat_matches
            or (
                verification_detected
                and account_context
            )
        ):

            risk_score += 20

            reasons.append(
                "Possible institution impersonation"
            )

    # ========================================================
    # 10. MARKETING / PROMOTIONAL CONTENT
    # ========================================================

    marketing_phrases = [
        "discount",
        "% off",
        "special offer",
        "exclusive offer",
        "limited time offer",
        "shop now",
        "buy now",
        "sale",
        "promo",
        "coupon",
        "use code",
        "free shipping",
        "text stop to opt-out",
        "text stop to opt out",
        "unsubscribe",
    ]

    marketing_detected = any(
        phrase_exists(processed_text, phrase)
        for phrase in marketing_phrases
    )

    if marketing_detected:

        # Marketing is spam-like, but NOT automatically a scam.
        #
        # Only give it a small score.

        risk_score += 10

        reasons.append(
            "Promotional or marketing language detected"
        )

    # ========================================================
    # 11. LEGITIMATE CONTEXT PROTECTION
    # ========================================================
    #
    # This is the important part.
    #
    # A normal appointment/reminder should not get a high
    # score just because it contains words such as:
    #
    # reminder
    # confirm
    # call
    # doctor
    # appointment
    #
    # If it contains no strong scam signals, force the score
    # very low.

    if is_routine_message:

        # If there are NO strong scam signals:
        if strong_scam_signals == 0:

            # Normal routine messages should be essentially safe.
            risk_score = min(
                risk_score,
                5
            )

            reasons.append(
                f"Routine {legitimate_contexts[0]} notification detected"
            )

        # If there is only one weak signal and no dangerous
        # credential/financial request:
        elif (
            strong_scam_signals == 1
            and not credential_matches
            and not financial_matches
            and not has_suspicious_link
            and not crypto_detected
            and not reward_detected
        ):

            risk_score = min(
                risk_score,
                20
            )

            reasons.append(
                f"Message contains legitimate {legitimate_contexts[0]} context"
            )

    # ========================================================
    # 12. STRUCTURAL ANOMALIES
    # ========================================================

    caps_count = sum(
        1
        for character in text
        if character.isupper()
    )

    alpha_count = sum(
        1
        for character in text
        if character.isalpha()
    )

    caps_ratio = (
        caps_count / alpha_count
        if alpha_count > 0
        else 0
    )

    # Don't penalize short messages for capitalization.

    if (
        caps_ratio > 0.65
        and alpha_count >= 20
    ):

        risk_score += 5

        reasons.append(
            "Excessive use of capital letters"
        )

    # Multiple exclamation marks

    if text.count("!") >= 3:

        risk_score += 3

        reasons.append(
            "Multiple exclamation marks detected"
        )

    # ========================================================
    # 13. FINAL SCORE
    # ========================================================

    risk_score = max(
        0,
        min(100, risk_score)
    )

    # ========================================================
    # 14. CLASSIFICATION
    # ========================================================

    if risk_score <= 20:

        classification = "Safe"

    elif risk_score <= 40:

        classification = "Suspicious"

    elif risk_score <= 70:

        classification = "Spam"

    else:

        classification = "Scam"

    # ========================================================
    # 15. REMOVE DUPLICATE REASONS
    # ========================================================

    unique_reasons = []

    for reason in reasons:

        if reason not in unique_reasons:
            unique_reasons.append(reason)

    # ========================================================
    # 16. RETURN RESULT
    # ========================================================

    return {
        "classification": classification,
        "risk_score": risk_score,
        "reasons": unique_reasons,
    }


# ============================================================
# API: TEXT ANALYSIS
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json(silent=True)

        if not data:

            return jsonify({
                "error": "Invalid or missing JSON body"
            }), 400

        if "message" not in data:

            return jsonify({
                "error": "No message provided"
            }), 400

        message = data["message"]

        if not isinstance(message, str):

            return jsonify({
                "error": "Message must be a string"
            }), 400

        result = analyze_message(message)

        return jsonify(result), 200

    except Exception as error:

        print("Analysis error:", error)

        return jsonify({
            "error": "An error occurred while analyzing the message"
        }), 500


# ============================================================
# API: MEDIA ANALYSIS
# ============================================================

@app.route("/api/analyze-media", methods=["POST"])
def analyze_media():

    try:

        if "file" not in request.files:

            return jsonify({
                "error": "No file provided"
            }), 400

        file = request.files["file"]

        if not file:

            return jsonify({
                "error": "Invalid file"
            }), 400

        data = file.read()

        file_size = len(data)

        # ----------------------------------------------------
        # Deterministic demo score
        # ----------------------------------------------------

        score = (
            file_size * 31 + 7
        ) % 101

        confidence = (
            (file_size * 17 + 41) % 21
        ) + 75

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if score > 70:

            level = "danger"

        elif score > 30:

            level = "suspicious"

        else:

            level = "safe"

        return jsonify({
            "score": score,
            "confidence": confidence,
            "level": level,
        }), 200

    except Exception as error:

        print("Media analysis error:", error)

        return jsonify({
            "error": "An error occurred while analyzing the media"
        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok"
    }), 200


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
