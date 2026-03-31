import io
import re
import math
import json
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

# Optional ML
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
except Exception:
    TfidfVectorizer = None
    LogisticRegression = None

from report_utils import build_pdf_report


APP_NAME = "DarkHorse API"
DB_PATH = "darkhorse_logs.db"

LABEL_THRESHOLDS = {"safe_max": 30, "suspicious_max": 70}

SUSPICIOUS_TLDS = {"top", "xyz", "zip", "click", "work", "kim", "gq", "tk", "ml", "cf", "ga"}

URL_PHISH_WORDS = [
    "login", "verify", "secure", "update", "bank", "account", "password",
    "signin", "support", "wallet", "payment", "confirm", "otp"
]

KEYWORD_CATEGORIES = {
    "Urgency": ["urgent", "act now", "immediately", "limited time", "final notice", "asap", "last chance", "within 24 hours"],
    "Financial": ["bank", "account", "payment", "transaction", "invoice", "credit", "debit", "card", "refund", "upi", "wallet", "balance"],
    "Credentials / OTP": ["otp", "password", "passcode", "pin", "verification code", "2fa", "security code", "login", "sign in", "authenticate"],
    "Reward / Lottery": ["free", "win", "winner", "prize", "gift", "offer", "reward", "cashback"],
    "Threat / Extortion": ["suspended", "blocked", "terminated", "legal action", "lawsuit", "arrest", "penalty", "fine"],
}

MISINFO_CATEGORIES = {
    "Absolutist language": ["everyone knows", "never", "always", "undeniable", "100% proven", "no doubt"],
    "Conspiracy framing": ["they don't want you to know", "mainstream media", "cover-up", "secret agenda", "deep state"],
    "Call to virality": ["share this", "forward this", "make it viral", "send to everyone", "spread the truth"],
    "Pseudo authority": ["doctor says", "scientists confirm", "experts agree"]  # simplistic; demo only
}


# -----------------------
# Core structures
# -----------------------
@dataclass
class AnalysisResult:
    label: str
    score: int
    confidence: int
    reasons: list
    detected_categories: dict
    highlights: list
    extra: dict


# -----------------------
# DB
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            input_type TEXT NOT NULL,
            input_value TEXT NOT NULL,
            label TEXT NOT NULL,
            score INTEGER NOT NULL,
            confidence INTEGER NOT NULL,
            reasons TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_event(input_type: str, input_value: str, result: AnalysisResult):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (ts_utc, input_type, input_value, label, score, confidence, reasons) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            input_type,
            input_value[:2000],
            result.label,
            int(result.score),
            int(result.confidence),
            json.dumps(result.reasons),
        )
    )
    conn.commit()
    conn.close()


def fetch_logs(limit: int = 200) -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT id, ts_utc, input_type, label, score, confidence, reasons FROM logs ORDER BY id DESC LIMIT ?",
        conn,
        params=(limit,)
    )
    conn.close()
    if not df.empty:
        df["reasons"] = df["reasons"].apply(lambda x: "; ".join(json.loads(x))[:250])
    return df


def clear_logs():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


# -----------------------
# Scoring utils
# -----------------------
def clamp(n: float, lo=0, hi=100) -> int:
    return int(max(lo, min(hi, round(n))))


def label_from_score(score: int) -> str:
    if score <= LABEL_THRESHOLDS["safe_max"]:
        return "Safe"
    if score <= LABEL_THRESHOLDS["suspicious_max"]:
        return "Suspicious"
    return "Malicious"


def confidence_from_score(score: int) -> int:
    x = (score - 50) / 12.0
    conf = 100 / (1 + math.exp(-x))
    return clamp(conf, 55, 98)


def normalize_text(s: str) -> str:
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    return s


# -----------------------
# Keyword/Misinfo detection
# -----------------------
def find_keyword_hits(text: str, categories: dict):
    t = text.lower()
    detected = {}
    highlights = set()
    for cat, kws in categories.items():
        hits = []
        for kw in kws:
            if kw in t:
                hits.append(kw)
                highlights.add(kw)
        if hits:
            detected[cat] = sorted(set(hits))
    return detected, sorted(highlights)


def build_text_reasons(detected_categories: dict):
    reasons = []
    if detected_categories.get("Urgency"):
        reasons.append("Urgency-based language detected (pressure tactics).")
    if detected_categories.get("Financial"):
        reasons.append("Financial keywords detected (possible payment/bank scam).")
    if detected_categories.get("Credentials / OTP"):
        reasons.append("Credential/OTP keywords detected (account takeover risk).")
    if detected_categories.get("Reward / Lottery"):
        reasons.append("Reward/lottery bait detected (common scam pattern).")
    if detected_categories.get("Threat / Extortion"):
        reasons.append("Threat/extortion language detected (scare tactic).")
    return reasons


def build_misinfo_reasons(misinfo_detected: dict):
    reasons = []
    if misinfo_detected.get("Call to virality"):
        reasons.append("Virality prompts detected (encourages rapid forwarding without verification).")
    if misinfo_detected.get("Conspiracy framing"):
        reasons.append("Conspiracy framing detected (common misinformation pattern).")
    if misinfo_detected.get("Absolutist language"):
        reasons.append("Overconfident/absolute claims detected (low evidence style).")
    if misinfo_detected.get("Pseudo authority"):
        reasons.append("Pseudo-authority phrasing detected (may imply evidence without sources).")
    return reasons


# -----------------------
# ML (toy)
# -----------------------
_VEC = None
_CLF = None

def ensure_model():
    global _VEC, _CLF
    if _VEC is not None and _CLF is not None:
        return True
    if TfidfVectorizer is None or LogisticRegression is None:
        return False

    train_texts = [
        "Your account will be suspended. Verify your login immediately.",
        "Urgent: update your bank details to receive refund",
        "Click this link to confirm your OTP and secure your account",
        "Congratulations! You won a prize. Claim your reward now",
        "Limited time offer, act now to get free gift card",
        "Pay the invoice now to avoid legal action",
        "Verify your password to continue using the service",
        "This is a normal meeting reminder for tomorrow",
        "Lunch at 2 pm? Let me know",
        "Here is the document you asked for, thanks",
        "Your order has been delivered successfully",
        "Project status update: tasks completed and next steps"
    ]
    y = [1,1,1,1,1,1,1,0,0,0,0,0]

    _VEC = TfidfVectorizer(ngram_range=(1,2), max_features=2500)
    X = _VEC.fit_transform(train_texts)
    _CLF = LogisticRegression(max_iter=500)
    _CLF.fit(X, y)
    return True


def ml_risk_score_text(text: str) -> int:
    if not ensure_model():
        return -1
    proba = _CLF.predict_proba(_VEC.transform([text]))[0][1]
    return clamp(proba * 100)


# -----------------------
# URL analysis
# -----------------------
def is_ip_host(hostname: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname or ""))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    probs = [c / len(s) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


def analyze_url(url: str) -> AnalysisResult:
    url = url.strip()
    reasons = []
    highlights = []
    score = 0

    if not re.match(r"^https?://", url, re.IGNORECASE):
        parse_target = "http://" + url
        score += 10
        reasons.append("URL missing scheme; often used in deceptive messages.")
    else:
        parse_target = url

    p = urlparse(parse_target)
    host = (p.hostname or "").lower()
    path_q = (p.path or "") + "?" + (p.query or "")

    if p.scheme.lower() == "http":
        score += 15
        reasons.append("Uses HTTP instead of HTTPS (less secure, suspicious for logins).")

    if is_ip_host(host):
        score += 20
        reasons.append("Uses an IP address instead of a normal domain (common in phishing).")

    hits = [w for w in URL_PHISH_WORDS if w in (host + path_q).lower()]
    if hits:
        score += 15 + min(20, 3 * len(hits))
        reasons.append(f"Contains phishing-related keywords: {', '.join(sorted(set(hits)))}")
        highlights.extend(sorted(set(hits)))

    hyphens = host.count("-")
    if hyphens >= 3:
        score += 15
        reasons.append("Unusual domain structure: too many hyphens.")

    parts = [x for x in host.split(".") if x]
    if len(parts) >= 4:
        score += 10
        reasons.append("Too many subdomains (can be used to mimic trusted brands).")

    if "xn--" in host:
        score += 20
        reasons.append("Punycode domain detected (can be used for lookalike attacks).")

    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        score += 10
        reasons.append(f"Suspicious/abused TLD detected: .{tld}")

    if len(url) > 80:
        score += 10
        reasons.append("Very long URL (often used to hide malicious parts).")
    if len(url) > 140:
        score += 10
        reasons.append("Extremely long URL (high risk).")

    ent = shannon_entropy(host)
    if ent > 3.6:
        score += 10
        reasons.append("Domain looks random/high-entropy (possible generated phishing domain).")

    score = clamp(score)
    label = label_from_score(score)
    conf = confidence_from_score(score)

    if not reasons:
        reasons = ["No strong phishing indicators detected in the URL."]

    return AnalysisResult(
        label=label,
        score=score,
        confidence=conf,
        reasons=reasons,
        detected_categories={},
        highlights=highlights,
        extra={"host": host}
    )


# -----------------------
# Text + Misinfo combined
# -----------------------
def analyze_text(text: str) -> AnalysisResult:
    text = normalize_text(text)

    detected, highlights_kw = find_keyword_hits(text, KEYWORD_CATEGORIES)
    misinfo_detected, highlights_mis = find_keyword_hits(text, MISINFO_CATEGORIES)

    reasons = []
    score = 0

    # Threat keyword scoring
    for cat, hits in detected.items():
        score += min(30, 10 * len(hits))
    if detected:
        reasons.extend(build_text_reasons(detected))

    # Misinformation scoring (separate signal, lighter weight)
    misinfo_score = 0
    for cat, hits in misinfo_detected.items():
        misinfo_score += min(20, 7 * len(hits))
    if misinfo_detected:
        reasons.extend(build_misinfo_reasons(misinfo_detected))

    # ML scoring
    ml_score = ml_risk_score_text(text)
    if ml_score >= 0:
        score = clamp(0.6 * ml_score + 0.4 * score)
        reasons.append(f"ML signal indicates risk probability ≈ {ml_score} / 100.")

    # If message contains URL, increase
    if re.search(r"https?://\S+|www\.\S+", text, re.IGNORECASE):
        score = clamp(score + 10)
        reasons.append("Message contains a URL (common delivery method for phishing).")

    # Combine misinformation into final score as additive but capped
    score = clamp(score + min(25, misinfo_score))

    label = label_from_score(score)
    conf = confidence_from_score(score)

    if not reasons:
        reasons = ["No suspicious patterns detected in the text."]

    highlights = sorted(set(highlights_kw + highlights_mis))

    return AnalysisResult(
        label=label,
        score=score,
        confidence=conf,
        reasons=reasons,
        detected_categories={"Threat Keywords": detected, "Misinformation Signals": misinfo_detected},
        highlights=highlights,
        extra={"ml_score": ml_score, "misinfo_score": misinfo_score}
    )


# -----------------------
# FastAPI app
# -----------------------
app = FastAPI(title=APP_NAME)

# Allow Streamlit/React/Flutter later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    init_db()
    ensure_model()


@app.post("/analyze/text")
def api_analyze_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return JSONResponse(status_code=400, content={"error": "Missing 'text'."})

    result = analyze_text(text)
    log_event("text", text, result)
    return asdict(result)


@app.post("/analyze/url")
def api_analyze_url(payload: dict = Body(...)):
    url = payload.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return JSONResponse(status_code=400, content={"error": "Missing 'url'."})

    result = analyze_url(url)
    log_event("url", url, result)
    return asdict(result)


@app.get("/logs")
def api_logs(limit: int = 200):
    df = fetch_logs(limit=limit)
    return {"items": df.to_dict(orient="records")}


@app.post("/logs/clear")
def api_clear_logs():
    clear_logs()
    return {"ok": True}


@app.post("/report/pdf")
def api_pdf_report(payload: dict = Body(...)):
    """
    Expects:
      {
        "input_type": "text"|"url",
        "input_value": "...",
        "result": { ...AnalysisResult dict... }
      }
    """
    input_type = payload.get("input_type", "text")
    input_value = payload.get("input_value", "")
    result = payload.get("result", {})

    pdf_bytes = build_pdf_report(input_type=input_type, input_value=input_value, result=result)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=darkhorse_report.pdf"}
    )