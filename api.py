# api.py
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
from dotenv import load_dotenv
load_dotenv()

import os
import requests

FACT_CHECK_API_KEY = os.getenv("FACT_CHECK_API_KEY")
print("FACT KEY:", FACT_CHECK_API_KEY)

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
    "Urgency": ["urgent", "act now", "immediately", "limited time"],
    "Financial": ["bank", "account", "payment", "upi", "wallet"],
    "Credentials / OTP": ["otp", "password", "pin", "login"],
}

MISINFO_CATEGORIES = {
    "Absolutist": ["100% proven", "no doubt", "always"],
    "Conspiracy": ["they don't want you to know", "secret agenda"],
    "Virality": ["share this", "forward this"],
}


# -----------------------
# STRUCT
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
# FACT CHECK (FIXED)
# -----------------------
def get_fact_check_results(query: str):
    if not FACT_CHECK_API_KEY:
        return []

    try:
        url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
        params = {"query": query, "key": FACT_CHECK_API_KEY}

        res = requests.get(url, params=params, timeout=5)

        if res.status_code != 200:
            return []

        data = res.json()
        claims = data.get("claims", [])

        results = []
        for c in claims[:3]:
            review = c.get("claimReview", [{}])[0]

            results.append({
                "text": c.get("text"),
                "rating": review.get("textualRating", "Unknown"),
                "publisher": review.get("publisher", {}).get("name", "Unknown"),
                "url": review.get("url")
            })

        return results

    except Exception as e:
        print("FACT CHECK ERROR:", e)
        return []


# -----------------------
# TEXT ANALYSIS (FIXED)
# -----------------------
def analyze_text(text: str) -> AnalysisResult:
    text = text.lower()

    score = 0
    reasons = []
    highlights = []

    # keyword scoring
    for cat, kws in KEYWORD_CATEGORIES.items():
        for kw in kws:
            if kw in text:
                score += 10
                highlights.append(kw)

    for cat, kws in MISINFO_CATEGORIES.items():
        for kw in kws:
            if kw in text:
                score += 5
                highlights.append(kw)

    # URL present
    if "http" in text:
        score += 10
        reasons.append("Contains URL")

    # FACT CHECK
    fact_results = get_fact_check_results(text)

    if fact_results:
        reasons.append("Fact-check results found")

    # FINAL
    score = min(score, 100)

    if score <= 30:
        label = "Safe"
    elif score <= 70:
        label = "Suspicious"
    else:
        label = "Malicious"

    confidence = min(95, 50 + score)

    return AnalysisResult(
        label=label,
        score=score,
        confidence=confidence,
        reasons=reasons,
        detected_categories={},
        highlights=list(set(highlights)),
        extra={
            "fact_check": fact_results
        }
    )


# -----------------------
# URL ANALYSIS (same)
# -----------------------
def analyze_url(url: str) -> AnalysisResult:
    score = 0
    reasons = []

    if "http://" in url:
        score += 20
        reasons.append("No HTTPS")

    if any(word in url for word in URL_PHISH_WORDS):
        score += 30
        reasons.append("Phishing keywords")

    score = min(score, 100)

    label = "Safe" if score < 30 else "Suspicious"
    confidence = min(95, 50 + score)

    return AnalysisResult(
        label=label,
        score=score,
        confidence=confidence,
        reasons=reasons,
        detected_categories={},
        highlights=[],
        extra={}
    )


# -----------------------
# FASTAPI
# -----------------------
app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/analyze/text")
def api_analyze_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    result = analyze_text(text)
    return asdict(result)


@app.post("/analyze/url")
def api_analyze_url(payload: dict = Body(...)):
    url = payload.get("url", "")
    result = analyze_url(url)
    return asdict(result)