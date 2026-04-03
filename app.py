import json
import time
import requests
import streamlit as st
import pandas as pd
import os

API_BASE = "http://127.0.0.1:8000"


def highlight_text_html(text: str, phrases: list) -> str:
    safe = (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
    for ph in sorted(phrases or [], key=len, reverse=True):
        safe = _ireplace(safe, ph, f"<mark>{ph}</mark>")
    return safe


def _ireplace(text, old, new):
    import re
    return re.compile(re.escape(old), re.IGNORECASE).sub(
        lambda m: new.replace(old, m.group(0)), text
    )


def render_result(result: dict, highlighted_html=None):
    label = result.get("label", "Safe")
    score = int(result.get("score", 0))
    conf = int(result.get("confidence", 0))

    def badge(l):
        return "🟢 SAFE" if l == "Safe" else ("🟡 SUSPICIOUS" if l == "Suspicious" else "🔴 MALICIOUS")

    st.subheader("Result")
    a, b, c = st.columns([1, 1, 2])
    a.metric("Threat Type", badge(label))
    b.metric("Risk Score", f"{score}/100")
    c.metric("Confidence", f"{conf}%")
    st.progress(score)

    st.markdown("**Explanation (why flagged):**")
    for r in result.get("reasons", []):
        st.write(f"- {r}")

    # ✅ FACT CHECK RESULTS
    fact_data = result.get("extra", {}).get("fact_check")
    if fact_data:
        st.markdown("**🧾 Fact Check Results:**")
        for fc in fact_data:
            st.write(f"• {fc.get('rating', 'Unknown')} — {fc.get('publisher', 'Unknown')}")
            if fc.get("url"):
                st.write(fc.get("url"))
    else:
        st.info("No verified fact-checks found for this claim.")

    cats = result.get("detected_categories", {})
    if cats:
        st.markdown("**Detected Signals:**")
        st.json(cats, expanded=False)

    if highlighted_html:
        st.markdown("**Highlighted suspicious terms:**")
        st.markdown(
            f"<div style='padding:10px;border:1px solid #eee;border-radius:8px'>{highlighted_html}</div>",
            unsafe_allow_html=True
        )


def main():
    st.set_page_config(page_title="DarkHorse AI", layout="wide")
    st.title("DarkHorse AI")
    st.caption("Real-Time Digital Threat Intelligence (PS-402)")

    tabs = st.tabs(["📩 Text Analysis", "🔗 URL Analysis", "🧾 Monitoring", "ℹ️ API Health"])

    # ---------------- TEXT ----------------
    with tabs[0]:
        if "text" not in st.session_state:
            st.session_state.text = ""

        sample_cols = st.columns(3)

        if sample_cols[0].button("Sample: Phishing"):
            st.session_state.text = "URGENT: Your bank account will be suspended. Verify login and share OTP immediately: http://secure-login-bank-verify.com"

        if sample_cols[1].button("Sample: Misinformation"):
            st.session_state.text = "They don't want you to know this! 100% proven cure. Share this to everyone before it gets deleted!"

        if sample_cols[2].button("Sample: Safe"):
            st.session_state.text = "Hi, please join the meeting at 3 PM. Agenda attached. Thanks!"

        text = st.text_area("Paste message/email/social content", height=200, key="text")

        if st.button("Analyze Text", type="primary"):
            if not text.strip():
                st.warning("Paste some text.")
            else:
                with st.spinner("Analyzing..."):
                    time.sleep(0.3)
                    try:
                        res = requests.post(f"{API_BASE}/analyze/text", json={"text": text})
                        result = res.json()
                    except Exception:
                        st.warning("Backend not running — showing demo result")
                        result = {
                            "label": "Suspicious" if "urgent" in text.lower() else "Safe",
                            "score": 65 if "urgent" in text.lower() else 10,
                            "confidence": 80,
                            "reasons": ["Demo fallback"],
                            "highlights": ["urgent", "verify"],
                            "extra": {}
                        }

                highlighted = highlight_text_html(text, result.get("highlights", []))
                render_result(result, highlighted_html=highlighted)

    # ---------------- URL ----------------
    with tabs[1]:
        if "url" not in st.session_state:
            st.session_state.url = ""

        sample_cols = st.columns(3)

        if sample_cols[0].button("Sample URL: Suspicious"):
            st.session_state.url = "http://secure-login-bank-verify.com/account/update"

        if sample_cols[1].button("Sample URL: IP"):
            st.session_state.url = "http://185.199.108.153/verify/login"

        if sample_cols[2].button("Sample URL: Safe"):
            st.session_state.url = "https://www.wikipedia.org/"

        url = st.text_input("Paste URL", key="url")

        if st.button("Analyze URL", type="primary"):
            if not url.strip():
                st.warning("Paste a URL.")
            else:
                with st.spinner("Analyzing..."):
                    time.sleep(0.2)
                    try:
                        res = requests.post(f"{API_BASE}/analyze/url", json={"url": url})
                        result = res.json()
                    except Exception:
                        st.warning("Backend not running — demo mode")
                        result = {
                            "label": "Suspicious",
                            "score": 65,
                            "confidence": 80,
                            "reasons": ["Demo fallback"],
                            "extra": {}
                        }

                render_result(result)

    # ---------------- MONITORING ----------------
    with tabs[2]:
        st.subheader("Threat Monitoring")
        st.info("Will activate after deployment")

    # ---------------- API HEALTH ----------------
    with tabs[3]:
        st.write("API Base:", API_BASE)
        st.success("Backend expected at this URL")


if __name__ == "__main__":
    main()