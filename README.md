# 🚀 DarkHorse AI

### Real-Time Digital Threat Intelligence System (PS-402)

---

## 📌 Overview

DarkHorse AI is a real-time system designed to detect **malicious content, phishing attempts, and misinformation** from text and URLs.

It combines:

* Rule-based detection
* Machine Learning
* External Fact-Checking APIs

to generate **accurate, explainable threat intelligence**.

---

## 🎯 Problem Statement

With the rapid growth of digital platforms, users are exposed to:

* Phishing attacks
* Fake news & misinformation
* Malicious URLs

Existing solutions lack **real-time explainability + multi-layer detection**.

---

## 💡 Our Solution

DarkHorse AI provides:

* Instant analysis of text & URLs
* Risk scoring (0–100)
* Threat classification (Safe / Suspicious / Malicious)
* Explainable reasoning
* Real-time fact-checking integration

---

## ⚙️ Tech Stack

### Frontend

* Streamlit

### Backend

* FastAPI

### Machine Learning

* TF-IDF + Logistic Regression

### APIs

* Google Fact Check API

### Database

* SQLite (for logging & monitoring)

---

## 🧠 Architecture

User Input → Streamlit UI → FastAPI Backend
→ Rule Engine + ML Model + Fact Check API
→ Risk Scoring + Explanation
→ Output to UI
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/c99f5572-fb7e-470e-b2ba-1b9bf7792428" />

---

## 🔍 Features  

- Text Analysis (Phishing + Misinformation detection)  
- URL Analysis (Heuristic-based phishing detection)  
- Fact-Check Integration (Google API)  
- Explainable AI (reasons + highlights)  
- Risk Scoring System  
- Monitoring (SQLite logs)  
---

## 🖥️ Demo

### Sample Inputs:

* "URGENT: Verify your bank account now…" → 🔴 Malicious
* "5G towers spread coronavirus" → Fact-check triggered
* Suspicious URLs → flagged with reasons

---

## 📂 Project Structure

```
├── app.py              # Streamlit frontend  
├── api.py              # FastAPI backend  
├── factcheck.py        # Google Fact Check integration  
├── report_utils.py     # PDF report generation  
├── requirements.txt  
├── Procfile  
└── .gitignore  
```

---

## ⚡ How to Run Locally

### 1. Clone repo

```
git clone (https://github.com/Ayush-2005547/DarkHorse-AI)
cd darkhorse-ai
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

### 3. Set environment variable

```
FACT_CHECK_API_KEY=your_api_key
```

### 4. Run backend

```
uvicorn api:app --reload
```

### 5. Run frontend

```
streamlit run app.py
```

---

## ⚠️ Note

* API key is **not included for security reasons**
* Some features (fact-checking) depend on external API availability

---

## 🚀 Future Improvements

* Deep learning (BERT-based detection)
* Browser extension integration
* Real-time social media monitoring
* Advanced threat intelligence dashboard




---

## 🏁 Conclusion

DarkHorse AI delivers a **scalable, explainable, and real-time solution** for detecting digital threats and misinformation — making online environments safer.

---
