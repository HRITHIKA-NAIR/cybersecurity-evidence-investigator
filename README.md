# Cybersecurity Evidence Investigator

An AI-assisted cybersecurity investigation tool that analyses suspicious URLs, emails, text, and uploaded files using threat intelligence and evidence-grounded AI reasoning.

Instead of simply predicting whether something is "safe" or "malicious", the system collects evidence, explains its assessment, and allows the user to **challenge the conclusion** through a counter-evidence review.

## Live Demo

**Frontend:** https://evidence-m0j5.onrender.com/`

**Backend API:**  
https://cybersecurity-evidence-investigator.onrender.com

**API Documentation:**  
https://cybersecurity-evidence-investigator.onrender.com/docs

---

## Key Features

- Analyse suspicious URLs, emails, and text
- Upload `.txt` and `.eml` files
- Extract URLs, domains, and email addresses
- Analyse suspicious URL characteristics
- Investigate domains using VirusTotal
- Assess evidence using Google Gemini
- Generate:
  - Threat score from `0–100`
  - Risk verdict
  - Confidence score
  - Evidence-grounded reasoning
- Return `Inconclusive` when evidence is insufficient
- Challenge an AI conclusion with an adversarial second review
- Identify counter-evidence and revise confidence/verdict
- Store investigations using SQLite
- View the latest 10 investigations from the History sidebar

---

## How It Works

```text
User Input / File
        ↓
Indicator Extraction
        ↓
Local URL Analysis
        ↓
VirusTotal Threat Intelligence
        ↓
Gemini Evidence Analysis
        ↓
Threat Score + Verdict + Confidence
        ↓
SQLite Investigation History
        ↓
Challenge Conclusion
        ↓
Counter-Evidence Review
```

The backend uses explicit **FastAPI orchestration** to coordinate each investigation stage.

---

## Evidence-First AI

Gemini is instructed to reason only from evidence collected during the investigation.

The application applies several safeguards:

- HTTPS does not automatically mean a site is legitimate.
- Zero malicious detections do not guarantee safety.
- VirusTotal `undetected` results are not treated as harmless.
- Absence of malicious evidence is not automatically evidence of safety.
- Unsupported prior knowledge about domains or organisations should not influence the assessment.
- Cases with insufficient evidence can return `Inconclusive`.

A deterministic abstention guardrail is also used to reduce false certainty when cybersecurity evidence is unavailable.

---

## Challenge Conclusion

The **Challenge Conclusion** feature performs a second adversarial review of the initial assessment.

It checks whether evidence:

- contradicts the original conclusion,
- weakens it,
- was overlooked,
- was given too much weight,
- or introduces uncertainty.

The review can retain or revise the original verdict and confidence.

---

## Evaluation

The application was evaluated using five controlled test cases:

| Case | Expected | Result |
|---|---|---|
| Benign HTTPS URL | Low Risk | Pass |
| IP-based URL | Suspicious | Pass |
| Multi-subdomain URL | Suspicious | Pass |
| Phishing-style text | Suspicious | Pass |
| Insufficient evidence | Inconclusive | Pass |

**Final evaluation**

- 5 test cases
- 5 correct verdicts
- 0 request errors
- **100% verdict accuracy on the controlled test set**
- **7.59 s average end-to-end latency**

The 100% result refers only to this small controlled evaluation set and is not a claim of universal threat-detection accuracy.

Evaluation data is available in:

```text
data/test_cases/evaluation.json
data/evaluation_results.json
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend | Python, FastAPI, Uvicorn |
| AI | Google Gemini API |
| Threat Intelligence | VirusTotal API |
| Persistence | SQLite |
| HTTP Client | HTTPX |
| Deployment | Render |
| Version Control | Git, GitHub |

---

## Project Structure

```text
cybersecurity-evidence-investigator/
│
├── backend/
│   ├── app/
│   │   ├── tools/
│   │   │   ├── ai_analysis.py
│   │   │   ├── indicators.py
│   │   │   ├── url_analysis.py
│   │   │   └── virustotal.py
│   │   ├── database.py
│   │   └── main.py
│   ├── evaluate.py
│   └── requirements.txt
│
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       └── index.css
│
├── data/
│   ├── test_cases/
│   └── evaluation_results.json
│
├── .env.example
├── .gitignore
└── README.md
```

---

## Local Setup

### Backend

```bash
cd backend
python -m venv venv
```

Activate the virtual environment and install dependencies:

```bash
pip install -r requirements.txt
```

Create a local `.env` file:

```env
GEMINI_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
FRONTEND_ORIGIN=http://localhost:5173
```

Run:

```bash
uvicorn app.main:app --reload --port 8001
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

During local development the frontend falls back to:

```text
http://127.0.0.1:8001
```

For deployment, the frontend uses:

```env
VITE_API_URL=https://your-backend-url
```

API keys remain on the backend and are never exposed through Vite.

---

## Privacy & Security

Submitted domains may be checked using VirusTotal, and submitted content may be processed by Gemini.

Users should avoid submitting confidential or sensitive information.

API keys are stored as backend environment variables and are excluded from Git.

---

## Current Limitations

- Threat-intelligence quality depends on VirusTotal coverage.
- LLM responses can vary despite low-temperature generation.
- A `Low Risk` verdict does not guarantee that content is safe.
- The evaluation dataset is intentionally small.
- SQLite is appropriate for this prototype but not intended as a large-scale production database.
- The free Render deployment uses ephemeral storage, so deployed investigation history may reset after backend restarts.
- The application is an investigation-support prototype and should not replace professional cybersecurity analysis.

---

## About

Built for the **DDS Building AI Application Challenge 2026**.

The project explores how threat intelligence, structured evidence collection, and evidence-grounded LLM reasoning can work together to produce more transparent cybersecurity assessments.