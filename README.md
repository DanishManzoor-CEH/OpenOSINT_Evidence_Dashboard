# OpenOSINT Evidence Dashboard

A Streamlit public-evidence research dashboard with optional CrewAI analysis.

## Scope and limitations

Supports phone numbering-plan checks, email syntax and public DNS/MX checks, CNIC format validation only, public profile URL reachability checks for selected username-based platforms, image dimensions and available EXIF metadata, and JSON/Markdown evidence exports. Optional sequential CrewAI summary uses Groq.

It does **not** access confidential telecom subscriber records, SIM ownership databases, NADRA records, bank KYC/account records, private account-registration data, or perform face recognition/reverse identity matching. Use official channels to verify your own telecom or banking records.

## Local setup (Windows PowerShell)

Install Python 3.12 from https://www.python.org/downloads/

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
streamlit run app.py
```

Add your Groq key to `.streamlit/secrets.toml` to enable AI summaries. Public-data modules work without it.

## GitHub

```powershell
git init
git add .
git status
git commit -m "Initial evidence-first OSINT dashboard"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
git push -u origin main
```

Never commit `.streamlit/secrets.toml`.

## Streamlit Community Cloud

1. Push this project to GitHub.
2. Open https://share.streamlit.io/ and choose **Create app**.
3. Select repository and branch `main`; main file path is `app.py`.
4. Select Python 3.12 in advanced settings.
5. Add `GROQ_API_KEY = "your-key"` in Streamlit Secrets if AI is desired.
6. Deploy, inspect logs, and test each module separately.

## Evidence quality

HTTP 403/429 and network errors are inconclusive. HTTP 200 only indicates a page responded; it does not prove identity. Email syntax does not prove mailbox ownership. IP geolocation is approximate. EXIF data may be absent or edited. Streamlit local filesystem is not durable cloud storage; download reports you need to retain.
