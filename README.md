# OpenOSINT Evidence Dashboard

A Streamlit application for public-source research, phone-number format validation, email DNS and breach checks, image metadata extraction, and evidence-based reporting.

## Features

- **Phone:** Numbering-plan validation using `phonenumbers`; optional Twilio line-type intelligence.
- **Email:** Syntax and DNS checks; optional Have I Been Pwned breach search.
- **Public search:** Search for public webpages and profile candidates through SerpAPI.
- **CNIC:** Local 13-digit format check and links to official self-service resources.
- **Image:** Extract image dimensions, format, EXIF fields, and GPS-metadata presence.
- **Reverse image search:** Manual link to Google Lens.
- **AI analysis:** Optional CrewAI evidence analyst, OSINT analyst, and report reviewer.
- **Reports:** Download findings in JSON and Markdown formats.

## Requirements

- Python 3.12
- Git
- Optional API credentials for external integrations

## Run locally

```bash
python -m venv .venv
```

Activate the environment, then install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

## Configure optional APIs

Create `.streamlit/secrets.toml` using the example template.

- `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN`: optional phone line-type lookup.
- `HIBP_API_KEY`: optional email breach search.
- `SERPAPI_API_KEY`: optional public web search.
- `OPENAI_API_KEY`: optional LLM credentials for CrewAI analysis.
- `CREWAI_ENABLED`: set to `"true"` to enable CrewAI analysis.

Never commit API keys, `.env` files, or the real `secrets.toml` file to source control.

## Run tests

```bash
pytest -q
```

## Deploy on Streamlit Community Cloud

1. Push the project to a GitHub repository.
2. Create a new app in Streamlit Community Cloud.
3. Select the repository and `app.py` as the entry point.
4. Configure API keys in the deployment's app secrets.
5. Deploy and check the logs for dependency or configuration errors.

## Evidence interpretation

- `verified`: a source returned the stated technical result; this does not necessarily verify a person's identity.
- `candidate`: a possible public-page match requiring review.
- `inconclusive`: evidence is insufficient to make the stated determination.
- `unavailable`: a source or integration could not return usable information.
- `reference` or `manual`: a link or manual workflow was provided rather than an automated lookup.

## Important limitations

This project does not access private NADRA records, CNIC-linked subscriber names, bank-account ownership, hidden social-account registrations, or private platform databases. It does not identify people across websites by their faces.

Public search results are leads, not proof. EXIF metadata may be missing or modified. A missing breach record does not prove an email has never been exposed.

Only investigate data you are authorized to process, respect the terms of each provider, and review original evidence before drawing conclusions.
