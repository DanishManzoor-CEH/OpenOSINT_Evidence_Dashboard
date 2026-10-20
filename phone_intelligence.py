"""
OpenOSINT Phone Intelligence module
Drop-in Streamlit component for authorized phone-number research.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote
import json
import re
import requests
import streamlit as st
import phonenumbers
from phonenumbers import NumberParseException
from phonenumbers import geocoder as phone_geocoder

REQUEST_TIMEOUT = 12
MAX_PUBLIC_RESULTS = 5
USER_AGENT = "OpenOSINT-Evidence-Dashboard/1.0 (public-source research)"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_secret(name: str, default: str = "") -> str:
    """Read Streamlit secrets first, then environment variables."""
    try:
        value = st.secrets.get(name, default)
        if value:
            return str(value).strip()
    except Exception:
        pass
    import os
    return os.getenv(name, default).strip()


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) <= 4:
        return "*" * len(digits)
    return "+" + ("*" * max(0, len(digits) - 4)) + digits[-4:]


def validate_phone(raw_phone: str, default_region: str = "PK") -> dict:
    """Local numbering-plan validation only; does not verify activity or owner."""
    result = {
        "module": "phone_validation",
        "status": "invalid_input",
        "source": "python-phonenumbers",
        "observed_at": utc_now(),
        "finding": "Enter a valid phone number.",
        "evidence": {},
        "limitations": [
            "Numbering-plan validation does not prove that a number is active or reachable.",
            "This check does not identify the subscriber, owner, or registered accounts.",
        ],
    }
    raw_phone = (raw_phone or "").strip()
    if not raw_phone:
        result["finding"] = "No phone number was entered."
        return result

    try:
        parsed = phonenumbers.parse(raw_phone, default_region or None)
    except NumberParseException as exc:
        result["finding"] = "The number could not be parsed."
        result["evidence"] = {"parse_error": str(exc)}
        return result

    possible = phonenumbers.is_possible_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    region = phonenumbers.region_code_for_number(parsed)
    number_type = phonenumbers.number_type(parsed)
    type_names = {
        0: "fixed_line", 1: "mobile", 2: "fixed_line_or_mobile",
        3: "toll_free", 4: "premium_rate", 5: "shared_cost",
        6: "voip", 7: "personal_number", 8: "pager",
        9: "uan", 10: "voicemail", 99: "unknown"
    }
    result.update({
        "status": "valid_format" if valid else ("possible_format" if possible else "invalid_input"),
        "finding": (
            "Number matches a valid numbering-plan format."
            if valid else
            "Number is possible but not confirmed valid by numbering-plan metadata."
            if possible else
            "Number does not match the numbering-plan rules."
        ),
        "evidence": {
            "input_masked": mask_phone(raw_phone),
            "possible": possible,
            "valid": valid,
            "e164": e164,
            "international_format": international,
            "country_calling_code": parsed.country_code,
            "region": region,
            "number_type_estimate": type_names.get(number_type, "unknown"),
            "national_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            ),
        },
    })
    return result


def twilio_line_type_lookup(e164: str) -> dict:
    """Optional paid Twilio Lookup v2 line-type request. Never logs secrets."""
    
    account_sid = get_secret("TWILIO_ACCOUNT_SID")

api_key = (
    get_secret("TWILIO_API_KEY_SID")
    or get_secret("TWILIO_API_KEY")
)

api_secret = (
    get_secret("TWILIO_API_KEY_SECRET")
    or get_secret("TWILIO_API_SECRET")
)
    

    base = {
        "module": "twilio_line_type",
        "source": "Twilio Lookup v2",
        "observed_at": utc_now(),
        "evidence": {},
        "limitations": [
            "Carrier and line type do not identify the subscriber.",
            "Carrier data can be missing or outdated, especially after number portability.",
            "A successful lookup does not prove current reachability.",
        ],
    }
    if not api_key or not api_secret:
    return {
        **base,
        "status": "unavailable",
        "finding": "Twilio API key credentials are missing.",
        "evidence": {
            "account_sid_found": bool(account_sid),
            "api_key_sid_found": bool(api_key),
            "api_key_secret_found": bool(api_secret),
        },
    }

    url = f"https://lookups.twilio.com/v2/PhoneNumbers/{quote(e164, safe='+')}"
    try:
        response = requests.get(
            url,
            params={"Fields": "line_type_intelligence"},
            auth=(api_key, api_secret),
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code in (401, 403):
            return {
                **base, "status": "unavailable",
                "finding": "Twilio authentication or permission failed.",
                "evidence": {"http_status": response.status_code},
                "limitations": ["Check account credentials, API key permissions, and product access."]
            }
        if response.status_code == 429:
            return {
                **base, "status": "unavailable",
                "finding": "Twilio rate limit reached.",
                "evidence": {"http_status": 429},
                "limitations": ["Retry later and review provider rate limits."]
            }
        if response.status_code == 404:
            return {
                **base, "status": "unavailable",
                "finding": "Twilio did not return a lookup result for this number.",
                "evidence": {"http_status": 404}
            }
        response.raise_for_status()
        data = response.json()
        line = data.get("line_type_intelligence") or {}
        evidence = {
            "phone_number": data.get("phone_number"),
            "valid": data.get("valid"),
            "country_code": data.get("country_code"),
            "carrier_name": line.get("carrier_name"),
            "line_type": line.get("type"),
            "mobile_country_code": line.get("mobile_country_code"),
            "mobile_network_code": line.get("mobile_network_code"),
            "provider_error_code": line.get("error_code"),
        }
        has_carrier_data = any(evidence.get(k) for k in (
            "carrier_name", "line_type", "mobile_country_code", "mobile_network_code"
        ))
        return {
            **base,
            "status": "carrier_identified" if has_carrier_data else "lookup_success",
            "finding": (
                "Twilio returned carrier/line-type information."
                if has_carrier_data else
                "Twilio returned a response, but carrier/line-type details were not supplied."
            ),
            "evidence": evidence,
        }
    except requests.Timeout:
        return {**base, "status": "unavailable", "finding": "Twilio request timed out."}
    except requests.RequestException as exc:
        # Deliberately avoid returning raw response bodies, query URLs, or credentials.
        return {
            **base, "status": "unavailable",
            "finding": "Twilio lookup request failed.",
            "evidence": {"error_type": type(exc).__name__}
        }
    except (ValueError, TypeError):
        return {**base, "status": "unavailable", "finding": "Twilio returned an unreadable response."}


def google_public_search(e164: str, international_format: str, max_results: int = MAX_PUBLIC_RESULTS) -> dict:
    """Optional Google Programmable Search for public web mentions only."""
    api_key = get_secret("GOOGLE_API_KEY")
    cx = get_secret("GOOGLE_CX")
    base = {
        "module": "public_web_search",
        "source": "Google Programmable Search",
        "observed_at": utc_now(),
        "evidence": {"results": []},
        "limitations": [
            "Search results are public indexed pages, not account-registration records.",
            "A page mentioning a number does not prove ownership or current control.",
            "Search coverage is incomplete; no results does not prove absence.",
        ],
    }
    if not (api_key and cx):
        return {
            **base, "status": "unavailable",
            "finding": "Google Programmable Search is not configured."
        }

    # Search exact public mentions; do not search account recovery endpoints.
    queries = list(dict.fromkeys([
        f'"{e164}"',
        f'"{international_format}"',
    ]))
    all_results, seen = [], set()
    try:
        for query in queries:
            response = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cx, "q": query, "num": min(max_results, 5)},
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 403:
                return {
                    **base, "status": "unavailable",
                    "finding": "Google Search API denied the request; check API access, billing, and quota.",
                    "evidence": {"http_status": 403}
                }
            if response.status_code == 429:
                return {
                    **base, "status": "unavailable",
                    "finding": "Google Search API quota or rate limit reached.",
                    "evidence": {"http_status": 429}
                }
            response.raise_for_status()
            data = response.json()
            for item in data.get("items", []):
                link = item.get("link", "")
                if not link.startswith(("https://", "http://")) or link in seen:
                    continue
                seen.add(link)
                all_results.append({
                    "title": item.get("title", "Untitled result"),
                    "url": link,
                    "snippet": item.get("snippet", ""),
                    "query": query,
                    "source_domain": item.get("displayLink", ""),
                })
                if len(all_results) >= max_results:
                    break
            if len(all_results) >= max_results:
                break

        return {
            **base,
            "status": "public_match_found" if all_results else "no_public_matches",
            "finding": (
                f"Found {len(all_results)} public search result(s) to review."
                if all_results else
                "No matching public results were returned by this search."
            ),
            "evidence": {"results": all_results, "result_count": len(all_results)},
        }
    except requests.Timeout:
        return {**base, "status": "unavailable", "finding": "Google Search request timed out."}
    except requests.RequestException as exc:
        return {
            **base, "status": "unavailable",
            "finding": "Google Search request failed.",
            "evidence": {"error_type": type(exc).__name__}
        }
    except (ValueError, TypeError):
        return {**base, "status": "unavailable", "finding": "Google Search returned an unreadable response."}


def run_phone_intelligence(raw_phone: str, default_region: str = "PK",
                           use_twilio: bool = True, use_public_search: bool = True) -> dict:
    validation = validate_phone(raw_phone, default_region)
    evidence = [validation]
    e164 = validation.get("evidence", {}).get("e164")
    international = validation.get("evidence", {}).get("international_format")

    if validation["status"] not in ("valid_format", "possible_format") or not e164:
        return {
            "report_type": "OpenOSINT Phone Intelligence",
            "generated_at": utc_now(),
            "scope": "Authorized phone-number validation and public-source research",
            "overall_status": "invalid_input",
            "phone_masked": mask_phone(raw_phone),
            "checks": evidence,
            "disclaimer": "Candidate matches are not proof of identity. No private account-registration or subscriber data was queried.",
        }

    if use_twilio:
        evidence.append(twilio_line_type_lookup(e164))
    if use_public_search:
        evidence.append(google_public_search(e164, international))

    statuses = [item["status"] for item in evidence]
    if "carrier_identified" in statuses or "public_match_found" in statuses:
        overall = "evidence_returned"
    elif any(s in ("unavailable", "lookup_success") for s in statuses):
        overall = "partial_results"
    else:
        overall = "validation_only"

    return {
        "report_type": "OpenOSINT Phone Intelligence",
        "generated_at": utc_now(),
        "scope": "Authorized phone-number validation and public-source research",
        "overall_status": overall,
        "phone_masked": mask_phone(raw_phone),
        "checks": evidence,
        "disclaimer": (
            "Candidate matches are not proof of identity. Number format and carrier data do not prove "
            "activity, ownership, location, or linked accounts. This report does not query private "
            "CNIC-linked subscriber records, account recovery systems, or hidden account registrations."
        ),
    }


def render_phone_intelligence() -> None:
    """Render this module inside an existing Streamlit app or tab."""
    st.subheader("📞 Phone Number Intelligence")
    st.caption(
        "Numbering-plan validation, optional Twilio carrier lookup, and public web mentions. "
        "Candidate matches are not proof of identity."
    )
    st.info(
        "Privacy scope: this module does not reveal private SIM subscriber names, CNIC-linked "
        "records, Google recovery details, or hidden social-account registrations."
    )

    with st.form("openosint_phone_intelligence_form"):
        raw_phone = st.text_input(
            "Phone number",
            placeholder="+923001234567",
            help="Use international format with +country code where possible."
        )
        region = st.selectbox(
            "Default region for national-format numbers",
            ["PK", "US", "GB", "AE", "SA", "IN", "CA", "AU"],
            index=0,
        )
        c1, c2 = st.columns(2)
        with c1:
            use_twilio = st.checkbox("Run Twilio carrier/line-type lookup (may incur charges)", value=True)
        with c2:
            use_public = st.checkbox("Search public web mentions (Google API required)", value=True)
        authorized = st.checkbox(
            "I am authorized to process this number and will use results lawfully.",
            value=False,
        )
        submitted = st.form_submit_button("Analyze phone number", type="primary")

    if submitted:
        if not authorized:
            st.error("Please confirm that you are authorized to process this number.")
            return
        if not raw_phone.strip():
            st.error("Enter a phone number first.")
            return
        with st.spinner("Running selected checks..."):
            report = run_phone_intelligence(raw_phone, region, use_twilio, use_public)
        st.session_state["openosint_phone_report"] = report

    report = st.session_state.get("openosint_phone_report")
    if not report:
        st.caption("Enter a number and run an analysis to view evidence.")
        return

    status = report.get("overall_status", "unknown")
    st.markdown("#### Assessment")
    st.write(f"**Status:** `{status}`")
    st.write(f"**Number:** `{report.get('phone_masked', 'masked')}`")
    st.write(f"**Generated:** {report.get('generated_at', '')}")
    st.warning(report.get("disclaimer", ""))

    for idx, check in enumerate(report.get("checks", []), start=1):
        with st.expander(f"{idx}. {check.get('module', 'Check')} — {check.get('status', 'unknown')}", expanded=(idx == 1)):
            st.write(check.get("finding", "No finding returned."))
            if check.get("source"):
                st.caption(f"Source: {check['source']} · Observed: {check.get('observed_at', '')}")
            evidence = check.get("evidence") or {}
            results = evidence.get("results") if isinstance(evidence, dict) else None
            if results:
                for item in results:
                    st.markdown(f"**[{item.get('title', 'Public result')}]({item.get('url', '')})**")
                    st.write(item.get("snippet", ""))
                    st.caption(f"Domain: {item.get('source_domain', 'unknown')} · Query: {item.get('query', '')}")
                st.caption("Review each source manually. A result is a lead, not proof of identity.")
                other_evidence = {k: v for k, v in evidence.items() if k != "results"}
                if other_evidence:
                    st.json(other_evidence)
            elif evidence:
                st.json(evidence)
            limitations = check.get("limitations") or []
            if limitations:
                st.markdown("**Limitations**")
                for limitation in limitations:
                    st.markdown(f"- {limitation}")

    json_bytes = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    st.download_button(
        "Download evidence report (JSON)",
        data=json_bytes,
        file_name="openosint_phone_evidence.json",
        mime="application/json",
    )
