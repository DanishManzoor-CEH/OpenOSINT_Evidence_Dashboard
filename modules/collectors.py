
from __future__ import annotations

import io
import os
import re
import socket
from datetime import datetime, timezone
from urllib.parse import quote_plus, urlencode

import requests
import phonenumbers
import dns.resolver
from PIL import Image, ExifTags


TIMEOUT = 15
USER_AGENT = "OpenOSINT-Evidence-Dashboard/1.0 (public-information research)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})


def result(
    module: str,
    status: str,
    finding: str,
    source: str = "",
    evidence: dict | None = None,
    limitations: list[str] | None = None,
) -> dict:
    """Use a consistent evidence record across all collectors."""
    return {
        "module": module,
        "status": status,
        "finding": finding,
        "source": source,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence or {},
        "limitations": limitations or [],
    }


def validate_phone(phone: str, default_region: str = "PK") -> dict:
    """Validate numbering-plan format; does not identify the subscriber."""
    try:
        parsed = phonenumbers.parse(phone.strip(), default_region)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        return result(
            "phone",
            "verified" if valid else "inconclusive",
            "Number matches a valid numbering-plan format."
            if valid
            else "Number is not confirmed valid by the numbering plan.",
            source="python-phonenumbers",
            evidence={
                "input": phone,
                "possible": possible,
                "valid": valid,
                "e164": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                ),
                "international_format": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                "region": phonenumbers.region_code_for_number(parsed),
            },
            limitations=[
                "Does not prove the number is active or reachable.",
                "Does not identify the subscriber or CNIC owner.",
            ],
        )
    except phonenumbers.NumberParseException as exc:
        return result(
            "phone", "inconclusive", "Could not parse the supplied phone number.",
            evidence={"error": str(exc)},
        )


def twilio_line_type_lookup(phone: str) -> dict:
    """
    Optional Twilio Lookup v2 line-type lookup.
    Set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in environment/secrets.
    This requests line-type information only, not private subscriber identity.
    """
    sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not sid or not token:
        return result(
            "phone_carrier",
            "unavailable",
            "Twilio credentials are not configured.",
            limitations=["Configure Twilio credentials to enable this lookup."],
        )

    try:
        url = (
            "https://lookups.twilio.com/v2/PhoneNumbers/"
            + quote_plus(phone.strip(), safe="")
        )
        response = SESSION.get(
            url,
            params={"Fields": "line_type_intelligence"},
            auth=(sid, token),
            timeout=TIMEOUT,
        )
        if response.status_code >= 400:
            return result(
                "phone_carrier", "unavailable",
                "Twilio Lookup did not return a usable result.",
                source="Twilio Lookup v2",
                evidence={
                    "http_status": response.status_code,
                    "response": response.text[:500],
                },
            )

        data = response.json()
        line = data.get("line_type_intelligence") or {}
        return result(
            "phone_carrier",
            "verified" if line.get("type") else "inconclusive",
            "Returned carrier/line-type metadata." if line else
            "No line-type metadata was returned.",
            source="Twilio Lookup v2",
            evidence={
                "valid": data.get("valid"),
                "country_code": data.get("country_code"),
                "line_type": line.get("type"),
                "carrier": line.get("carrier_name"),
                "error_code": line.get("error_code"),
            },
            limitations=[
                "Carrier information can be unavailable or stale.",
                "This does not establish who owns or uses the number.",
            ],
        )
    except requests.RequestException as exc:
        return result(
            "phone_carrier", "unavailable", "Twilio request failed.",
            source="Twilio Lookup v2", evidence={"error": str(exc)},
        )


def check_email(email: str) -> dict:
    """Check syntax and DNS records; does not confirm mailbox ownership."""
    email = email.strip()
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.fullmatch(pattern, email):
        return result(
            "email", "inconclusive", "Email syntax appears invalid.",
            evidence={"syntax_valid": False},
        )

    domain = email.rsplit("@", 1)[1].lower()
    mx_records = []
    dns_error = None

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_records = sorted(str(item.exchange).rstrip(".") for item in answers)
    except Exception as exc:
        dns_error = str(exc)

    a_records = []
    try:
        a_records = sorted({item[4][0] for item in socket.getaddrinfo(
            domain, None, type=socket.SOCK_STREAM
        )})
    except OSError:
        pass

    return result(
        "email",
        "verified" if mx_records else "inconclusive",
        "Syntax is valid and MX records were found."
        if mx_records else "Syntax is valid, but no MX record was confirmed.",
        source="Email syntax check and DNS",
        evidence={
            "syntax_valid": True,
            "domain": domain,
            "mx_records": mx_records,
            "a_records": a_records,
            "dns_error": dns_error,
        },
        limitations=[
            "DNS records do not prove that this mailbox exists.",
            "Does not prove ownership or list every service using this email.",
        ],
    )


def hibp_email_breaches(email: str) -> dict:
    """Optional Have I Been Pwned account-breach search."""
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return result(
            "email_breaches", "unavailable",
            "HIBP_API_KEY is not configured.",
            source="Have I Been Pwned",
        )

    url = (
        "https://haveibeenpwned.com/api/v3/breachedAccount/"
        + quote_plus(email.strip(), safe="")
    )
    headers = {
        "hibp-api-key": api_key,
        "user-agent": USER_AGENT,
    }

    try:
        response = SESSION.get(
            url, headers=headers, params={"truncateResponse": "false"},
            timeout=TIMEOUT,
        )
        if response.status_code == 404:
            return result(
                "email_breaches", "inconclusive",
                "No breach was returned for this address by HIBP.",
                source="Have I Been Pwned",
                evidence={"http_status": 404},
                limitations=[
                    "Absence from this service does not prove the address was never exposed."
                ],
            )
        if response.status_code != 200:
            return result(
                "email_breaches", "unavailable",
                "HIBP could not complete the lookup.",
                source="Have I Been Pwned",
                evidence={
                    "http_status": response.status_code,
                    "response": response.text[:300],
                },
            )

        breaches = response.json()
        safe_breaches = [
            {
                "name": item.get("Name"),
                "domain": item.get("Domain"),
                "breach_date": item.get("BreachDate"),
                "added_date": item.get("AddedDate"),
                "data_classes": item.get("DataClasses", []),
            }
            for item in breaches
        ]
        return result(
            "email_breaches", "verified",
            f"HIBP returned {len(safe_breaches)} breach record(s).",
            source="Have I Been Pwned",
            evidence={"breach_count": len(safe_breaches), "breaches": safe_breaches},
            limitations=[
                "A breach listing does not prove current account access or compromise.",
                "Have I Been Pwned coverage is not exhaustive.",
            ],
        )
    except requests.RequestException as exc:
        return result(
            "email_breaches", "unavailable", "HIBP request failed.",
            source="Have I Been Pwned", evidence={"error": str(exc)},
        )


def search_public_profiles(query: str, limit: int = 10) -> dict:
    """
    Search public web results via SerpAPI.
    Requires SERPAPI_API_KEY. Results are candidate pages, not identity proof.
    """
    api_key = os.getenv("SERPAPI_API_KEY", "")
    if not api_key:
        return result(
            "public_profiles", "unavailable",
            "SERPAPI_API_KEY is not configured.",
            limitations=["Configure a search provider API key to enable discovery."],
        )

    params = {
        "engine": "google",
        "q": query.strip(),
        "api_key": api_key,
        "num": max(1, min(int(limit), 10)),
    }
    try:
        response = SESSION.get(
            "https://serpapi.com/search.json", params=params, timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        organic = data.get("organic_results", [])
        items = [
            {
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "displayed_source": item.get("source", ""),
            }
            for item in organic[:limit]
            if item.get("link", "").startswith(("https://", "http://"))
        ]
        return result(
            "public_profiles", "candidate" if items else "inconclusive",
            f"Found {len(items)} public search result(s).",
            source="Google results via SerpAPI",
            evidence={"query": query, "results": items},
            limitations=[
                "Search results are candidate pages, not verified account ownership.",
                "Do not use this result alone to link a person to a sensitive identifier.",
            ],
        )
    except (requests.RequestException, ValueError) as exc:
        return result(
            "public_profiles", "unavailable",
            "Public search could not be completed.",
            source="SerpAPI", evidence={"error": str(exc)},
        )


def validate_cnic_format(cnic: str) -> dict:
    """Pakistan CNIC shape check only; no NADRA or private-record lookup."""
    digits = re.sub(r"\D", "", cnic)
    valid_shape = len(digits) == 13

    return result(
        "cnic",
        "inconclusive",
        "CNIC has a 13-digit shape." if valid_shape else
        "CNIC should contain 13 digits.",
        source="Local format validation",
        evidence={
            "format_valid": valid_shape,
            "digits_count": len(digits),
            "masked": ("*" * 9 + digits[-4:]) if valid_shape else None,
        },
        limitations=[
            "Format validation does not authenticate a CNIC.",
            "No NADRA, SIM-registration, subscriber-name, or bank-account records are accessed.",
            "Use official channels for your own records and identity disputes.",
        ],
    )


def official_self_service_links() -> dict:
    return {
        "module": "official_self_service",
        "status": "reference",
        "finding": "Use official channels for your own telecom records.",
        "sources": [
            {
                "name": "Pakistan SIM Information System",
                "url": "https://cnic.sims.pk/",
                "purpose": "Official self-service SIM-count information",
            },
            {
                "name": "Pakistan Telecommunication Authority",
                "url": "https://www.pta.gov.pk/",
                "purpose": "Official telecom guidance and complaint channels",
            },
        ],
        "limitations": [
            "Do not bypass verification or automate access to private subscriber records.",
            "These links do not provide bank-account ownership information.",
        ],
    }


def extract_image_metadata(uploaded_file) -> dict:
    """Read image properties and EXIF; never identify a face or its owner."""
    try:
        raw = uploaded_file.getvalue()
        image = Image.open(io.BytesIO(raw))
        exif_raw = image.getexif()

        exif = {}
        for key, value in exif_raw.items():
            tag = ExifTags.TAGS.get(key, str(key))
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            exif[tag] = str(value)[:500]

        gps_present = any(
            "GPS" in key.upper() for key in exif
        ) or 34853 in exif_raw

        return result(
            "image_metadata", "verified",
            "Image metadata extracted successfully.",
            source="Pillow image metadata parser",
            evidence={
                "filename": getattr(uploaded_file, "name", "uploaded-image"),
                "size_bytes": len(raw),
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
                "exif": exif,
                "gps_metadata_present": gps_present,
            },
            limitations=[
                "EXIF fields may be absent, edited, or inaccurate.",
                "No GPS metadata means no GPS location was extracted.",
                "Image metadata does not identify the people depicted.",
            ],
        )
    except Exception as exc:
        return result(
            "image_metadata", "inconclusive",
            "Could not read image metadata.",
            evidence={"error": str(exc)},
        )


def build_google_lens_link(image_filename: str = "") -> dict:
    """
    Provides a manual reverse-image-search entry point.
    It does not upload the image or claim to perform reverse image search itself.
    """
    return {
        "module": "reverse_image_search",
        "status": "manual",
        "finding": "Use a reverse-image search service manually.",
        "sources": [
            {
                "name": "Google Lens",
                "url": "https://lens.google.com/",
                "purpose": "Compare an image with publicly indexed visual matches",
            }
        ],
        "limitations": [
            "This app does not upload images to Google Lens automatically.",
            "Similar images do not establish that two images depict the same person.",
            "Only upload images you are authorized to share.",
        ],
    }
