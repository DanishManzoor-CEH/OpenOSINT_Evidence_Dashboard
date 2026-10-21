
import os
import ipaddress
from datetime import datetime, timezone
from social_links import render_social_links_tab
import pandas as pd
import requests
import streamlit as st

from modules.collectors import (
    validate_phone,
    twilio_line_type_lookup,
    check_email,
    hibp_email_breaches,
    search_public_profiles,
    validate_cnic_format,
    official_self_service_links,
    extract_image_metadata,
    build_google_lens_link,
)
from modules.reporting import (
    make_report,
    report_to_json,
    report_to_markdown,
)
from modules.agents import analyze_findings


# --------------------------------------------------
# 1. APP CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="OpenOSINT Evidence Dashboard",
    page_icon="🔎",
    layout="wide",
)

IPGEOLOCATION_ENDPOINT = "https://api.ipgeolocation.io/v3/ipgeo"


# --------------------------------------------------
# 2. SECRET MANAGEMENT
# --------------------------------------------------

def get_secret_value(name, default=""):
    """Read a secret from Streamlit Cloud or environment variables."""
    try:
        value = st.secrets.get(name, default)
    except Exception:
        value = default

    if not value:
        value = os.getenv(name, default)

    return str(value).strip() if value else ""


# Pass existing secrets to modules that read environment variables.
for secret_name in [
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_API_KEY",
    "TWILIO_API_SECRET",
    "TWILIO_API_KEY_SID",
    "TWILIO_API_KEY_SECRET",
    "HIBP_API_KEY",
    "SERPAPI_API_KEY",
    "OPENAI_API_KEY",
    "CREWAI_ENABLED",
]:
    secret_value = get_secret_value(secret_name)
    if secret_value:
        os.environ[secret_name] = secret_value


# --------------------------------------------------
# 3. IP GEOLOCATION API
# --------------------------------------------------

def lookup_ip_geolocation(ip_address):
    """Look up an IPv4/IPv6 address using IPGeolocation.io."""

    raw_ip = (ip_address or "").strip()

    if not raw_ip:
        return {
            "status": "invalid",
            "finding": "Enter a public IPv4 or IPv6 address.",
            "source": "IPGeolocation.io",
            "evidence": {},
        }

    try:
        parsed_ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return {
            "status": "invalid",
            "finding": "The supplied value is not a valid IP address.",
            "source": "IPGeolocation.io",
            "evidence": {"input": raw_ip},
        }

    if not parsed_ip.is_global:
        return {
            "status": "unavailable",
            "finding": (
                "This is not a globally routable public IP address. "
                "Private, loopback, and reserved addresses cannot "
                "be meaningfully geolocated by this public-IP lookup."
            ),
            "source": "IPGeolocation.io",
            "evidence": {"ip": str(parsed_ip)},
        }

    api_key = get_secret_value("IPGEOLOCATION_API_KEY")

    if not api_key:
        return {
            "status": "unavailable",
            "finding": (
                "IPGeolocation.io API key is missing. Add "
                "IPGEOLOCATION_API_KEY to your Streamlit app Secrets."
            ),
            "source": "IPGeolocation.io",
            "evidence": {},
        }

    try:
        response = requests.get(
            IPGEOLOCATION_ENDPOINT,
            params={
                "apiKey": api_key,
                "ip": str(parsed_ip),
            },
            headers={"Accept": "application/json"},
            timeout=20,
        )

        if response.status_code == 401:
            return {
                "status": "error",
                "finding": (
                    "API authentication failed. Verify the API key "
                    "and that your account permits this endpoint."
                ),
                "source": "IPGeolocation.io",
                "evidence": {"http_status": 401},
            }

        if response.status_code == 403:
            return {
                "status": "error",
                "finding": (
                    "Access was forbidden. Check API plan, endpoint "
                    "permissions, and account status."
                ),
                "source": "IPGeolocation.io",
                "evidence": {"http_status": 403},
            }

        if response.status_code == 429:
            return {
                "status": "error",
                "finding": (
                    "API request limit reached. Check your account "
                    "quota and subscription."
                ),
                "source": "IPGeolocation.io",
                "evidence": {"http_status": 429},
            }

        response.raise_for_status()
        data = response.json()

        # Some API response sections may be absent.
        location = data.get("location") or {}
        timezone_info = data.get("time_zone") or {}
        asn_info = data.get("asn") or {}

        latitude = location.get("latitude")
        longitude = location.get("longitude")

        evidence = {
            "ip": data.get("ip", str(parsed_ip)),
            "country": location.get("country_name"),
            "country_code": (
                location.get("country_code2")
                or location.get("country_code")
            ),
            "state_region": location.get("state_prov"),
            "city": location.get("city"),
            "postal_code": location.get("zipcode"),
            "latitude": latitude,
            "longitude": longitude,
            "timezone": timezone_info.get("name"),
            "utc_offset": timezone_info.get("offset"),
            "asn": asn_info.get("as_number"),
            "organization": (
                asn_info.get("organization")
                or asn_info.get("as_name")
            ),
        }

        return {
            "module": "ip_geolocation",
            "status": "success",
            "finding": "IP geolocation lookup completed.",
            "source": "IPGeolocation.io",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence,
            "limitations": [
                "IP geolocation is an estimate based on network data.",
                "The result may represent an ISP gateway or VPN/proxy endpoint.",
                "It does not establish a person's identity or exact physical address.",
                "Missing fields mean the provider did not return that information.",
            ],
        }

    except requests.Timeout:
        return {
            "module": "ip_geolocation",
            "status": "error",
            "finding": "The geolocation request timed out. Please try again.",
            "source": "IPGeolocation.io",
            "evidence": {},
        }

    except requests.HTTPError as exc:
        # Do not display the request URL; it contains the API key.
        status_code = (
            exc.response.status_code
            if exc.response is not None
            else None
        )
        return {
            "module": "ip_geolocation",
            "status": "error",
            "finding": "The geolocation provider returned an HTTP error.",
            "source": "IPGeolocation.io",
            "evidence": {"http_status": status_code},
        }

    except requests.RequestException as exc:
        return {
            "module": "ip_geolocation",
            "status": "error",
            "finding": (
                "Could not connect to the geolocation service: "
                f"{type(exc).__name__}."
            ),
            "source": "IPGeolocation.io",
            "evidence": {},
        }

    except (ValueError, TypeError):
        return {
            "module": "ip_geolocation",
            "status": "error",
            "finding": "The API returned an unexpected response.",
            "source": "IPGeolocation.io",
            "evidence": {},
        }


# --------------------------------------------------
# 4. DASHBOARD HEADER
# --------------------------------------------------

st.title("🔎 OpenOSINT Evidence Dashboard")
st.caption(
    "Public-source research and metadata analysis. Use only data "
    "you are authorized to process. Candidate matches are not proof of identity."
)

with st.expander("Scope and privacy", expanded=True):
    st.write(
        "This tool does not retrieve private CNIC-linked subscriber names, "
        "SIM ownership records, bank accounts, private social-account registrations, "
        "or hidden account data. CNIC checks are format-only. IP geolocation "
        "provides an estimate of network location, not a person's exact location."
    )


# --------------------------------------------------
# 5. NAVIGATION TABS
# --------------------------------------------------


(
    phone_tab,
    email_tab,
    search_tab,
    cnic_tab,
    image_tab,
    geo_tab,
    social_tab,
    report_tab,
) = st.tabs(
    [
        "📱 Phone",
        "📧 Email",
        "🔎 Public Search",
        "🪪 CNIC",
        "🖼️ Image",
        "🌍 Geolocation Analyst",
        "🔗 Social Links",
        "📄 Report",
    ]
)

with social_tab:
    render_social_links_tab()


# --------------------------------------------------
# 6. PHONE TAB
# --------------------------------------------------

with tab_phone:
    st.subheader("Phone number checks")

    phone = st.text_input(
        "Phone number",
        placeholder="+923001234567",
        key="phone_input",
    )
    region = st.selectbox(
        "Default numbering region",
        ["PK", "US", "GB", "IN"],
        index=0,
    )
    use_twilio = st.checkbox(
        "Use Twilio line-type lookup (may incur charges)",
        value=False,
    )

    if st.button("Check phone", key="phone_check"):
        if not phone.strip():
            st.warning("Enter a phone number first.")
        else:
            results = [validate_phone(phone, region)]

            if use_twilio:
                results.append(twilio_line_type_lookup(phone))

            st.session_state.setdefault("last_findings", [])
            st.session_state["last_findings"].extend(results)

            for result in results:
                st.json(result)


# --------------------------------------------------
# 7. EMAIL TAB
# --------------------------------------------------

with tab_email:
    st.subheader("Email checks")

    email = st.text_input("Email address", key="email_input")
    use_hibp = st.checkbox(
        "Search Have I Been Pwned breach records (API key required)",
        value=False,
    )

    if st.button("Check email", key="email_check"):
        if not email.strip():
            st.warning("Enter an email address first.")
        else:
            results = [check_email(email)]

            if use_hibp:
                results.append(hibp_email_breaches(email))

            st.session_state.setdefault("last_findings", [])
            st.session_state["last_findings"].extend(results)

            for result in results:
                st.json(result)


# --------------------------------------------------
# 8. PUBLIC SEARCH TAB
# --------------------------------------------------

with tab_public:
    st.subheader("Public profile and page discovery")

    query = st.text_input(
        "Search query",
        placeholder='e.g. site:github.com "public username"',
        help=(
            "Use public, non-sensitive search terms. Do not attempt "
            "to access private accounts or records."
        ),
    )

    max_results = st.slider(
        "Maximum results",
        min_value=1,
        max_value=10,
        value=5,
    )

    if st.button("Search public pages", key="public_search"):
        if not query.strip():
            st.warning("Enter a public search query.")
        else:
            with st.spinner("Searching public sources..."):
                item = search_public_profiles(query, max_results)

            st.session_state.setdefault("last_findings", [])
            st.session_state["last_findings"].append(item)
            st.json(item)


# --------------------------------------------------
# 9. CNIC TAB
# --------------------------------------------------

with tab_cnic:
    st.subheader("CNIC format and official self-service")

    cnic = st.text_input(
        "CNIC (optional)",
        placeholder="13 digits",
        help="Avoid entering a CNIC unless you have a legitimate reason.",
    )

    if st.button("Check CNIC format", key="cnic_check"):
        if not cnic.strip():
            st.warning("Enter a value first.")
        else:
            item = validate_cnic_format(cnic)
            st.session_state.setdefault("last_findings", [])
            st.session_state["last_findings"].append(item)
            st.json(item)

    st.markdown("**Official self-service references**")
    st.markdown("[Pakistan SIM Information System](https://cnic.sims.pk/)")
    st.markdown("[Pakistan Telecommunication Authority](https://www.pta.gov.pk/)")
    st.caption(
        "These references are for official self-service and guidance. "
        "This application does not query private telecom records."
    )


# --------------------------------------------------
# 10. IMAGE TAB
# --------------------------------------------------

with tab_image:
    st.subheader("Image metadata")

    uploaded_image = st.file_uploader(
        "Upload an image you are authorized to analyze",
        type=["jpg", "jpeg", "png", "tif", "tiff", "webp"],
    )

    if uploaded_image:
        st.image(
            uploaded_image,
            caption="Uploaded image",
            use_container_width=True,
        )

    if st.button("Extract image metadata", key="image_check"):
        if not uploaded_image:
            st.warning("Upload an image first.")
        else:
            item = extract_image_metadata(uploaded_image)
            st.session_state.setdefault("last_findings", [])
            st.session_state["last_findings"].append(item)
            st.json(item)

    st.markdown("**Manual reverse-image search**")

    lens = build_google_lens_link()
    sources = lens.get("sources", [])

    if sources and sources[0].get("url"):
        st.markdown(f"[Open Google Lens]({sources[0]['url']})")
    else:
        st.info("A Google Lens link is not available.")

    st.caption(
        "The link opens the service. This app does not automatically upload "
        "your image or identify people across websites."
    )


# --------------------------------------------------
# 11. GEOLOCATION ANALYST TAB
# --------------------------------------------------

with tab_geo:
    st.subheader("🌍 IP Geolocation Analyst")

    st.write(
        "Look up approximate geographic and network details for a public "
        "IPv4 or IPv6 address using IPGeolocation.io."
    )

    st.info(
        "This tool locates an IP address approximately. It cannot locate "
        "a phone by its phone number or identify a person's exact address."
    )

    with st.form("ip_geolocation_form"):
        ip_input = st.text_input(
            "Public IP address",
            placeholder="e.g. 8.8.8.8",
            help=(
                "Use a public IP. Addresses such as 192.168.1.1 are private "
                "network addresses and cannot be looked up meaningfully."
            ),
        )

        geo_submitted = st.form_submit_button(
            "Locate IP address",
            type="primary",
            use_container_width=True,
        )

    if geo_submitted:
        with st.spinner("Contacting IPGeolocation.io..."):
            geo_result = lookup_ip_geolocation(ip_input)

        st.session_state.setdefault("last_findings", [])
        st.session_state["last_findings"].append(geo_result)

        if geo_result.get("status") != "success":
            st.error(geo_result.get("finding", "Geolocation lookup failed."))
            if geo_result.get("evidence"):
                st.json(geo_result["evidence"])

        else:
            evidence = geo_result.get("evidence", {})
            st.success(geo_result["finding"])

            col1, col2, col3 = st.columns(3)
            col1.metric("IP address", evidence.get("ip") or "Unknown")
            col2.metric("Country", evidence.get("country") or "Unknown")
            col3.metric("City", evidence.get("city") or "Unknown")

            st.markdown("### Location details")

            detail_columns = st.columns(2)

            with detail_columns[0]:
                st.write("**Country code:**", evidence.get("country_code") or "Unknown")
                st.write("**State / region:**", evidence.get("state_region") or "Unknown")
                st.write("**Postal code:**", evidence.get("postal_code") or "Unknown")
                st.write("**Timezone:**", evidence.get("timezone") or "Unknown")

            with detail_columns[1]:
                st.write("**Latitude:**", evidence.get("latitude") or "Unknown")
                st.write("**Longitude:**", evidence.get("longitude") or "Unknown")
                st.write("**ASN:**", evidence.get("asn") or "Unknown")
                st.write(
                    "**Network organization:**",
                    evidence.get("organization") or "Unknown",
                )

            latitude = evidence.get("latitude")
            longitude = evidence.get("longitude")

            if latitude is not None and longitude is not None:
                try:
                    map_frame = pd.DataFrame(
                        [{
                            "latitude": float(latitude),
                            "longitude": float(longitude),
                        }]
                    )

                    st.markdown("### Approximate map location")
                    st.map(
                        map_frame,
                        latitude="latitude",
                        longitude="longitude",
                    )
                except (ValueError, TypeError):
                    st.info("Coordinates were returned but could not be displayed on the map.")

            with st.expander("Full evidence record"):
                st.json(geo_result)

            st.markdown("### Limitations")
            for limitation in geo_result.get("limitations", []):
                st.write(f"- {limitation}")


# --------------------------------------------------
# 12. REPORT TAB
# --------------------------------------------------

with tab_report:
    st.subheader("Evidence report")

    saved_findings = st.session_state.get("last_findings", [])

    st.write(f"Collected finding records: **{len(saved_findings)}**")

    case_label = st.text_input(
        "Report label",
        value="OSINT case",
        key="report_case_label",
    )

    if st.button("Generate report", key="generate_report"):
        try:
            report = make_report(saved_findings, case_label)
            st.session_state["last_report"] = report
            st.session_state["last_analysis"] = analyze_findings(saved_findings)
        except Exception as exc:
            st.error(
                "Could not generate the report. "
                f"Error type: {type(exc).__name__}."
            )

    report = st.session_state.get("last_report")
    analysis = st.session_state.get("last_analysis")

    if report:
        st.json(report["summary"])

        st.download_button(
            "Download JSON",
            data=report_to_json(report),
            file_name="osint_report.json",
            mime="application/json",
        )

        st.download_button(
            "Download Markdown",
            data=report_to_markdown(report),
            file_name="osint_report.md",
            mime="text/markdown",
        )

    if analysis:
        st.markdown("### Analysis")
        st.write(analysis.get("summary", "No summary available."))

        if analysis.get("key_cautions"):
            st.markdown("**Cautions**")
            for caution in analysis["key_cautions"]:
                st.write(f"- {caution}")

        if analysis.get("recommended_next_steps"):
            st.markdown("**Recommended next steps**")
            for step in analysis["recommended_next_steps"]:
                st.write(f"- {step}")

    if st.button("Clear session findings", key="clear_findings"):
        st.session_state["last_findings"] = []
        st.session_state.pop("last_report", None)
        st.session_state.pop("last_analysis", None)
        st.rerun()
