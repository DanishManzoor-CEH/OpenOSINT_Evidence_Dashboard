
import os
import json
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
from modules.reporting import make_report, report_to_json, report_to_markdown
from modules.agents import analyze_findings


st.set_page_config(
    page_title="OpenOSINT Evidence Dashboard",
    page_icon="🔎",
    layout="wide",
)

# Streamlit Cloud secrets are exposed as environment variables for these modules.
for key in [
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "HIBP_API_KEY",
    "SERPAPI_API_KEY",
    "OPENAI_API_KEY",
    "CREWAI_ENABLED",
]:
    if key not in os.environ and key in st.secrets:
        os.environ[key] = str(st.secrets[key])

st.title("🔎 OpenOSINT Evidence Dashboard")
st.caption(
    "Public-source research and metadata analysis. Use only data you are authorized "
    "to process. Candidate matches are not proof of identity."
)

with st.expander("Scope and privacy", expanded=True):
    st.write(
        "This tool does not retrieve private CNIC-linked subscriber names, SIM ownership "
        "records, bank accounts, private social-account registrations, or hidden account "
        "data. CNIC checks are format-only. Do not submit another person's sensitive "
        "identifiers without a lawful basis and appropriate authorization."
    )

findings = []

tab_phone, tab_email, tab_public, tab_cnic, tab_image, tab_report = st.tabs(
    ["Phone", "Email", "Public Search", "CNIC", "Image", "Report"]
)

with tab_phone:
    st.subheader("Phone number checks")
    phone = st.text_input("Phone number", placeholder="+92...")
    region = st.selectbox("Default numbering region", ["PK", "US", "GB", "IN"], index=0)
    use_twilio = st.checkbox("Use Twilio line-type lookup (may incur charges)", value=False)

    if st.button("Check phone", key="phone_check"):
        if not phone.strip():
            st.warning("Enter a phone number first.")
        else:
            phone_result = validate_phone(phone, region)
            findings.append(phone_result)
            if use_twilio:
                carrier_result = twilio_line_type_lookup(phone)
                findings.append(carrier_result)

            st.session_state["last_findings"] = (
                st.session_state.get("last_findings", []) + findings
            )
            for item in findings:
                st.json(item)

with tab_email:
    st.subheader("Email checks")
    email = st.text_input("Email address")
    use_hibp = st.checkbox(
        "Search Have I Been Pwned breach records (API key required)",
        value=False,
    )

    if st.button("Check email", key="email_check"):
        if not email.strip():
            st.warning("Enter an email address first.")
        else:
            findings = [check_email(email)]
            if use_hibp:
                findings.append(hibp_email_breaches(email))

            st.session_state["last_findings"] = (
                st.session_state.get("last_findings", []) + findings
            )
            for item in findings:
                st.json(item)

with tab_public:
    st.subheader("Public profile and page discovery")
    query = st.text_input(
        "Search query",
        placeholder='e.g. site:github.com "public username"',
        help=(
            "Use public, non-sensitive search terms. Avoid searching for private "
            "identifiers or attempting to connect sensitive identifiers to a person."
        ),
    )
    max_results = st.slider("Maximum results", min_value=1, max_value=10, value=5)

    if st.button("Search public pages", key="public_search"):
        if not query.strip():
            st.warning("Enter a public search query.")
        else:
            item = search_public_profiles(query, max_results)
            st.session_state["last_findings"] = (
                st.session_state.get("last_findings", []) + [item]
            )
            st.json(item)

with tab_cnic:
    st.subheader("CNIC format and official self-service")
    cnic = st.text_input(
        "CNIC (optional)",
        placeholder="13 digits",
        help="Avoid entering a CNIC unless you have a legitimate reason to process it.",
    )

    if st.button("Check CNIC format", key="cnic_check"):
        if not cnic.strip():
            st.warning("Enter a value first.")
        else:
            item = validate_cnic_format(cnic)
            st.session_state["last_findings"] = (
                st.session_state.get("last_findings", []) + [item]
            )
            st.json(item)

    st.markdown("**Official self-service references**")
    st.write("Pakistan SIM Information System: https://cnic.sims.pk/")
    st.write("Pakistan Telecommunication Authority: https://www.pta.gov.pk/")
    st.caption(
        "These links are for official self-service and guidance; this application "
        "does not query private telecom or bank records."
    )

with tab_image:
    st.subheader("Image metadata")
    uploaded_image = st.file_uploader(
        "Upload an image you are authorized to analyze",
        type=["jpg", "jpeg", "png", "tif", "tiff", "webp"],
    )
    if uploaded_image:
        st.image(uploaded_image, caption="Uploaded image", use_container_width=True)

    if st.button("Extract image metadata", key="image_check"):
        if not uploaded_image:
            st.warning("Upload an image first.")
        else:
            item = extract_image_metadata(uploaded_image)
            st.session_state["last_findings"] = (
                st.session_state.get("last_findings", []) + [item]
            )
            st.json(item)

    st.markdown("**Manual reverse-image search**")
    lens = build_google_lens_link()
    st.markdown(f"[Open Google Lens]({lens['sources'][0]['url']})")
    st.caption(
        "The link opens the service; this app does not upload your image automatically "
        "or identify people across websites."
    )

with tab_report:
    st.subheader("Evidence report")
    saved_findings = st.session_state.get("last_findings", [])
    st.write(f"Collected finding records: **{len(saved_findings)}**")

    case_label = st.text_input("Report label", value="OSINT case")
    if st.button("Generate report", key="generate_report"):
        report = make_report(saved_findings, case_label)
        st.session_state["last_report"] = report
        st.session_state["last_analysis"] = analyze_findings(saved_findings)

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

if st.button("Clear session findings"):
    st.session_state["last_findings"] = []
    st.session_state.pop("last_report", None)
    st.session_state.pop("last_analysis", None)
    st.rerun()
