
# social_links.py
from urllib.parse import urlparse

import requests
import streamlit as st

OPENWEBNINJA_URL = (
    "https://api.openwebninja.com/"
    "social-links-search/search-social-links"
)

RAPIDAPI_URL = (
    "https://social-links-search.p.rapidapi.com/"
    "search-social-links"
)

NETWORKS = [
    "facebook",
    "tiktok",
    "instagram",
    "snapchat",
    "twitter",
    "youtube",
    "linkedin",
    "github",
    "pinterest",
]

DEFAULT_NETWORKS = [
    "facebook",
    "tiktok",
    "instagram",
    "snapchat",
    "twitter",
    "youtube",
    "linkedin",
    "github",
]


class SocialLinksAPIError(Exception):
    """A safe, user-displayable Social Links Search error."""


def _secret(name, default=""):
    """Read an optional secret without exposing it."""
    try:
        return str(st.secrets.get(name, default)).strip()
    except Exception:
        return default


def search_social_links(
    query,
    social_networks=None,
    provider="OpenWebNinja",
):
    """Search public social profile links through the selected provider."""

    query = str(query or "").strip()

    if not query:
        raise SocialLinksAPIError(
            "Enter a name, username, domain, or public search query."
        )

    if len(query) > 200:
        raise SocialLinksAPIError(
            "The search query must be 200 characters or fewer."
        )

    networks = social_networks or DEFAULT_NETWORKS
    networks = [
        n.lower() for n in networks if n.lower() in NETWORKS
    ]

    if not networks:
        raise SocialLinksAPIError(
            "Select at least one supported social network."
        )

    if provider == "OpenWebNinja":
        api_key = _secret("OPENWEBNINJA_API_KEY")

        if not api_key:
            raise SocialLinksAPIError(
                "OpenWebNinja is not configured. Add "
                "OPENWEBNINJA_API_KEY to Streamlit Secrets."
            )

        url = OPENWEBNINJA_URL
        headers = {"X-API-Key": api_key}

    elif provider == "RapidAPI":
        api_key = _secret("RAPIDAPI_KEY")
        api_host = _secret(
            "RAPIDAPI_SOCIAL_LINKS_HOST",
            "social-links-search.p.rapidapi.com",
        )

        if not api_key:
            raise SocialLinksAPIError(
                "RapidAPI is not configured. Add RAPIDAPI_KEY "
                "to Streamlit Secrets."
            )

        url = RAPIDAPI_URL
        headers = {
            "X-RapidAPI-Key": api_key,
            "X-RapidAPI-Host": api_host,
        }

    else:
        raise SocialLinksAPIError("Unsupported API provider.")

    params = {
        "query": query,
        "social_networks": ",".join(networks),
    }

    try:
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=(5, 25),
        )

    except requests.Timeout:
        raise SocialLinksAPIError(
            "The API request timed out. Try again later."
        ) from None

    except requests.RequestException:
        raise SocialLinksAPIError(
            "Could not connect to the Social Links Search API. "
            "Check the deployment and network status."
        ) from None

    if response.status_code in (401, 403):
        raise SocialLinksAPIError(
            "Authentication failed. Check your API key, provider, "
            "RapidAPI host, and active subscription."
        )

    if response.status_code == 429:
        raise SocialLinksAPIError(
            "The API rate limit or monthly quota has been reached. "
            "Check your provider's usage dashboard."
        )

    if response.status_code >= 500:
        raise SocialLinksAPIError(
            "The API provider returned a server error. Try again later."
        )

    if not response.ok:
        raise SocialLinksAPIError(
            f"The API returned HTTP {response.status_code}. "
            "Check the endpoint, query parameters, and subscription."
        )

    try:
        payload = response.json()
    except ValueError:
        raise SocialLinksAPIError(
            "The API returned an invalid JSON response."
        ) from None

    if not isinstance(payload, dict):
        raise SocialLinksAPIError(
            "The API response had an unexpected format."
        )

    status = str(payload.get("status", "")).upper()
    if status in {"ERROR", "FAILED", "FAILURE"}:
        raise SocialLinksAPIError(
            "The provider reported that the search failed."
        )

    # Some providers wrap network results inside "data".
    results = payload.get("data", payload)

    if not isinstance(results, dict):
        raise SocialLinksAPIError(
            "No usable social network results were returned."
        )

    # Only show networks selected in the interface.
    normalized = {}

    for network in networks:
        entries = results.get(network, [])
        if not isinstance(entries, list):
            continue

        valid_links = []
        for entry in entries:
            if not isinstance(entry, str):
                continue

            link = entry.strip()
            parsed = urlparse(link)

            # Only display normal web links, never executable schemes.
            if (
                parsed.scheme in ("http", "https")
                and parsed.hostname
                and "." in parsed.hostname
            ):
                valid_links.append(link)

        # Remove duplicates while preserving result order.
        normalized[network] = list(dict.fromkeys(valid_links))

    return {
        "query": query,
        "provider": provider,
        "request_id": payload.get("request_id", ""),
        "results": normalized,
        "total": sum(len(v) for v in normalized.values()),
        "http_status": response.status_code,
    }


def render_social_links_tab():
    """Render the Social Links Search feature inside Streamlit."""

    st.subheader("Social Links Search")
    st.caption(
        "Search publicly returned social profile links. "
        "A matching name or username does not prove identity."
    )

    with st.form("social_links_search_form"):
        query = st.text_input(
            "Search query",
            placeholder="Enter a name, username, or domain",
            max_chars=200,
        )

        provider = st.selectbox(
            "API provider",
            ["OpenWebNinja", "RapidAPI"],
            help="Choose the provider for which you configured a secret.",
        )

        networks = st.multiselect(
            "Social networks",
            options=NETWORKS,
            default=DEFAULT_NETWORKS,
            help="Only selected networks are requested and displayed.",
        )

        submitted = st.form_submit_button(
            "Search social links",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        try:
            with st.spinner("Searching public social profile links..."):
                result = search_social_links(
                    query=query,
                    social_networks=networks,
                    provider=provider,
                )

            st.session_state["social_links_last_result"] = result

        except SocialLinksAPIError as exc:
            st.error(str(exc))

    result = st.session_state.get("social_links_last_result")

    if not result:
        st.info(
            "Enter a query and select Search social links to begin."
        )
        return

    st.divider()
    st.markdown("### Search overview")

    metric1, metric2, metric3 = st.columns(3)
    metric1.metric("Profiles returned", result["total"])
    metric2.metric("Networks searched", len(result["results"]))
    metric3.metric("Provider", result["provider"])

    st.caption(f"Query: {result['query']}")

    if result.get("request_id"):
        st.caption(f"Request ID: {result['request_id']}")

    if result["total"] == 0:
        st.warning(
            "No valid profile links were returned for the selected "
            "networks. This does not establish that no profiles exist."
        )
        return

    st.markdown("### Results by social network")

    # Render two columns of independent result sections.
    items = list(result["results"].items())

    for start in range(0, len(items), 2):
        columns = st.columns(2)

        for col, (network, links) in zip(
            columns, items[start:start + 2]
        ):
            with col:
                with st.container(border=True):
                    st.markdown(f"#### {network.title()}")
                    st.metric("Links found", len(links))

                    if not links:
                        st.caption("No links returned.")
                        continue

                    for index, link in enumerate(links, start=1):
                        st.markdown(f"{index}. [{link}]({link})")

    st.caption(
        "Review profiles independently before associating them with "
        "a person. Search results may contain unrelated people."
    )
