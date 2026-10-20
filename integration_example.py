"""Minimal example: adapt this pattern to your existing app.py."""
import streamlit as st
from phone_intelligence import render_phone_intelligence

st.set_page_config(page_title="OpenOSINT Evidence Dashboard", page_icon="🔎", layout="wide")
st.title("🔎 OpenOSINT Evidence Dashboard")

# In your actual app, keep your existing tabs and add the renderer to the Phone tab.
phone_tab, other_tab = st.tabs(["Phone", "Other modules"])
with phone_tab:
    render_phone_intelligence()
with other_tab:
    st.write("Keep your existing modules here.")
