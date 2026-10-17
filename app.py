import json
import streamlit as st
from modules.collectors import check_phone, check_email, check_cnic, check_username, analyze_image
from modules.reporting import make_report
from modules.agents import summarize_evidence

st.set_page_config(page_title='OpenOSINT Evidence Dashboard', page_icon='🔎', layout='wide')
st.title('🔎 OpenOSINT Evidence Dashboard')
st.caption('Evidence-first public-data research. Findings are signals, not proof of identity.')
with st.sidebar:
    st.header('Investigation scope')
    st.info('Use only for your own data, consent-based checks, or authorized security research.')
    st.write('This app does not access confidential telecom subscriber databases, bank KYC records, private account registrations, or identify people from faces.')
    st.write('Provider errors and blocked requests are inconclusive, never proof that an account does not exist.')
tabs = st.tabs(['Phone', 'Email', 'CNIC', 'Username / public profiles', 'Image metadata'])
with tabs[0]:
    st.subheader('Phone number checks')
    phone = st.text_input('Phone number (include country code, e.g. +923001234567)', key='phone')
    if st.button('Analyze phone', key='phone_btn'): st.session_state['phone_result'] = check_phone(phone)
    if 'phone_result' in st.session_state: st.json(st.session_state['phone_result'])
with tabs[1]:
    st.subheader('Email address checks')
    email = st.text_input('Email address', key='email')
    if st.button('Analyze email', key='email_btn'): st.session_state['email_result'] = check_email(email)
    if 'email_result' in st.session_state: st.json(st.session_state['email_result'])
with tabs[2]:
    st.subheader('CNIC format and official self-service guidance')
    cnic = st.text_input('CNIC (13 digits; hyphens optional)', placeholder='1234512345671', key='cnic')
    if st.button('Validate CNIC format', key='cnic_btn'): st.session_state['cnic_result'] = check_cnic(cnic)
    if 'cnic_result' in st.session_state: st.json(st.session_state['cnic_result'])
    st.warning('A valid format does not confirm identity or retrieve SIM/bank records.')
    st.markdown('- For SIMs registered to your own CNIC, use the current official PTA/CNIC self-service process or contact your mobile operator.\n- For bank-account ownership, contact the bank through its official verification process.')
with tabs[3]:
    st.subheader('Public username/profile checks')
    username = st.text_input('Username (without @)', key='username')
    platforms = st.multiselect('Platforms', ['GitHub', 'GitLab', 'Reddit', 'Medium', 'Dev.to', 'Hacker News'], default=['GitHub', 'GitLab', 'Reddit', 'Medium', 'Dev.to'])
    if st.button('Check public profile URLs', key='username_btn'): st.session_state['username_result'] = check_username(username, platforms)
    if 'username_result' in st.session_state:
        st.dataframe(st.session_state['username_result'], use_container_width=True, hide_index=True)
        st.caption('HTTP status is only a reachability signal. It does not establish who controls a profile.')
with tabs[4]:
    st.subheader('Image metadata and local comparison')
    uploaded = st.file_uploader('Upload an image you are authorized to analyze', type=['jpg', 'jpeg', 'png', 'webp'])
    if uploaded:
        st.json(analyze_image(uploaded.getvalue(), uploaded.name))
        st.info('Reads metadata and image properties. Does not identify a person or perform face-based identity matching across websites.')
st.divider()
st.subheader('Evidence summary')
st.caption('Optional AI summary. The model can summarize only collected evidence; it cannot verify private records.')
all_results = {k: v for k, v in st.session_state.items() if k.endswith('_result')}
if all_results:
    report = make_report(all_results)
    c1, c2 = st.columns(2)
    with c1: st.download_button('Download JSON evidence', json.dumps(report, indent=2, ensure_ascii=False), 'osint_evidence.json', 'application/json')
    with c2:
        md = '# OpenOSINT Evidence Report\n\n' + '\n'.join(f'## {k}\n\n```json\n{json.dumps(v, indent=2, ensure_ascii=False)}\n```' for k, v in report.items())
        st.download_button('Download Markdown report', md, 'osint_evidence.md', 'text/markdown')
    if st.button('Summarize collected evidence with CrewAI'):
        with st.spinner('Summarizing evidence...'): st.session_state['ai_summary'] = summarize_evidence(report)
    if 'ai_summary' in st.session_state: st.markdown(st.session_state['ai_summary'])
else: st.info('Run a check above to populate evidence and enable report exports.')
