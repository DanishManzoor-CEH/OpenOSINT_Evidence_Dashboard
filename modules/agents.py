import os, json
def summarize_evidence(report: dict) -> str:
    api_key = os.getenv('GROQ_API_KEY')
    try:
        import streamlit as st
        api_key = api_key or st.secrets.get('GROQ_API_KEY', '')
    except Exception: pass
    if not api_key: return 'AI summary unavailable: configure GROQ_API_KEY in Streamlit secrets. Evidence collection and report export still work.'
    try:
        from crewai import Agent, Task, Crew, Process, LLM
        llm = LLM(model='groq/llama-3.3-70b-versatile', api_key=api_key, temperature=0.1)
        evidence = json.dumps(report, ensure_ascii=False)[:18000]
        a1 = Agent(role='Evidence Quality Analyst', goal='Separate observations, unavailable checks, and uncertainty.', backstory='Never invent findings or infer identity.', llm=llm, verbose=False, allow_delegation=False)
        a2 = Agent(role='Technical OSINT Analyst', goal='Explain what public technical evidence does and does not support.', backstory='Interpret only supplied evidence and flag unsupported inferences.', llm=llm, verbose=False, allow_delegation=False)
        a3 = Agent(role='Report Reviewer', goal='Produce an evidence-grounded report and safe next steps.', backstory='Reject fabricated identities, bank details, phone links, and subscriber records.', llm=llm, verbose=False, allow_delegation=False)
        t1 = Task(description=f'Review this evidence JSON. List observations, failures and unknowns. Do not infer identity.\n{evidence}', expected_output='Evidence review with observations and unknowns.', agent=a1)
        t2 = Task(description='Interpret the review conservatively. Do not claim private account links.', expected_output='Technical interpretation with confidence limits.', agent=a2, context=[t1])
        t3 = Task(description='Write Markdown with Observed facts, Interpretation, Unknowns, Safe next steps. State that no private databases were queried.', expected_output='Four-section Markdown report.', agent=a3, context=[t1,t2])
        return str(Crew(agents=[a1,a2,a3], tasks=[t1,t2,t3], process=Process.sequential, verbose=False).kickoff())
    except Exception as exc: return f'AI summary failed ({type(exc).__name__}). Evidence remains available; verify API key, model availability, and dependency compatibility.'
