
from __future__ import annotations

import json
import os


def analyze_findings(findings: list[dict]) -> dict:
    """
    Run a small CrewAI analysis when configured.
    Falls back to a deterministic summary if CrewAI or an LLM key is unavailable.
    """
    verified = [f for f in findings if f.get("status") == "verified"]
    candidates = [f for f in findings if f.get("status") == "candidate"]
    unavailable = [f for f in findings if f.get("status") == "unavailable"]

    fallback = {
        "analysis_method": "deterministic_fallback",
        "summary": (
            f"Reviewed {len(findings)} finding(s): "
            f"{len(verified)} verified-status record(s), "
            f"{len(candidates)} candidate result(s), and "
            f"{len(unavailable)} unavailable integration(s)."
        ),
        "key_cautions": [
            "A format-valid phone number does not identify its subscriber.",
            "A public search result does not prove account ownership.",
            "An image similarity result does not establish personal identity.",
            "Unavailable data must not be interpreted as a negative finding.",
        ],
        "recommended_next_steps": [
            "Review the original source for each important finding.",
            "Record any manual verification and its date.",
            "Remove unrelated personal data from the final report.",
        ],
    }

    if os.getenv("CREWAI_ENABLED", "false").lower() != "true":
        return fallback

    if not os.getenv("OPENAI_API_KEY"):
        fallback["note"] = "CREWAI_ENABLED is true, but OPENAI_API_KEY is missing."
        return fallback

    try:
        from crewai import Agent, Crew, Process, Task

        # Limit the payload to collected evidence, not an open-ended identity request.
        payload = json.dumps(findings, ensure_ascii=False, default=str)[:18000]

        evidence_analyst = Agent(
            role="Evidence Quality Analyst",
            goal="Classify findings by evidence quality and point out missing verification.",
            backstory=(
                "You are a cautious analyst. You do not infer identity from weak matches "
                "and you never invent evidence."
            ),
            verbose=False,
            allow_delegation=False,
        )

        osint_analyst = Agent(
            role="Public OSINT Analyst",
            goal="Summarize the supplied public-source findings and useful next steps.",
            backstory=(
                "You work only from supplied evidence and distinguish facts from hypotheses."
            ),
            verbose=False,
            allow_delegation=False,
        )

        reviewer = Agent(
            role="Report Reviewer",
            goal="Review the summary for unsupported claims, privacy risks, and ambiguity.",
            backstory=(
                "You reject claims that exceed the evidence and require explicit limitations."
            ),
            verbose=False,
            allow_delegation=False,
        )

        task1 = Task(
            description=(
                "Review these collected records. Identify strong evidence, candidate "
                "matches, inconclusive records, and missing evidence. Do not infer who "
                "owns a phone number, email, CNIC, or bank account. Records:\n"
                f"{payload}"
            ),
            expected_output="A concise evidence-quality assessment with limitations.",
            agent=evidence_analyst,
        )

        task2 = Task(
            description=(
                "Using the assessment, summarize only the supplied findings. Recommend "
                "lawful, privacy-preserving follow-up steps. Label candidates as candidates."
            ),
            expected_output="A short factual OSINT summary and prioritized next steps.",
            agent=osint_analyst,
            context=[task1],
        )

        task3 = Task(
            description=(
                "Review the previous summary. Flag unsupported identity claims, "
                "overconfidence, privacy risks, and any statement that mistakes missing "
                "data for a negative result. Return the corrected summary."
            ),
            expected_output="A corrected, cautious final report summary.",
            agent=reviewer,
            context=[task1, task2],
        )

        crew = Crew(
            agents=[evidence_analyst, osint_analyst, reviewer],
            tasks=[task1, task2, task3],
            process=Process.sequential,
            verbose=False,
        )

        output = crew.kickoff()
        return {
            "analysis_method": "crewai",
            "summary": str(output),
            "key_cautions": fallback["key_cautions"],
            "recommended_next_steps": fallback["recommended_next_steps"],
            "note": "AI-generated analysis; check it against the original evidence.",
        }

    except Exception as exc:
        fallback["note"] = (
            "CrewAI analysis failed; deterministic summary used. "
            f"Error type: {type(exc).__name__}"
        )
        return fallback
