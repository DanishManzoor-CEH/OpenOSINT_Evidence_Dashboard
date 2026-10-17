
import json
from datetime import datetime, timezone


def make_report(findings: list[dict], case_label: str = "OSINT case") -> dict:
    return {
        "report_title": "OpenOSINT Evidence Report",
        "case_label": case_label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology": (
            "Findings are based on the sources and observations listed below. "
            "Candidate matches are not proof of identity or ownership."
        ),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "verified": sum(f.get("status") == "verified" for f in findings),
            "candidate": sum(f.get("status") == "candidate" for f in findings),
            "inconclusive": sum(f.get("status") == "inconclusive" for f in findings),
            "unavailable": sum(f.get("status") == "unavailable" for f in findings),
        },
    }


def report_to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def report_to_markdown(report: dict) -> str:
    lines = [
        f"# {report.get('report_title', 'OSINT Report')}",
        "",
        f"- **Case:** {report.get('case_label', 'OSINT case')}",
        f"- **Generated:** {report.get('generated_at', 'Unknown')}",
        "",
        "## Summary",
        "",
    ]

    for key, value in report.get("summary", {}).items():
        lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

    lines += ["", "## Findings", ""]

    for index, finding in enumerate(report.get("findings", []), start=1):
        lines += [
            f"### {index}. {finding.get('module', 'Unknown module')}",
            "",
            f"- **Status:** {finding.get('status', 'unknown')}",
            f"- **Finding:** {finding.get('finding', '')}",
            f"- **Source:** {finding.get('source', 'Not specified')}",
            f"- **Observed at:** {finding.get('observed_at', 'Not recorded')}",
        ]

        evidence = finding.get("evidence", {})
        if evidence:
            lines += ["", "**Evidence:**", "```json",
                      json.dumps(evidence, indent=2, ensure_ascii=False, default=str),
                      "```"]

        limitations = finding.get("limitations", [])
        if limitations:
            lines += ["", "**Limitations:**"]
            lines.extend(f"- {item}" for item in limitations)

        lines.append("")

    lines += [
        "## Interpretation",
        "",
        report.get("methodology", ""),
        "",
        "Do not treat a candidate result as proof of identity, ownership, or wrongdoing.",
    ]
    return "\n".join(lines)
