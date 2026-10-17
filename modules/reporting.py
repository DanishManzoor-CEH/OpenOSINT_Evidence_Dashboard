from datetime import datetime, timezone
def make_report(results: dict) -> dict:
    return {'report_type': 'OpenOSINT public-evidence report', 'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'notice': 'Signals are not proof of identity. Provider errors are inconclusive. No confidential telecom or banking records were accessed.', 'results': results}
