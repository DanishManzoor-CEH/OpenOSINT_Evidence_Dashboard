import io, re
from datetime import datetime, timezone
from urllib.parse import quote
import requests
from PIL import Image
from PIL.ExifTags import TAGS
TIMEOUT = 8
HEADERS = {'User-Agent': 'OpenOSINT-Evidence-Dashboard/1.0 (public research)'}
def stamp(): return datetime.now(timezone.utc).isoformat()
def check_phone(value: str) -> dict:
    value = (value or '').strip(); digits = re.sub(r'\D', '', value)
    result = {'input': value, 'checked_at_utc': stamp(), 'scope': 'format validation only; no subscriber lookup', 'is_plausible_international_length': 7 <= len(digits) <= 15, 'normalized_digits': digits if 7 <= len(digits) <= 15 else None, 'limitations': ['Length validation does not confirm assignment or reachability.', 'Subscriber name, CNIC, linked accounts and SIM ownership require authorized provider records.']}
    try:
        import phonenumbers
        parsed = phonenumbers.parse(value, None if value.startswith('+') else 'PK')
        result.update(valid_numbering_plan=bool(phonenumbers.is_valid_number(parsed)), possible_numbering_plan=bool(phonenumbers.is_possible_number(parsed)), region_code=phonenumbers.region_code_for_number(parsed), international_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL), national_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
    except Exception as exc: result['numbering_plan_check'] = f'Unavailable or invalid input: {type(exc).__name__}'
    return result
def check_email(value: str) -> dict:
    value = (value or '').strip(); basic = bool(re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', value))
    result = {'input': value, 'checked_at_utc': stamp(), 'syntax_valid': basic, 'scope': 'syntax and public domain DNS only', 'limitations': ['Does not prove mailbox existence or ownership.', 'Does not discover private phone links or accounts registered using this email.']}
    if not basic: return result
    domain = value.rsplit('@', 1)[1].lower(); result['domain'] = domain
    try:
        import dns.resolver
        records = []
        for rtype in ('MX', 'A', 'AAAA'):
            try: records.append({'type': rtype, 'values': [str(a).rstrip('.') for a in dns.resolver.resolve(domain, rtype, lifetime=4)]})
            except Exception: records.append({'type': rtype, 'values': []})
        result['dns_records'] = records; result['domain_has_mx'] = any(x['type'] == 'MX' and x['values'] for x in records)
    except Exception as exc: result['dns_check'] = f'Unavailable: {type(exc).__name__}'
    return result
def check_cnic(value: str) -> dict:
    digits = re.sub(r'\D', '', (value or '').strip()); ok = bool(re.fullmatch(r'\d{13}', digits))
    return {'input_masked': ('*' * 9 + digits[-4:]) if len(digits) >= 4 else None, 'checked_at_utc': stamp(), 'format_has_13_digits': ok, 'scope': 'format validation only; no identity, SIM, or banking lookup', 'limitations': ['A 13-digit format does not validate against NADRA records.', 'Private telecom subscriber and bank account records are not publicly queried.', 'For your own records, use official PTA/operator and bank verification channels.']}
def check_username(username: str, platforms: list[str]) -> list[dict]:
    username = (username or '').strip().lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,50}', username): return [{'platform': '-', 'status': 'invalid_input', 'url': '', 'detail': 'Use letters, numbers, dots, underscores or hyphens.'}]
    base = {'GitHub': f'https://github.com/{quote(username)}', 'GitLab': f'https://gitlab.com/{quote(username)}', 'Reddit': f'https://www.reddit.com/user/{quote(username)}/', 'Medium': f'https://medium.com/@{quote(username)}', 'Dev.to': f'https://dev.to/{quote(username)}', 'Hacker News': f'https://news.ycombinator.com/user?id={quote(username)}'}
    out = []
    for platform in platforms:
        url = base.get(platform)
        if not url: continue
        item = {'platform': platform, 'url': url, 'checked_at_utc': stamp()}
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True); item.update(http_status=r.status_code, final_url=r.url)
            if r.status_code == 200: item.update(status='reachable_public_page', detail='Page returned HTTP 200; manually verify it is a profile and relevant.')
            elif r.status_code == 404: item.update(status='not_found_signal', detail='This endpoint returned 404; platform behavior may vary.')
            elif r.status_code in (401,403,429): item.update(status='inconclusive_blocked_or_rate_limited', detail='Do not infer absence from blocked or rate-limited responses.')
            else: item.update(status='inconclusive', detail='HTTP response does not establish profile existence or identity.')
        except requests.RequestException as exc: item.update(status='request_failed', detail=type(exc).__name__)
        out.append(item)
    return out
def analyze_image(data: bytes, filename: str) -> dict:
    result = {'filename': filename, 'checked_at_utc': stamp(), 'scope': 'image properties and embedded metadata only', 'limitations': ['Metadata can be missing or altered.', 'No face recognition, identity matching, or private account search is performed.']}
    try:
        image = Image.open(io.BytesIO(data)); result.update(format=image.format, width_px=image.width, height_px=image.height, mode=image.mode, byte_size=len(data)); exif_out = {}
        try:
            for tag_id, val in image.getexif().items():
                name = TAGS.get(tag_id, str(tag_id)); exif_out[name] = (f'<binary data: {len(val)} bytes>' if isinstance(val, bytes) else str(val))[:500]
        except Exception: pass
        result['exif'] = exif_out; result['gps_metadata_present'] = any('GPS' in k.upper() for k in exif_out)
    except Exception as exc: result['error'] = f'Could not parse image: {type(exc).__name__}'
    return result
