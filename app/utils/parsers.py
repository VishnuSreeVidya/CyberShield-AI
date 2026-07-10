import re
import json
import csv
import io
from datetime import datetime
from typing import Optional

APACHE_COMBINED_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+) \S+" (\d{3}) (\d+) "([^"]*)" "([^"]*)"'
)

APACHE_COMMON_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] '
    r'"(\S+) (\S+) \S+" (\d{3}) (\d+)'
)

FAILED_AUTH_RE = re.compile(
    r'.*(?:Failed password|authentication failure|FAILED LOGIN|'
    r'failed login|LOGIN FAILED).*from\s+(\S+)',
    re.IGNORECASE,
)

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SYSLOG_TS_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')


def parse_apache_date(date_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
    except (ValueError, IndexError):
        return None


def parse_apache_combined(line: str) -> Optional[dict]:
    m = APACHE_COMBINED_RE.match(line)
    if not m:
        return None
    ip, date_str, method, url, status, size, referer, ua = m.groups()
    return {
        'timestamp': parse_apache_date(date_str),
        'ip_address': ip,
        'http_method': method,
        'request_url': url,
        'status_code': int(status),
        'user_agent': ua,
        'raw_log': line,
    }


def parse_apache_common(line: str) -> Optional[dict]:
    m = APACHE_COMMON_RE.match(line)
    if not m:
        return None
    ip, date_str, method, url, status, size = m.groups()
    return {
        'timestamp': parse_apache_date(date_str),
        'ip_address': ip,
        'http_method': method,
        'request_url': url,
        'status_code': int(status),
        'user_agent': None,
        'raw_log': line,
    }


def parse_auth_log(line: str) -> Optional[dict]:
    m = FAILED_AUTH_RE.match(line)
    if not m:
        return None
    ip = m.group(1)
    ts_match = SYSLOG_TS_RE.match(line)
    timestamp = None
    if ts_match:
        try:
            timestamp = datetime.strptime(ts_match.group(1), '%b %d %H:%M:%S')
            timestamp = timestamp.replace(year=datetime.now().year)
        except ValueError:
            pass
    return {
        'timestamp': timestamp,
        'ip_address': ip,
        'http_method': None,
        'request_url': None,
        'status_code': None,
        'user_agent': None,
        'raw_log': line,
    }


def detect_format(content: str) -> str:
    lines = [l for l in content.strip().split('\n') if l.strip()]
    if not lines:
        return 'unknown'

    try:
        json.loads(content)
        return 'json'
    except (json.JSONDecodeError, ValueError):
        pass

    if ',' in lines[0]:
        return 'csv'

    for line in lines[:10]:
        if APACHE_COMBINED_RE.match(line):
            return 'apache_combined'
        if APACHE_COMMON_RE.match(line):
            return 'apache_common'
        if FAILED_AUTH_RE.match(line):
            return 'auth'

    return 'text'


def parse_line(line: str, fmt: str) -> Optional[dict]:
    parsers = {
        'apache_combined': parse_apache_combined,
        'apache_common': parse_apache_common,
        'auth': parse_auth_log,
    }
    parser = parsers.get(fmt)
    if parser:
        return parser(line)
    return None


def parse_csv(content: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(content))
    results = []
    for row in reader:
        r = {k.lower(): v for k, v in row.items()}
        sc = r.get('status_code') or r.get('status')
        try:
            sc = int(sc) if sc else None
        except (ValueError, TypeError):
            sc = None
        results.append({
            'timestamp': r.get('timestamp') or r.get('time'),
            'ip_address': r.get('ip_address') or r.get('ip'),
            'http_method': r.get('http_method') or r.get('method'),
            'request_url': r.get('request_url') or r.get('url') or r.get('path'),
            'status_code': sc,
            'user_agent': r.get('user_agent') or r.get('user-agent') or r.get('agent'),
            'raw_log': str(row),
        })
    return results


def parse_json(content: str) -> list[dict]:
    data = json.loads(content)
    if isinstance(data, dict):
        data = [data]
    results = []
    for item in data:
        sc = item.get('status_code') or item.get('status')
        try:
            sc = int(sc) if sc else None
        except (ValueError, TypeError):
            sc = None
        results.append({
            'timestamp': item.get('timestamp') or item.get('time'),
            'ip_address': (
                item.get('ip_address')
                or item.get('ip')
                or item.get('remote_addr')
            ),
            'http_method': item.get('http_method') or item.get('method'),
            'request_url': (
                item.get('request_url')
                or item.get('url')
                or item.get('path')
            ),
            'status_code': sc,
            'user_agent': (
                item.get('user_agent')
                or item.get('user-agent')
                or item.get('agent')
            ),
            'raw_log': str(item),
        })
    return results


def parse_file(content: str, filename: str = '') -> list[dict]:
    fmt = detect_format(content)

    if fmt == 'json':
        return parse_json(content)
    if fmt == 'csv':
        return parse_csv(content)

    lines = content.strip().split('\n')
    results = []

    formats_to_try = ['apache_combined', 'apache_common', 'auth', 'text']

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parsed = None
        if fmt != 'text':
            parsed = parse_line(line, fmt)

        if not parsed and fmt != 'text':
            for alt_fmt in formats_to_try:
                if alt_fmt == fmt or alt_fmt == 'text':
                    continue
                parsed = parse_line(line, alt_fmt)
                if parsed:
                    break

        if parsed:
            results.append(parsed)
        else:
            ip_m = IP_RE.search(line)
            results.append({
                'timestamp': None,
                'ip_address': ip_m.group(0) if ip_m else None,
                'http_method': None,
                'request_url': None,
                'status_code': None,
                'user_agent': None,
                'raw_log': line,
            })

    return results
