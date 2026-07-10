import re
from collections import Counter
from datetime import datetime, timezone
from typing import Optional
from app.models import Alert


SQL_INJECTION_RE = re.compile(
    r'(?:\bUNION\b.*\bSELECT\b|'
    r'\bSELECT\b.*\bFROM\b|'
    r'\bDROP\s+TABLE\b|'
    r'\bOR\s+[\'"]\s*=\s*[\'"]|'
    r'--|'
    r'\bOR\s+\d+\s*=\s*\d+|'
    r"\' OR \'1\'=\'1|"
    r'\bALTER\s+TABLE\b)',
    re.IGNORECASE,
)

XSS_RE = re.compile(
    r'(?:<script[^>]*>|'
    r'alert\s*\(|'
    r'onerror\s*=|'
    r'javascript\s*:|'
    r'onload\s*=|'
    r'<img[^>]+onerror|'
    r'<svg[^>]*>|'
    r'%3Cscript|'
    r'%3Csvg)',
    re.IGNORECASE,
)

DIRECTORY_TRAVERSAL_RE = re.compile(
    r'(?:\.\.(?:\\|/|%2f)|'
    r'%2e%2e(?:%2f|\\|/)|'
    r'\.\.%255c|'
    r'\.\.%252f|'
    r'\.\.\\\\|'
    r'\.\.//|'
    r'\.\.\\\\\\\\)',
    re.IGNORECASE,
)

FAILED_LOGIN_RE = re.compile(
    r'(?:Failed password|authentication failure|'
    r'FAILED LOGIN|failed login|LOGIN FAILED|'
    r'invalid user|Failed keyboard)',
    re.IGNORECASE,
)


def detect_failed_login(raw_log: str, ip_address: Optional[str]) -> Optional[dict]:
    if not FAILED_LOGIN_RE.search(raw_log):
        return None
    return {
        'attack_type': 'Failed Login Attempt',
        'severity': 'Medium',
        'description': f'Failed login attempt detected from {ip_address or "unknown IP"}',
    }


def detect_sql_injection(request_url: Optional[str], raw_log: str) -> Optional[dict]:
    target = (request_url or '') + ' ' + raw_log
    m = SQL_INJECTION_RE.search(target)
    if not m:
        return None
    match_text = m.group(0)[:60]
    return {
        'attack_type': 'SQL Injection',
        'severity': 'Critical',
        'description': f'SQL injection pattern detected: "{match_text}"',
    }


def detect_xss(request_url: Optional[str], user_agent: Optional[str], raw_log: str) -> Optional[dict]:
    target = (request_url or '') + ' ' + (user_agent or '') + ' ' + raw_log
    m = XSS_RE.search(target)
    if not m:
        return None
    match_text = m.group(0)[:60]
    return {
        'attack_type': 'Cross Site Scripting (XSS)',
        'severity': 'High',
        'description': f'XSS pattern detected: "{match_text}"',
    }


def detect_directory_traversal(request_url: Optional[str], raw_log: str) -> Optional[dict]:
    target = (request_url or '') + ' ' + raw_log
    m = DIRECTORY_TRAVERSAL_RE.search(target)
    if not m:
        return None
    match_text = m.group(0)[:40]
    return {
        'attack_type': 'Directory Traversal',
        'severity': 'High',
        'description': f'Directory traversal attempt: "{match_text}"',
    }


def detect_port_scanning(log_entries: list) -> list[dict]:
    alerts = []
    ip_ports = {}
    for entry in log_entries:
        if entry.ip_address and entry.request_url:
            if entry.ip_address not in ip_ports:
                ip_ports[entry.ip_address] = set()
            ip_ports[entry.ip_address].add(entry.request_url)

    for ip, urls in ip_ports.items():
        if len(urls) >= 15:
            alerts.append({
                'attack_type': 'Port Scanning',
                'severity': 'Medium',
                'description': (
                    f'Possible port scanning from {ip}: '
                    f'accessed {len(urls)} unique endpoints'
                ),
            })
    return alerts


def detect_dos(log_entries: list, threshold: int = 100) -> list[dict]:
    alerts = []
    ip_counts = Counter(e.ip_address for e in log_entries if e.ip_address)
    for ip, count in ip_counts.items():
        if count >= threshold:
            alerts.append({
                'attack_type': 'Denial of Service (DoS)',
                'severity': 'Critical',
                'description': (
                    f'Possible DoS attack from {ip}: '
                    f'{count} requests in dataset'
                ),
            })
    return alerts


def detect_brute_force(log_entries: list, threshold: int = 5) -> list[dict]:
    alerts = []
    ip_count = Counter()
    for entry in log_entries:
        if entry.raw_log and FAILED_LOGIN_RE.search(entry.raw_log) and entry.ip_address:
            ip_count[entry.ip_address] += 1

    for ip, count in ip_count.items():
        if count >= threshold:
            alerts.append({
                'attack_type': 'Brute Force Attack',
                'severity': 'High',
                'description': (
                    f'Brute force from {ip}: '
                    f'{count} failed login attempts'
                ),
            })
    return alerts


def run_detection(log_entries: list) -> list[Alert]:
    alerts = []

    for entry in log_entries:
        raw = entry.raw_log or ''

        result = detect_failed_login(raw, entry.ip_address)
        if result:
            alerts.append(Alert(log_id=entry.id, source_ip=entry.ip_address, **result))

        result = detect_sql_injection(entry.request_url, raw)
        if result:
            alerts.append(Alert(log_id=entry.id, source_ip=entry.ip_address, **result))

        result = detect_xss(entry.request_url, entry.user_agent, raw)
        if result:
            alerts.append(Alert(log_id=entry.id, source_ip=entry.ip_address, **result))

        result = detect_directory_traversal(entry.request_url, raw)
        if result:
            alerts.append(Alert(log_id=entry.id, source_ip=entry.ip_address, **result))

    if log_entries:
        alerts.extend(
            Alert(log_id=log_entries[0].id, source_ip=log_entries[0].ip_address, **a)
            for a in detect_port_scanning(log_entries)
        )

        alerts.extend(
            Alert(log_id=log_entries[0].id, source_ip=log_entries[0].ip_address, **a)
            for a in detect_dos(log_entries)
        )

        alerts.extend(
            Alert(log_id=log_entries[0].id, source_ip=log_entries[0].ip_address, **a)
            for a in detect_brute_force(log_entries)
        )

    return alerts
