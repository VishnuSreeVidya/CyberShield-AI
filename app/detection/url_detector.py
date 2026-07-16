import re
import hashlib
import ipaddress
from urllib.parse import urlparse
from typing import Optional


SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'account', 'secure', 'banking',
    'confirm', 'password', 'suspended', 'unusual', 'activity',
    'click here', 'urgent', 'act now', 'limited time', 'congratulations',
    'you won', 'free', 'winner', 'claim', 'reward', 'gift',
]

PHISHING_INDICATORS = [
    'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
    'google', 'instagram', 'whatsapp', 'linkedin', 'twitter',
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
    'buff.ly', 'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at',
]


def analyze_url(url: str) -> dict:
    findings = []
    recommendations = []
    risk_score = 0
    phishing_indicators_found = []

    parsed = urlparse(url)
    is_https = parsed.scheme == 'https'
    url_length = len(url)
    hostname = parsed.hostname or ''
    is_ip_based = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))

    if not is_https:
        risk_score += 20
        findings.append('URL does not use HTTPS encryption')

    if url_length > 100:
        risk_score += 10
        findings.append(f'Unusually long URL ({url_length} characters)')
    elif url_length > 75:
        risk_score += 5

    if is_ip_based:
        risk_score += 30
        findings.append('URL uses IP address instead of domain name')

    has_suspicious_keywords = False
    url_lower = url.lower()
    found_words = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            found_words.append(kw)
            has_suspicious_keywords = True

    if has_suspicious_keywords:
        risk_score += min(len(found_words) * 8, 30)
        findings.append(f'Suspicious keywords found: {", ".join(found_words)}')

    for indicator in PHISHING_INDICATORS:
        if indicator in hostname.lower() and indicator not in hostname.lower().split('.')[0]:
            phishing_indicators_found.append(indicator)

    if phishing_indicators_found:
        risk_score += 25
        findings.append(f'Potential brand impersonation: {", ".join(phishing_indicators_found)}')

    for shortener in URL_SHORTENERS:
        if shortener in hostname.lower():
            risk_score += 15
            findings.append(f'URL shortener detected: {shortener}')
            break

    if parsed.path.count('.') > 3:
        risk_score += 10
        findings.append('Multiple subdomains detected (possible subdomain spoofing)')

    if url.count('@') > 0:
        risk_score += 20
        findings.append('URL contains @ symbol (possible URL redirection)')

    if url.count('%') > 5:
        risk_score += 10
        findings.append('High percentage of URL-encoded characters')

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        threat_level = 'Critical'
    elif risk_score >= 50:
        threat_level = 'High'
    elif risk_score >= 30:
        threat_level = 'Medium'
    else:
        threat_level = 'Low'

    if not is_https:
        recommendations.append('Use HTTPS URLs when possible')
    if is_ip_based:
        recommendations.append('IP-based URLs are often malicious. Verify the source.')
    if has_suspicious_keywords:
        recommendations.append('URL contains phishing-associated keywords. Exercise caution.')
    if phishing_indicators_found:
        recommendations.append('This URL may impersonate a known brand. Do not enter credentials.')
    if not findings:
        findings.append('No significant issues detected')
        recommendations.append('URL appears relatively safe, but always verify before entering sensitive data')

    return {
        'url': url,
        'is_https': is_https,
        'url_length': url_length,
        'has_suspicious_keywords': has_suspicious_keywords,
        'is_ip_based': is_ip_based,
        'phishing_indicators': ','.join(phishing_indicators_found) if phishing_indicators_found else None,
        'threat_level': threat_level,
        'risk_score': risk_score,
        'findings': '\n'.join(findings),
        'recommendations': '\n'.join(recommendations),
    }
