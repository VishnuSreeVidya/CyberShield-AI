import re
from typing import Optional


PHISHING_PATTERNS = [
    r'(?i)verify\s+(?:your|the)\s+account',
    r'(?i)confirm\s+your\s+(?:identity|account|email)',
    r'(?i)your\s+account\s+(?:has\s+been|is)\s+(?:suspended|locked|compromised)',
    r'(?i)click\s+(?:here|below|the\s+link)\s+immediately',
    r'(?i)act\s+now|urgent\s+action\s+required',
    r'(?i)failure\s+to\s+(?:verify|confirm|update)',
    r'(?i)unusual\s+(?:activity|sign[\s-]?in)',
    r'(?i)dear\s+(?:customer|user|valued)',
    r'(?i)update\s+your\s+(?:payment|billing|account)\s+(?:info|details)',
    r'(?i)(?:suspended|locked|limited)\s+(?:account|access)',
]

SCAM_PATTERNS = [
    r'(?i)you\s+(?:have\s+)?(?:won|selected|been\s+chosen)',
    r'(?i)congratulations.*?(?:won|prize|reward|lottery)',
    r'(?i)claim\s+your\s+(?:prize|reward|gift|money)',
    r'(?i)free\s+(?:gift|money|trial|offer|iphone|cash)',
    r'(?i)make\s+money\s+(?:fast|online|now|guaranteed)',
    r'(?i)no\s+(?:risk|cost|obligation)',
    r'(?i)limited\s+time\s+offer',
    r'(?i)act\s+now\s+before',
    r'(?i)exclusive\s+(?:deal|offer|access)',
    r'(?i)work\s+from\s+home.*?(?:\$|money|earn)',
]

SPAM_PATTERNS = [
    r'(?i)buy\s+now',
    r'(?i)order\s+(?:now|today|before)',
    r'(?i)discount\s+(?:code|offer|%|price)',
    r'(?i)(?:unsubscribe|opt[\s-]?out)',
    r'(?i)100%\s+(?:free|guaranteed)',
    r'(?i)increase\s+(?:your|traffic|sales|revenue)',
    r'(?i)double\s+your',
    r'(?i)no\s+(?:credit\s+card|obligation)',
    r'(?i)(?:cheapest|best\s+price|lowest\s+price)',
    r'(?i)email\s+(?:marketing|blast|campaign)',
]

SUSPICIOUS_WORDS = [
    'password', 'credential', 'social security', 'ssn', 'credit card',
    'bank account', 'routing number', 'pin code', 'wire transfer',
    'bitcoin', 'crypto', 'wallet address', 'private key',
    'malware', 'virus', 'trojan', 'ransomware', 'exploit',
    'hack', 'crack', 'exploit', 'inject', 'backdoor',
    'phish', 'scam', 'fraud', 'steal', 'compromise',
]


def analyze_text(text: str) -> dict:
    findings = []
    recommendations = []
    suspicious_words_found = []
    risk_score = 0
    is_phishing = False
    is_scam = False
    is_spam = False

    text_lower = text.lower()

    phishing_matches = 0
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, text):
            phishing_matches += 1
    if phishing_matches > 0:
        is_phishing = True
        risk_score += min(phishing_matches * 15, 45)
        findings.append(f'Phishing indicators detected ({phishing_matches} patterns matched)')

    scam_matches = 0
    for pattern in SCAM_PATTERNS:
        if re.search(pattern, text):
            scam_matches += 1
    if scam_matches > 0:
        is_scam = True
        risk_score += min(scam_matches * 15, 40)
        findings.append(f'Scam content detected ({scam_matches} patterns matched)')

    spam_matches = 0
    for pattern in SPAM_PATTERNS:
        if re.search(pattern, text):
            spam_matches += 1
    if spam_matches > 0:
        is_spam = True
        risk_score += min(spam_matches * 8, 20)
        findings.append(f'Spam indicators detected ({spam_matches} patterns matched)')

    for word in SUSPICIOUS_WORDS:
        if word in text_lower:
            suspicious_words_found.append(word)
            risk_score += 5

    if suspicious_words_found:
        findings.append(f'Suspicious/sensitive words found: {", ".join(suspicious_words_found[:10])}')

    if text.count('!') > 3:
        risk_score += 5
        findings.append('Excessive exclamation marks (common in spam/phishing)')

    if text.upper() == text and len(text) > 20:
        risk_score += 5
        findings.append('ALL CAPS text detected (common in spam)')

    urls = re.findall(r'https?://\S+', text)
    if urls:
        risk_score += 5
        findings.append(f'Contains {len(urls)} URL(s) - verify before clicking')

    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text)
    if emails:
        risk_score += 3
        findings.append(f'Contains email address(es): {", ".join(emails[:3])}')

    risk_score = min(risk_score, 100)

    if is_phishing and is_scam:
        classification = 'Malicious'
    elif is_phishing or is_scam:
        classification = 'Suspicious'
    elif is_spam:
        classification = 'Spam'
    elif suspicious_words_found:
        classification = 'Caution'
    else:
        classification = 'Safe'

    confidence_score = min(60 + risk_score * 0.4, 98)

    if is_phishing:
        recommendations.append('This text shows phishing characteristics. Do not click any links or provide personal information.')
    if is_scam:
        recommendations.append('This text appears to be a scam. Do not send money or share personal details.')
    if is_spam:
        recommendations.append('This appears to be spam. Mark as spam and block the sender if applicable.')
    if suspicious_words_found:
        recommendations.append('Text contains sensitive security terms. Verify the legitimacy of the source.')
    if not findings:
        findings.append('No significant threats detected in the text')
        recommendations.append('Text appears safe, but always exercise caution with unsolicited messages')

    return {
        'input_text': text[:5000],
        'classification': classification,
        'confidence_score': round(confidence_score, 1),
        'is_phishing': is_phishing,
        'is_scam': is_scam,
        'is_spam': is_spam,
        'suspicious_words': ','.join(suspicious_words_found[:20]) if suspicious_words_found else None,
        'threat_level': classification if classification in ('Critical', 'High', 'Medium', 'Low') else ('Medium' if classification == 'Caution' else 'Low'),
        'risk_score': risk_score,
        'findings': '\n'.join(findings),
        'recommendations': '\n'.join(recommendations),
    }
