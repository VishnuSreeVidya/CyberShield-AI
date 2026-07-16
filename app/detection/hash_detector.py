import re
import hashlib
from typing import Optional


KNOWN_MALICIOUS_HASHES = {
    'e99a18c428cb38d5f260853678922e03': ('MD5', 'Trojan.GenericKD'),
    'd8578edf8458ce06fbc5bb76a58c5ca4': ('MD5', 'Worm.Win32.AutoRun'),
    '5d41402abc4b2a76b9719d911017c592': ('MD5', 'RiskTool.Win64'),
    '098f6bcd4621d373cade4e832627b4f6': ('MD5', 'Test file - safe'),
    '3395856ce81f2b7382dee72602f798b642f14140': ('SHA1', 'TrojanSpy.KeyLogger'),
    'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': ('SHA1', 'Backdoor.Win32'),
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f': ('SHA256', 'EICAR-Test-File'),
    '2d62e86e4dbbf1e4406985953985f29f0f9a9794db7f0446a2ce3543861e03fd': ('SHA256', 'Malware.Sandbox.Evader'),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': ('SHA256', 'Empty file hash'),
}

HASH_PATTERNS = {
    'MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'SHA1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'SHA256': re.compile(r'^[a-fA-F0-9]{64}$'),
}


def detect_hash_type(hash_str: str) -> Optional[str]:
    for htype, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_str):
            return htype
    return None


def analyze_hash(hash_str: str) -> dict:
    findings = []
    recommendations = []
    risk_score = 0

    hash_str = hash_str.strip()
    hash_type = detect_hash_type(hash_str)

    if not hash_type:
        return {
            'hash_value': hash_str,
            'hash_type': 'Unknown',
            'is_valid_format': False,
            'threat_status': 'Invalid',
            'threat_level': 'Medium',
            'risk_score': 30,
            'findings': f'Invalid hash format. Expected MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars).',
            'recommendations': 'Provide a valid hash in MD5, SHA1, or SHA256 format.',
        }

    findings.append(f'Valid {hash_type} hash format detected ({len(hash_str)} characters)')

    is_known = False
    for known_hash, (known_type, threat_name) in KNOWN_MALICIOUS_HASHES.items():
        if hash_str.lower() == known_hash.lower():
            is_known = True
            risk_score = 85
            findings.append(f'Match found in demo threat database: {threat_name}')
            recommendations.append(f'THREAT DETECTED: {threat_name}. Isolate the file and run a full system scan.')
            break

    if is_known:
        threat_status = 'Malicious'
    elif len(hash_str) == 32:
        risk_score += 10
        threat_status = 'Unknown'
        findings.append('MD5 hash - weaker algorithm, susceptible to collision attacks')
        recommendations.append('MD5 is cryptographically weak. Prefer SHA256 for file integrity verification.')
    elif len(hash_str) == 40:
        risk_score += 5
        threat_status = 'Unknown'
        findings.append('SHA1 hash - legacy algorithm')
        recommendations.append('SHA1 is deprecated for security use. Consider SHA256 for stronger verification.')
    else:
        threat_status = 'Unknown'
        findings.append('SHA256 hash - strong cryptographic algorithm')

    if threat_status == 'Unknown':
        risk_score += 20
        findings.append('Hash not found in demo threat database')
        recommendations.append('For accurate results, integrate with VirusTotal or MalwareBazaar API.')

    if threat_status not in ('Malicious',):
        if risk_score < 30:
            threat_status = 'Safe'
        else:
            threat_status = 'Suspicious'

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        threat_level = 'Critical'
    elif risk_score >= 50:
        threat_level = 'High'
    elif risk_score >= 30:
        threat_level = 'Medium'
    else:
        threat_level = 'Low'

    return {
        'hash_value': hash_str,
        'hash_type': hash_type,
        'is_valid_format': True,
        'threat_status': threat_status,
        'threat_level': threat_level,
        'risk_score': risk_score,
        'findings': '\n'.join(findings),
        'recommendations': '\n'.join(recommendations),
    }
