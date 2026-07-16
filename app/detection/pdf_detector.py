import os
import re
from datetime import datetime
from typing import Optional


SUSPICIOUS_PDF_KEYWORDS = [
    'javascript', 'js', 'openaction', 'launch', 'uri',
    'submitform', 'importdata', 'exportdata', 'richmedia',
    'embeddedfile', 'fileattachment', 'epayload',
    '/aa', '/openaction', '/js', '/javascript',
]

SUSPICIOUS_URL_PATTERNS = [
    r'https?://[^\s<>"]+',
]


def extract_pdf_metadata(file_content: bytes, filename: str) -> dict:
    findings = []
    recommendations = []
    risk_score = 0

    file_size = len(file_content)
    author = None
    creation_date = None
    page_count = 0
    embedded_urls = []
    suspicious_keywords_found = []

    try:
        content_str = file_content.decode('latin-1', errors='replace')

        title_match = re.search(r'/Title\s*\(([^)]*)\)', content_str)
        author_match = re.search(r'/Author\s*\(([^)]*)\)', content_str)
        creator_match = re.search(r'/Creator\s*\(([^)]*)\)', content_str)
        producer_match = re.search(r'/Producer\s*\(([^)]*)\)', content_str)

        if author_match:
            author = author_match.group(1).strip()

        page_matches = re.findall(r'/Type\s*/Page[^s]', content_str)
        page_count = len(page_matches) if page_matches else 0

        date_match = re.search(r'/CreationDate\s*\(([^)]*)\)', content_str)
        if date_match:
            try:
                creation_date = datetime.strptime(date_match.group(1)[:14], '%Y%m%d%H%M%S')
            except (ValueError, IndexError):
                pass

        urls_found = set()
        for pattern in SUSPICIOUS_URL_PATTERNS:
            for match in re.finditer(pattern, content_str):
                url = match.group(0)
                if len(url) < 200:
                    urls_found.add(url)
        embedded_urls = list(urls_found)

        text_lower = content_str.lower()
        for keyword in SUSPICIOUS_PDF_KEYWORDS:
            if keyword in text_lower:
                suspicious_keywords_found.append(keyword)

        if suspicious_keywords_found:
            risk_score += min(len(suspicious_keywords_found) * 12, 40)
            findings.append(f'Suspicious PDF keywords detected: {", ".join(suspicious_keywords_found[:5])}')
            recommendations.append('PDF contains potentially dangerous elements. Open with caution in a sandboxed environment.')

        if embedded_urls:
            risk_score += min(len(embedded_urls) * 8, 25)
            findings.append(f'Embedded URLs found: {len(embedded_urls)}')
            recommendations.append('Verify all embedded URLs before clicking. Scan with antivirus.')

        if file_size > 10 * 1024 * 1024:
            risk_score += 10
            findings.append(f'Unusually large PDF file ({file_size / (1024*1024):.1f} MB)')
            recommendations.append('Large file size may contain hidden payloads.')

        if not author:
            risk_score += 5
            findings.append('No author metadata found (common in malicious PDFs)')

        if creator_match:
            creator = creator_match.group(1).strip()
            if any(x in creator.lower() for x in ['exploit', 'metasploit', 'meterpreter']):
                risk_score += 50
                findings.append(f'Suspicious PDF creator: {creator}')
                recommendations.append('CRITICAL: PDF was created by known exploit tool. Do NOT open.')

        if not findings:
            findings.append('No significant issues detected in PDF metadata')
            recommendations.append('PDF appears safe, but always keep your PDF reader updated.')

    except Exception as e:
        findings.append(f'Error parsing PDF: {str(e)[:100]}')
        recommendations.append('Could not fully analyze PDF. Open with caution.')
        risk_score = 30

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
        'filename': filename,
        'file_size': file_size,
        'author': author,
        'creation_date': creation_date,
        'page_count': page_count,
        'embedded_urls': '\n'.join(embedded_urls[:20]) if embedded_urls else None,
        'suspicious_keywords': ','.join(suspicious_keywords_found[:20]) if suspicious_keywords_found else None,
        'threat_level': threat_level,
        'risk_score': risk_score,
        'findings': '\n'.join(findings),
        'recommendations': '\n'.join(recommendations),
    }
