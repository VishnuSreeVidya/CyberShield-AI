import pytest
import io
from app.detection.ip_detector import analyze_ip
from app.detection.hash_detector import analyze_hash, detect_hash_type
from app.detection.pdf_detector import extract_pdf_metadata
from app.detection.text_detector import analyze_text
from app.detection.url_detector import analyze_url


class TestIPDetector:
    def test_invalid_ip(self):
        res = analyze_ip("invalid_ip_string")
        assert res['is_valid'] is False
        assert res['threat_level'] == 'Medium'
        assert res['risk_score'] == 50

    def test_loopback_ip(self):
        res = analyze_ip("127.0.0.1")
        assert res['is_valid'] is True
        assert res['is_reserved'] is True
        assert res['ip_type'] == 'IPv4'
        assert 'Loopback' in res['findings']

    def test_private_ip(self):
        res = analyze_ip("10.0.0.5")
        assert res['is_valid'] is True
        assert 'Private' in res['findings']

    def test_link_local_ip(self):
        res = analyze_ip("169.254.1.1")
        assert res['is_valid'] is True
        assert 'Private' in res['findings'] or 'Link-local' in res['findings']

    def test_reserved_ip(self):
        res = analyze_ip("240.0.0.1")
        assert res['is_valid'] is True

    def test_multicast_ip(self):
        res = analyze_ip("224.0.0.1")
        assert res['is_valid'] is True
        assert 'Multicast' in res['findings']

    def test_public_ipv4(self):
        res = analyze_ip("8.8.8.8")
        assert res['is_valid'] is True
        assert res['is_public'] is True
        assert res['ip_type'] == 'IPv4'

    def test_public_ipv6(self):
        res = analyze_ip("2001:4860:4860::8888")
        assert res['is_valid'] is True
        assert res['ip_type'] == 'IPv6'
        assert 'IPv6' in res['findings']

    def test_malicious_prefix_ip(self):
        res = analyze_ip("104.28.1.1")
        assert res['is_valid'] is True
        assert 'scanning activity' in res['findings']


class TestHashDetector:
    def test_detect_hash_type(self):
        assert detect_hash_type("e99a18c428cb38d5f260853678922e03") == "MD5"
        assert detect_hash_type("3395856ce81f2b7382dee72602f798b642f14140") == "SHA1"
        assert detect_hash_type("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "SHA256"
        assert detect_hash_type("invalid_hash") is None

    def test_invalid_hash_format(self):
        res = analyze_hash("12345")
        assert res['is_valid_format'] is False
        assert res['threat_status'] == 'Invalid'

    def test_known_malicious_md5(self):
        res = analyze_hash("e99a18c428cb38d5f260853678922e03")
        assert res['is_valid_format'] is True
        assert res['threat_status'] == 'Malicious'
        assert res['threat_level'] == 'Critical'
        assert res['risk_score'] == 85

    def test_unknown_md5(self):
        res = analyze_hash("00000000000000000000000000000000")
        assert res['is_valid_format'] is True
        assert res['hash_type'] == 'MD5'
        assert res['threat_status'] in ('Suspicious', 'Safe')

    def test_unknown_sha1(self):
        res = analyze_hash("0000000000000000000000000000000000000000")
        assert res['is_valid_format'] is True
        assert res['hash_type'] == 'SHA1'

    def test_unknown_sha256(self):
        res = analyze_hash("0000000000000000000000000000000000000000000000000000000000000000")
        assert res['is_valid_format'] is True
        assert res['hash_type'] == 'SHA256'


class TestPDFDetector:
    def test_pdf_metadata_extraction(self):
        content = (
            b"%PDF-1.4\n"
            b"/Title (Test PDF)\n"
            b"/Author (John Doe)\n"
            b"/Creator (Metasploit Framework)\n"
            b"/CreationDate (20260818100000)\n"
            b"/Type /Page\n"
            b"http://malicious-site.com/payload\n"
            b"/JavaScript /OpenAction\n"
        )
        res = extract_pdf_metadata(content, "exploit.pdf")
        assert res['filename'] == "exploit.pdf"
        assert res['author'] == "John Doe"
        assert res['page_count'] == 1
        assert "metasploit" in res['findings'].lower() or res['risk_score'] >= 50
        assert "http://malicious-site.com/payload" in res['embedded_urls']
        assert "javascript" in res['suspicious_keywords']

    def test_clean_pdf(self):
        content = b"%PDF-1.4\n/Title (Clean Document)\n"
        res = extract_pdf_metadata(content, "clean.pdf")
        assert res['filename'] == "clean.pdf"
        assert res['risk_score'] < 50

    def test_large_pdf(self):
        content = b"%PDF-1.4\n" + (b"0" * (11 * 1024 * 1024))
        res = extract_pdf_metadata(content, "huge.pdf")
        assert "Unusually large PDF" in res['findings']


class TestTextDetector:
    def test_phishing_text(self):
        text = "URGENT ACTION REQUIRED! Please verify your account immediately at http://login-fake.com or your access will be suspended!"
        res = analyze_text(text)
        assert res['is_phishing'] is True
        assert res['classification'] in ('Suspicious', 'Malicious')

    def test_scam_text(self):
        text = "Congratulations! You have won a free iPhone! Claim your prize now at http://free-gift.com"
        res = analyze_text(text)
        assert res['is_scam'] is True

    def test_spam_text(self):
        text = "Buy now! 100% free discount code for cheap products. Click to opt out."
        res = analyze_text(text)
        assert res['is_spam'] is True

    def test_suspicious_words_and_all_caps(self):
        text = "ATTENTION ALL USERS! ENTER YOUR PASSWORD CREDENTIAL AND SOCIAL SECURITY NUMBER NOW!!!!"
        res = analyze_text(text)
        assert res['suspicious_words'] is not None
        assert "ALL CAPS" in res['findings']


    def test_safe_text(self):
        text = "Hello team, let's schedule our project kickoff meeting for tomorrow afternoon."
        res = analyze_text(text)
        assert res['classification'] == 'Safe'
        assert res['risk_score'] < 30


class TestURLDetector:
    def test_http_ip_based_url(self):
        res = analyze_url("http://192.168.1.1/login")
        assert res['is_https'] is False
        assert res['is_ip_based'] is True
        assert res['has_suspicious_keywords'] is True
        assert res['risk_score'] >= 50

    def test_brand_impersonation(self):
        res = analyze_url("https://secure-login.paypal.phishing.com/verify")
        assert res['phishing_indicators'] is not None
        assert "paypal" in res['phishing_indicators']

    def test_url_shortener(self):
        res = analyze_url("https://bit.ly/3xyz789")
        assert "bit.ly" in res['findings']

    def test_long_url_with_at_and_encoding(self):
        url = "http://user:pass@domain.com/" + ("a" * 120) + "/%20%20%20%20%20%20"
        res = analyze_url(url)
        assert res['url_length'] > 100
        assert "@ symbol" in res['findings']

    def test_clean_https_url(self):
        res = analyze_url("https://github.com/VishnuSreeVidya/CyberShield-AI")
        assert res['is_https'] is True
        assert res['is_ip_based'] is False
        assert res['risk_score'] < 30
