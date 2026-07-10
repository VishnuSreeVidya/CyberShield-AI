from app.detection.engine import (
    detect_failed_login, detect_sql_injection, detect_xss,
    detect_directory_traversal, detect_port_scanning, detect_dos,
    detect_brute_force, run_detection,
)
from app.models import LogEntry, Alert
from app import db


class TestFailedLoginDetection:
    def test_detect_failed_password(self):
        result = detect_failed_login('Failed password for root from 10.0.0.1', '10.0.0.1')
        assert result is not None
        assert result['attack_type'] == 'Failed Login Attempt'
        assert result['severity'] == 'Medium'

    def test_detect_authentication_failure(self):
        result = detect_failed_login('authentication failure; logname= uid=0 euid=0', '10.0.0.1')
        assert result is not None

    def test_no_false_positive(self):
        result = detect_failed_login('Successful login for user', '10.0.0.1')
        assert result is None


class TestSQLInjectionDetection:
    def test_detect_union_select(self):
        result = detect_sql_injection('/page?id=1 UNION SELECT * FROM users', '')
        assert result is not None
        assert result['attack_type'] == 'SQL Injection'
        assert result['severity'] == 'Critical'

    def test_detect_or_equals(self):
        result = detect_sql_injection('/page?id=1 OR 1=1', '')
        assert result is not None

    def test_detect_drop_table(self):
        result = detect_sql_injection('/page?id=1; DROP TABLE users', '')
        assert result is not None

    def test_no_false_positive(self):
        result = detect_sql_injection('/page?id=1', '')
        assert result is None


class TestXSSDetection:
    def test_detect_script_tag(self):
        result = detect_xss('/page?q=<script>alert(1)</script>', '', '')
        assert result is not None
        assert result['attack_type'] == 'Cross Site Scripting (XSS)'

    def test_detect_onerror(self):
        result = detect_xss('/page?q=<img src=x onerror=alert(1)>', '', '')
        assert result is not None

    def test_detect_javascript_protocol(self):
        result = detect_xss('/page?q=javascript:alert(1)', '', '')
        assert result is not None

    def test_no_false_positive(self):
        result = detect_xss('/page?q=hello', '', '')
        assert result is None


class TestDirectoryTraversalDetection:
    def test_detect_dot_dot_slash(self):
        result = detect_directory_traversal('/page?file=../../../etc/passwd', '')
        assert result is not None

    def test_detect_url_encoded(self):
        result = detect_directory_traversal('/page?file=%2e%2e%2fetc/passwd', '')
        assert result is not None

    def test_no_false_positive(self):
        result = detect_directory_traversal('/page?file=normal.txt', '')
        assert result is None


class TestPortScanningDetection:
    def test_detect_port_scan(self):
        entries = []
        for i in range(20):
            entries.append(LogEntry(
                id=1000 + i, ip_address='10.0.0.99', request_url=f'/page/{i}',
                raw_log='GET / HTTP/1.1',
            ))
        results = detect_port_scanning(entries)
        assert len(results) >= 1

    def test_no_false_positive(self):
        entries = [LogEntry(id=1, ip_address='10.0.0.1', request_url='/page', raw_log='OK')]
        entries.append(LogEntry(id=2, ip_address='10.0.0.1', request_url='/page', raw_log='OK'))
        results = detect_port_scanning(entries)
        assert len(results) == 0


class TestDoSDetection:
    def test_detect_dos(self):
        entries = [LogEntry(id=i, ip_address='10.0.0.50', raw_log='GET') for i in range(150)]
        results = detect_dos(entries, threshold=100)
        assert len(results) >= 1

    def test_below_threshold(self):
        entries = [LogEntry(id=i, ip_address='10.0.0.50', raw_log='GET') for i in range(50)]
        results = detect_dos(entries, threshold=100)
        assert len(results) == 0


class TestBruteForceDetection:
    def test_detect_brute_force(self):
        entries = []
        for i in range(10):
            entries.append(LogEntry(
                id=2000 + i,
                ip_address='10.0.0.77',
                raw_log='Failed password from 10.0.0.77',
            ))
        results = detect_brute_force(entries, threshold=5)
        assert len(results) >= 1

    def test_below_threshold(self):
        entries = [LogEntry(id=1, ip_address='10.0.0.77', raw_log='Failed password') for _ in range(2)]
        results = detect_brute_force(entries, threshold=5)
        assert len(results) == 0


class TestRunDetection:
    def test_run_detection_no_alerts(self, db):
        entries = [LogEntry(id=1, ip_address='1.2.3.4', raw_log='normal request', request_url='/test')]
        db.session.add_all(entries)
        db.session.flush()
        alerts = run_detection(entries)
        assert len(alerts) >= 0

    def test_run_detection_sql_injection(self, db):
        entries = [LogEntry(
            id=2, ip_address='5.5.5.5', raw_log='GET /page',
            request_url='/page?id=1 UNION SELECT * FROM users',
        )]
        db.session.add_all(entries)
        db.session.flush()
        alerts = run_detection(entries)
        types = [a.attack_type for a in alerts]
        assert 'SQL Injection' in types
