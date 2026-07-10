import json
from app.utils.parsers import (
    parse_file, detect_format, parse_apache_combined, parse_apache_common,
    parse_auth_log, parse_csv, parse_json,
)


class TestFormatDetection:
    def test_detect_apache_combined(self):
        content = '1.2.3.4 - - [10/Jul/2026:08:30:15 +0000] "GET / HTTP/1.1" 200 1234 "-" "Agent"'
        assert detect_format(content) == 'apache_combined'

    def test_detect_apache_common(self):
        content = '1.2.3.4 - - [10/Jul/2026:08:30:15 +0000] "GET / HTTP/1.1" 200 1234'
        assert detect_format(content) == 'apache_common'

    def test_detect_auth(self):
        content = 'Jul 10 08:30:00 server sshd[1234]: Failed password for root from 10.0.0.1 port 22'
        assert detect_format(content) == 'auth'

    def test_detect_json(self):
        content = '[{"ip":"1.2.3.4"}]'
        assert detect_format(content) == 'json'

    def test_detect_csv(self):
        content = 'ip,method,url\n1.2.3.4,GET,/test'
        assert detect_format(content) == 'csv'

    def test_detect_text(self):
        content = 'some random text line\nanother line'
        assert detect_format(content) == 'text'

    def test_empty_content(self):
        assert detect_format('') == 'unknown'
        assert detect_format('   \n  \n') == 'unknown'


class TestApacheCombinedParser:
    def test_full_line(self):
        line = (
            '192.168.1.1 - - [10/Jul/2026:08:30:15 +0000] '
            '"GET /index.html HTTP/1.1" 200 1234 '
            '"http://ref.com" "Mozilla/5.0"'
        )
        result = parse_apache_combined(line)
        assert result is not None
        assert result['ip_address'] == '192.168.1.1'
        assert result['http_method'] == 'GET'
        assert result['request_url'] == '/index.html'
        assert result['status_code'] == 200
        assert result['user_agent'] == 'Mozilla/5.0'

    def test_invalid_line(self):
        assert parse_apache_combined('not a log line') is None


class TestApacheCommonParser:
    def test_full_line(self):
        line = (
            '10.0.0.1 - - [10/Jul/2026:08:30:15 +0000] '
            '"POST /login HTTP/1.1" 401 567'
        )
        result = parse_apache_common(line)
        assert result is not None
        assert result['ip_address'] == '10.0.0.1'
        assert result['http_method'] == 'POST'
        assert result['request_url'] == '/login'
        assert result['status_code'] == 401
        assert result['user_agent'] is None


class TestAuthParser:
    def test_failed_password(self):
        line = 'Jul 10 08:30:00 server sshd[1234]: Failed password for root from 10.0.0.99 port 22 ssh2'
        result = parse_auth_log(line)
        assert result is not None
        assert result['ip_address'] == '10.0.0.99'

    def test_no_match(self):
        assert parse_auth_log('normal log line') is None


class TestCSVParser:
    def test_basic_csv(self):
        content = 'ip_address,method,url,status_code\n10.0.0.1,GET,/home,200\n10.0.0.2,POST,/login,401\n'
        results = parse_csv(content)
        assert len(results) == 2
        assert results[0]['ip_address'] == '10.0.0.1'
        assert results[1]['status_code'] == 401

    def test_csv_with_varied_headers(self):
        content = 'ip,method,path\n1.2.3.4,GET,/test'
        results = parse_csv(content)
        assert len(results) == 1
        assert results[0]['request_url'] == '/test'


class TestJSONParser:
    def test_json_array(self):
        content = json.dumps([
            {'ip_address': '10.0.0.1', 'method': 'GET', 'url': '/index'},
        ])
        results = parse_json(content)
        assert len(results) == 1
        assert results[0]['ip_address'] == '10.0.0.1'

    def test_json_single_object(self):
        content = json.dumps({'ip_address': '10.0.0.1', 'method': 'POST'})
        results = parse_json(content)
        assert len(results) == 1
        assert results[0]['http_method'] == 'POST'

    def test_json_varied_keys(self):
        content = json.dumps([
            {'ip': '1.1.1.1', 'method': 'GET', 'path': '/api', 'status': 200},
        ])
        results = parse_json(content)
        assert results[0]['ip_address'] == '1.1.1.1'
        assert results[0]['request_url'] == '/api'


class TestParseFile:
    def test_parse_apache_file(self, sample_apache_log):
        results = parse_file(sample_apache_log)
        assert len(results) == 2
        assert results[0]['ip_address'] == '192.168.1.1'
        assert results[1]['http_method'] == 'POST'

    def test_parse_auth_file(self, sample_auth_log):
        results = parse_file(sample_auth_log)
        assert len(results) >= 1
        assert results[0]['ip_address'] == '10.0.0.99'

    def test_parse_json_file(self, sample_malicious_json):
        results = parse_file(sample_malicious_json)
        assert len(results) == 1
        assert results[0]['ip_address'] == '5.5.5.5'

    def test_empty_file(self):
        assert parse_file('') == []
        assert parse_file('   \n  \n') == []
