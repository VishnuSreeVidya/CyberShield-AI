import pytest
from app.detection.anomaly_detector import LogAnomalyDetector, extract_features

class DummyEntry:
    def __init__(self, raw_log, url='', method='GET', status=200, ip='192.168.1.1', id=1):
        self.raw_log = raw_log
        self.request_url = url
        self.http_method = method
        self.status_code = status
        self.ip_address = ip
        self.id = id

def test_extract_features():
    entry = DummyEntry(raw_log='192.168.1.1 GET /index.html 200', url='/index.html')
    features = extract_features(entry)
    assert len(features) == 7
    assert features[1] == len('/index.html')

def test_anomaly_detector_scoring():
    detector = LogAnomalyDetector()
    entries = [
        DummyEntry('192.168.1.1 GET /index.html 200', url='/index.html'),
        DummyEntry('192.168.1.1 GET /about.html 200', url='/about.html'),
        DummyEntry('10.0.0.5 POST /admin/login?exec=cat%20/etc/passwd%27%22%3C%3E 500', url='/admin/login?exec=cat%20/etc/passwd%27%22%3C%3E', method='POST', status=500),
    ]
    anomalies = detector.detect_anomalies(entries)
    assert isinstance(anomalies, list)
