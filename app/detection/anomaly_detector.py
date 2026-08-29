import math
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest

SPECIAL_CHARS = set("'\"<>;%-=/\\")

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(entry: Any) -> List[float]:
    raw_log = getattr(entry, 'raw_log', '') or ''
    url = getattr(entry, 'request_url', '') or ''
    method = getattr(entry, 'http_method', '') or ''
    status_code = getattr(entry, 'status_code', 200) or 200

    raw_len = float(len(raw_log))
    url_len = float(len(url))
    spec_count = float(sum(1 for c in (url + raw_log) if c in SPECIAL_CHARS))
    param_count = float(url.count('?') + url.count('&'))
    entropy = calculate_entropy(url or raw_log)
    is_post_or_put = 1.0 if method.upper() in ('POST', 'PUT', 'DELETE') else 0.0
    status_err = 1.0 if status_code >= 400 else 0.0

    return [raw_len, url_len, spec_count, param_count, entropy, is_post_or_put, status_err]

class LogAnomalyDetector:
    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self._is_fitted = False
        self._fit_default_baseline()

    def _fit_default_baseline(self):
        # Baseline normal HTTP traffic features
        normal_samples = [
            [50.0, 15.0, 1.0, 0.0, 3.2, 0.0, 0.0],
            [60.0, 20.0, 2.0, 0.0, 3.5, 0.0, 0.0],
            [80.0, 25.0, 2.0, 1.0, 3.8, 1.0, 0.0],
            [55.0, 12.0, 1.0, 0.0, 3.1, 0.0, 0.0],
            [70.0, 18.0, 2.0, 0.0, 3.4, 0.0, 0.0],
            [90.0, 30.0, 3.0, 1.0, 4.0, 1.0, 0.0],
        ]
        self.model.fit(np.array(normal_samples))
        self._is_fitted = True

    def detect_anomalies(self, entries: List[Any]) -> List[Dict[str, Any]]:
        if not entries:
            return []

        features = [extract_features(e) for e in entries]
        X = np.array(features)
        
        # Fit on current batch if large enough to learn session context
        if len(entries) >= 10:
            try:
                self.model.fit(X)
            except Exception:
                pass

        scores = self.model.decision_function(X)
        predictions = self.model.predict(X)

        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1 or score < -0.15:
                entry = entries[i]
                ip = getattr(entry, 'ip_address', 'unknown')
                url = getattr(entry, 'request_url', '') or getattr(entry, 'raw_log', '')[:40]
                severity = 'High' if score < -0.30 else 'Medium'
                anomalies.append({
                    'log_entry_index': i,
                    'log_entry': entry,
                    'attack_type': 'Anomalous Request Pattern',
                    'severity': severity,
                    'description': f'ML Anomaly Detector flagged request from {ip} (score: {score:.2f}): "{url[:50]}"',
                })
        return anomalies

anomaly_detector = LogAnomalyDetector()
