from datetime import datetime, timezone
from app import db


class URLAnalysis(db.Model):
    __tablename__ = 'url_analyses'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('analysis_history.id'), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    is_https = db.Column(db.Boolean, default=False)
    url_length = db.Column(db.Integer, default=0)
    has_suspicious_keywords = db.Column(db.Boolean, default=False)
    is_ip_based = db.Column(db.Boolean, default=False)
    phishing_indicators = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    history = db.relationship('AnalysisHistory', backref=db.backref('url_detail', uselist=False))

    def __repr__(self):
        return f'<URLAnalysis {self.url[:50]}>'
