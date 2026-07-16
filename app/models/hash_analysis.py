from datetime import datetime, timezone
from app import db


class HashAnalysis(db.Model):
    __tablename__ = 'hash_analyses'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('analysis_history.id'), nullable=False, index=True)
    hash_value = db.Column(db.String(64), nullable=False)
    hash_type = db.Column(db.String(10), nullable=False)
    is_valid_format = db.Column(db.Boolean, default=True)
    threat_status = db.Column(db.String(20), nullable=False, default='Safe')
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    history = db.relationship('AnalysisHistory', backref=db.backref('hash_detail', uselist=False))

    def __repr__(self):
        return f'<HashAnalysis {self.hash_type} [{self.threat_status}]>'
