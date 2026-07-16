from datetime import datetime, timezone
from app import db


class IPAnalysis(db.Model):
    __tablename__ = 'ip_analyses'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('analysis_history.id'), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    is_valid = db.Column(db.Boolean, default=True)
    is_reserved = db.Column(db.Boolean, default=False)
    ip_type = db.Column(db.String(20), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    history = db.relationship('AnalysisHistory', backref=db.backref('ip_detail', uselist=False))

    def __repr__(self):
        return f'<IPAnalysis {self.ip_address}>'
