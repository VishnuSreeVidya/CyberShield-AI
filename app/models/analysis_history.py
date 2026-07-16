from datetime import datetime, timezone
from app import db


class AnalysisHistory(db.Model):
    __tablename__ = 'analysis_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    analysis_type = db.Column(db.String(50), nullable=False, index=True)
    threat_level = db.Column(db.String(20), nullable=False, default='Low')
    risk_score = db.Column(db.Float, default=0.0)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('analyses', lazy='dynamic'))

    def __repr__(self):
        return f'<AnalysisHistory {self.analysis_type} [{self.threat_level}]>'
