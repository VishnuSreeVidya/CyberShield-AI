from datetime import datetime, timezone
from app import db


class TextAnalysis(db.Model):
    __tablename__ = 'text_analyses'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('analysis_history.id'), nullable=False, index=True)
    input_text = db.Column(db.Text, nullable=False)
    classification = db.Column(db.String(50), nullable=False, default='Safe')
    confidence_score = db.Column(db.Float, default=0.0)
    is_phishing = db.Column(db.Boolean, default=False)
    is_scam = db.Column(db.Boolean, default=False)
    is_spam = db.Column(db.Boolean, default=False)
    suspicious_words = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    history = db.relationship('AnalysisHistory', backref=db.backref('text_detail', uselist=False))

    def __repr__(self):
        return f'<TextAnalysis [{self.classification}]>'
