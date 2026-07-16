from datetime import datetime, timezone
from app import db


class PDFAnalysis(db.Model):
    __tablename__ = 'pdf_analyses'

    id = db.Column(db.Integer, primary_key=True)
    history_id = db.Column(db.Integer, db.ForeignKey('analysis_history.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    author = db.Column(db.String(200), nullable=True)
    creation_date = db.Column(db.DateTime, nullable=True)
    page_count = db.Column(db.Integer, default=0)
    embedded_urls = db.Column(db.Text, nullable=True)
    suspicious_keywords = db.Column(db.Text, nullable=True)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    history = db.relationship('AnalysisHistory', backref=db.backref('pdf_detail', uselist=False))

    def __repr__(self):
        return f'<PDFAnalysis {self.filename}>'
