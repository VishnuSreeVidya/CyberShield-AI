from datetime import datetime, timezone
from app import db


class LogEntry(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    http_method = db.Column(db.String(10), nullable=True)
    request_url = db.Column(db.Text, nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    raw_log = db.Column(db.Text, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    alerts = db.relationship(
        'Alert', backref='log', lazy='dynamic', cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<LogEntry {self.ip_address} @ {self.timestamp}>'
