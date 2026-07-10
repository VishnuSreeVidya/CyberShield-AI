from datetime import datetime, timezone
from app import db


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('logs.id'), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    attack_type = db.Column(db.String(100), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default='Low')
    description = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Alert {self.attack_type} [{self.severity}]>'
