from flask import jsonify
from flask_login import login_required
from app import db
from app.models import LogEntry, Alert, Report
from sqlalchemy import func


def register_api_routes(main_bp):

    @main_bp.route('/api/dashboard/stats')
    @login_required
    def dashboard_stats():
        total_logs = LogEntry.query.count()
        total_alerts = Alert.query.count()
        critical = Alert.query.filter_by(severity='Critical').count()
        high = Alert.query.filter_by(severity='High').count()
        medium = Alert.query.filter_by(severity='Medium').count()
        low = Alert.query.filter_by(severity='Low').count()
        total_reports = Report.query.count()

        return jsonify({
            'total_logs': total_logs,
            'total_alerts': total_alerts,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'total_reports': total_reports,
        })

    @main_bp.route('/api/dashboard/alerts_by_type')
    @login_required
    def alerts_by_type():
        rows = db.session.query(
            Alert.attack_type, func.count(Alert.id)
        ).group_by(Alert.attack_type).all()
        return jsonify({row[0]: row[1] for row in rows})

    @main_bp.route('/api/dashboard/recent_alerts')
    @login_required
    def recent_alerts():
        alerts = Alert.query.order_by(
            Alert.detected_at.desc()
        ).limit(10).all()
        return jsonify([{
            'id': a.id,
            'attack_type': a.attack_type,
            'severity': a.severity,
            'description': a.description,
            'detected_at': a.detected_at.isoformat() if a.detected_at else None,
        } for a in alerts])
