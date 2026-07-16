from flask import jsonify
from flask_login import login_required
from datetime import datetime, timedelta, timezone
from app import db
from app.models import LogEntry, Alert, Report, AnalysisHistory
from sqlalchemy import func, extract, case


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
        total_analyses = AnalysisHistory.query.count()

        return jsonify({
            'total_logs': total_logs,
            'total_alerts': total_alerts,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'total_reports': total_reports,
            'total_analyses': total_analyses,
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
            'source_ip': a.source_ip,
            'detected_at': a.detected_at.isoformat() if a.detected_at else None,
        } for a in alerts])

    @main_bp.route('/api/dashboard/timeline')
    @login_required
    def attack_timeline():
        now = datetime.now(timezone.utc)
        hours = []
        counts = []
        for i in range(23, -1, -1):
            start = now - timedelta(hours=i + 1)
            end = now - timedelta(hours=i)
            label = end.strftime('%H:00')
            count = Alert.query.filter(
                Alert.detected_at >= start,
                Alert.detected_at < end,
            ).count()
            hours.append(label)
            counts.append(count)
        return jsonify({'labels': hours, 'data': counts})

    @main_bp.route('/api/dashboard/top_ips')
    @login_required
    def top_ips():
        rows = db.session.query(
            Alert.source_ip, func.count(Alert.id).label('cnt')
        ).filter(
            Alert.source_ip.isnot(None)
        ).group_by(
            Alert.source_ip
        ).order_by(
            func.count(Alert.id).desc()
        ).limit(10).all()
        return jsonify({
            'labels': [row[0] for row in rows],
            'data': [row[1] for row in rows],
        })
