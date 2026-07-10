from flask import render_template, request
from flask_login import login_required
from app.models import LogEntry, Alert
from sqlalchemy import func
from app import db
from . import dashboard_bp


@dashboard_bp.route('/')
@login_required
def index():
    total_logs = LogEntry.query.count()
    total_alerts = Alert.query.count()

    failed_login = Alert.query.filter_by(attack_type='Failed Login').count()
    brute_force = Alert.query.filter_by(attack_type='Brute Force').count()
    sql_injection = Alert.query.filter_by(attack_type='SQL Injection').count()
    xss = Alert.query.filter_by(attack_type='XSS').count()
    directory_traversal = Alert.query.filter_by(attack_type='Directory Traversal').count()
    port_scan = Alert.query.filter_by(attack_type='Port Scanning').count()
    dos = Alert.query.filter_by(attack_type='DoS').count()

    critical = Alert.query.filter_by(severity='Critical').count()
    high = Alert.query.filter_by(severity='High').count()
    medium = Alert.query.filter_by(severity='Medium').count()
    low = Alert.query.filter_by(severity='Low').count()

    high_risk_ips = db.session.query(
        Alert.source_ip, func.count(Alert.id).label('cnt')
    ).filter(
        Alert.severity.in_(['Critical', 'High'])
    ).group_by(
        Alert.source_ip
    ).having(
        func.count(Alert.id) >= 1
    ).count()

    recent_alerts = Alert.query.order_by(
        Alert.detected_at.desc()
    ).limit(10).all()

    return render_template(
        'dashboard/index.html',
        total_logs=total_logs,
        total_alerts=total_alerts,
        failed_login=failed_login,
        brute_force=brute_force,
        sql_injection=sql_injection,
        xss=xss,
        directory_traversal=directory_traversal,
        port_scan=port_scan,
        dos=dos,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        high_risk_ips=high_risk_ips,
        recent_alerts=recent_alerts,
    )


@dashboard_bp.route('/alerts')
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)
    pagination = Alert.query.order_by(Alert.detected_at.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template('dashboard/alerts.html', alerts=pagination.items, pagination=pagination)


@dashboard_bp.route('/reports')
@login_required
def reports():
    return render_template('dashboard/reports.html')


@dashboard_bp.route('/settings')
@login_required
def settings():
    return render_template('dashboard/settings.html')
