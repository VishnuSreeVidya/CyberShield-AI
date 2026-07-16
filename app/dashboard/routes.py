import csv
import io
import json
from datetime import datetime, timezone
from flask import render_template, request, redirect, url_for, flash, Response
from flask_login import login_required, current_user
from app.models import (
    LogEntry, Alert, User, AnalysisHistory,
    URLAnalysis, TextAnalysis, PDFAnalysis, IPAnalysis, HashAnalysis,
)
from sqlalchemy import func
from app import db
from app.auth.forms import ChangePasswordForm, ProfileForm
from . import dashboard_bp


@dashboard_bp.route('/')
@login_required
def index():
    total_logs = LogEntry.query.count()
    total_alerts = Alert.query.count()

    failed_login = Alert.query.filter_by(attack_type='Failed Login Attempt').count()
    brute_force = Alert.query.filter_by(attack_type='Brute Force Attack').count()
    sql_injection = Alert.query.filter_by(attack_type='SQL Injection').count()
    xss = Alert.query.filter_by(attack_type='Cross Site Scripting (XSS)').count()
    directory_traversal = Alert.query.filter_by(attack_type='Directory Traversal').count()
    port_scan = Alert.query.filter_by(attack_type='Port Scanning').count()
    dos = Alert.query.filter_by(attack_type='Denial of Service (DoS)').count()

    critical = Alert.query.filter_by(severity='Critical').count()
    high = Alert.query.filter_by(severity='High').count()
    medium = Alert.query.filter_by(severity='Medium').count()
    low = Alert.query.filter_by(severity='Low').count()

    high_risk_ips = db.session.query(
        Alert.source_ip
    ).filter(
        Alert.severity.in_(['Critical', 'High']),
        Alert.source_ip.isnot(None),
    ).distinct().count()

    recent_alerts = Alert.query.order_by(
        Alert.detected_at.desc()
    ).limit(10).all()

    total_analyses = AnalysisHistory.query.count()
    url_count = URLAnalysis.query.count()
    text_count = TextAnalysis.query.count()
    pdf_count = PDFAnalysis.query.count()
    ip_count = IPAnalysis.query.count()
    hash_count = HashAnalysis.query.count()

    critical_analyses = AnalysisHistory.query.filter_by(threat_level='Critical').count()
    high_analyses = AnalysisHistory.query.filter_by(threat_level='High').count()
    medium_analyses = AnalysisHistory.query.filter_by(threat_level='Medium').count()
    low_analyses = AnalysisHistory.query.filter_by(threat_level='Low').count()

    recent_analyses = AnalysisHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(AnalysisHistory.created_at.desc()).limit(10).all()

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
        total_analyses=total_analyses,
        url_count=url_count,
        text_count=text_count,
        pdf_count=pdf_count,
        ip_count=ip_count,
        hash_count=hash_count,
        critical_analyses=critical_analyses,
        high_analyses=high_analyses,
        medium_analyses=medium_analyses,
        low_analyses=low_analyses,
        recent_analyses=recent_analyses,
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
    total_logs = LogEntry.query.count()
    total_alerts = Alert.query.count()

    attack_types = db.session.query(
        Alert.attack_type, func.count(Alert.id).label('cnt')
    ).group_by(Alert.attack_type).order_by(func.count(Alert.id).desc()).all()

    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id).label('cnt')
    ).group_by(Alert.severity).order_by(Alert.severity).all()

    top_ips = db.session.query(
        Alert.source_ip, func.count(Alert.id).label('cnt')
    ).filter(Alert.source_ip.isnot(None)).group_by(Alert.source_ip).order_by(
        func.count(Alert.id).desc()
    ).limit(10).all()

    recent_alerts = Alert.query.order_by(Alert.detected_at.desc()).limit(50).all()

    total_analyses = AnalysisHistory.query.count()
    analysis_types = db.session.query(
        AnalysisHistory.analysis_type, func.count(AnalysisHistory.id)
    ).group_by(AnalysisHistory.analysis_type).all()

    analysis_threats = db.session.query(
        AnalysisHistory.threat_level, func.count(AnalysisHistory.id)
    ).group_by(AnalysisHistory.threat_level).all()

    return render_template(
        'dashboard/reports.html',
        total_logs=total_logs,
        total_alerts=total_alerts,
        attack_types=attack_types,
        severity_counts=severity_counts,
        top_ips=top_ips,
        recent_alerts=recent_alerts,
        now=datetime.now,
        total_analyses=total_analyses,
        analysis_types=analysis_types,
        analysis_threats=analysis_threats,
    )


@dashboard_bp.route('/reports/export/csv')
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Attack Type', 'Severity', 'Source IP', 'Description', 'Log ID', 'Detected At'])

    for alert in Alert.query.order_by(Alert.detected_at.desc()).all():
        writer.writerow([
            alert.id,
            alert.attack_type,
            alert.severity,
            alert.source_ip or '',
            alert.description or '',
            alert.log_id or '',
            alert.detected_at.strftime('%Y-%m-%d %H:%M:%S') if alert.detected_at else '',
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=alerts_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv'}
    )


@dashboard_bp.route('/reports/export/json')
@login_required
def export_json():
    alerts_data = []
    for alert in Alert.query.order_by(Alert.detected_at.desc()).all():
        alerts_data.append({
            'id': alert.id,
            'attack_type': alert.attack_type,
            'severity': alert.severity,
            'source_ip': alert.source_ip,
            'description': alert.description,
            'log_id': alert.log_id,
            'detected_at': alert.detected_at.strftime('%Y-%m-%d %H:%M:%S') if alert.detected_at else None,
        })

    return Response(
        json.dumps(alerts_data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename=alerts_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json'}
    )


@dashboard_bp.route('/reports/export/pdf')
@login_required
def export_pdf():
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
    import tempfile
    import os

    attack_types = db.session.query(
        Alert.attack_type, func.count(Alert.id)
    ).group_by(Alert.attack_type).order_by(func.count(Alert.id).desc()).all()

    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).group_by(Alert.severity).order_by(Alert.severity).all()

    top_ips = db.session.query(
        Alert.source_ip, func.count(Alert.id)
    ).filter(Alert.source_ip.isnot(None)).group_by(Alert.source_ip).order_by(
        func.count(Alert.id).desc()
    ).limit(10).all()

    total_logs = LogEntry.query.count()
    total_alerts = Alert.query.count()
    total_analyses = AnalysisHistory.query.count()

    tmp = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
    tmp_path = tmp.name
    tmp.close()

    try:
        with PdfPages(tmp_path) as pdf:
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.axis('off')
            ax.text(0.5, 0.85, 'CyberShield AI', fontsize=24, fontweight='bold',
                    ha='center', va='center', color='#00ff88', family='monospace')
            ax.text(0.5, 0.70, 'Security Operations Center Report', fontsize=12,
                    ha='center', va='center', color='#8888aa')
            ax.text(0.5, 0.55, f'Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}',
                    fontsize=9, ha='center', va='center', color='#55557a')
            ax.text(0.5, 0.40, f'Total Logs Processed: {total_logs}', fontsize=11,
                    ha='center', va='center', color='#e8e8f0')
            ax.text(0.5, 0.30, f'Total Alerts Generated: {total_alerts}', fontsize=11,
                    ha='center', va='center', color='#e8e8f0')
            ax.text(0.5, 0.20, f'Total Analyses Performed: {total_analyses}', fontsize=11,
                    ha='center', va='center', color='#e8e8f0')
            fig.patch.set_facecolor('#0a0a0f')
            pdf.savefig(fig, facecolor=fig.get_facecolor())
            plt.close(fig)

            if attack_types:
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor('#0a0a0f')
                ax.set_facecolor('#0a0a0f')
                labels = [t[0] for t in attack_types]
                values = [t[1] for t in attack_types]
                colors = ['#ff3355', '#ff8800', '#ffc107', '#00bbff', '#00ff88', '#d946ef', '#6c757d']
                ax.barh(labels, values, color=colors[:len(labels)], edgecolor='none')
                ax.set_title('Attack Type Breakdown', color='#e8e8f0', fontsize=14, fontweight='bold', pad=12)
                ax.tick_params(colors='#8888aa', labelsize=9)
                ax.invert_yaxis()
                for spine in ax.spines.values():
                    spine.set_visible(False)
                fig.tight_layout()
                pdf.savefig(fig, facecolor=fig.get_facecolor())
                plt.close(fig)

            if severity_counts:
                fig, ax = plt.subplots(figsize=(6, 4))
                fig.patch.set_facecolor('#0a0a0f')
                ax.set_facecolor('#0a0a0f')
                sev_colors = {'Critical': '#ff3355', 'High': '#ff8800', 'Medium': '#ffc107', 'Low': '#6c757d'}
                labels = [s[0] for s in severity_counts]
                values = [s[1] for s in severity_counts]
                colors = [sev_colors.get(l, '#6c757d') for l in labels]
                ax.bar(labels, values, color=colors, edgecolor='none', width=0.6)
                ax.set_title('Severity Distribution', color='#e8e8f0', fontsize=14, fontweight='bold', pad=12)
                ax.tick_params(colors='#8888aa', labelsize=9)
                for spine in ax.spines.values():
                    spine.set_visible(False)
                fig.tight_layout()
                pdf.savefig(fig, facecolor=fig.get_facecolor())
                plt.close(fig)

            if top_ips:
                fig, ax = plt.subplots(figsize=(8, 4))
                fig.patch.set_facecolor('#0a0a0f')
                ax.set_facecolor('#0a0a0f')
                ips = [t[0] for t in top_ips]
                cnts = [t[1] for t in top_ips]
                ax.barh(ips, cnts, color='#00ff88', edgecolor='none', alpha=0.7)
                ax.set_title('Top Attacking IPs', color='#e8e8f0', fontsize=14, fontweight='bold', pad=12)
                ax.tick_params(colors='#8888aa', labelsize=9)
                ax.invert_yaxis()
                for spine in ax.spines.values():
                    spine.set_visible(False)
                fig.tight_layout()
                pdf.savefig(fig, facecolor=fig.get_facecolor())
                plt.close(fig)

            recent = Alert.query.order_by(Alert.detected_at.desc()).limit(50).all()
            if recent:
                fig, ax = plt.subplots(figsize=(10, 6))
                fig.patch.set_facecolor('#0a0a0f')
                ax.set_facecolor('#0a0a0f')
                ax.axis('off')
                ax.set_title('Recent Alerts (Last 50)', color='#e8e8f0', fontsize=14, fontweight='bold', pad=12)
                cell_text = []
                for a in recent[:30]:
                    cell_text.append([
                        str(a.id),
                        a.attack_type[:30],
                        a.severity,
                        a.source_ip or '-',
                        a.detected_at.strftime('%Y-%m-%d %H:%M') if a.detected_at else '-',
                    ])
                table = ax.table(cellText=cell_text,
                                 colLabels=['ID', 'Attack Type', 'Severity', 'Source IP', 'Detected At'],
                                 loc='center', cellLoc='left')
                table.auto_set_font_size(False)
                table.set_fontsize(7)
                table.scale(1, 1.2)
                for key, cell in table.get_celld().items():
                    cell.set_edgecolor('#333355')
                    if key[0] == 0:
                        cell.set_facecolor('#1a1a2e')
                        cell.set_text_props(color='#00ff88', fontweight='bold')
                    else:
                        cell.set_facecolor('#0a0a0f')
                        cell.set_text_props(color='#e8e8f0')
                fig.tight_layout()
                pdf.savefig(fig, facecolor=fig.get_facecolor())
                plt.close(fig)

        with open(tmp_path, 'rb') as f:
            pdf_bytes = f.read()

        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment;filename=cybershield_report_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.pdf'
            },
        )
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@dashboard_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    profile_form = ProfileForm(obj=current_user)
    password_form = ChangePasswordForm()

    if request.method == 'POST':
        action = request.form.get('submit', '')

        if action == 'profile' and profile_form.validate():
            new_username = profile_form.username.data
            new_email = profile_form.email.data

            if new_username != current_user.username:
                existing = User.query.filter_by(username=new_username).first()
                if existing:
                    flash('Username already taken.', 'danger')
                    return render_template('dashboard/settings.html', profile_form=profile_form, password_form=password_form)
            if new_email != current_user.email:
                existing = User.query.filter_by(email=new_email).first()
                if existing:
                    flash('Email already registered.', 'danger')
                    return render_template('dashboard/settings.html', profile_form=profile_form, password_form=password_form)

            current_user.username = new_username
            current_user.email = new_email
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('dashboard.settings'))

        if action == 'password' and password_form.validate():
            if not current_user.check_password(password_form.old_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('dashboard/settings.html', profile_form=profile_form, password_form=password_form)
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard.settings'))

    return render_template('dashboard/settings.html', profile_form=profile_form, password_form=password_form)
