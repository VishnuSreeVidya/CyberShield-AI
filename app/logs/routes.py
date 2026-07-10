import os
from datetime import datetime, timezone
from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required
from app import db
from app.models import LogEntry, Alert
from app.utils.parsers import parse_file
from app.detection.engine import run_detection
from sqlalchemy.orm import joinedload
from . import logs_bp


ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv', '.json'}


def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


@logs_bp.route('/')
@login_required
def list_logs():
    page = request.args.get('page', 1, type=int)
    pagination = LogEntry.query.order_by(
        LogEntry.uploaded_at.desc()
    ).paginate(page=page, per_page=25, error_out=False)
    return render_template(
        'logs/list.html',
        logs=pagination.items,
        pagination=pagination,
    )


@logs_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename:
            flash('No file selected.', 'danger')
            return render_template('logs/upload.html')

        if not allowed_file(file.filename):
            flash('Unsupported file type. Use .log, .txt, .csv, or .json.', 'danger')
            return render_template('logs/upload.html')

        try:
            content = file.read().decode('utf-8', errors='replace')
        except Exception:
            flash('Could not read file. Ensure it is UTF-8 encoded.', 'danger')
            return render_template('logs/upload.html')

        parsed = parse_file(content, filename=file.filename)
        if not parsed:
            flash('No log entries could be parsed from the file.', 'warning')
            return render_template('logs/upload.html')

        now = datetime.now(timezone.utc)
        entries = []
        for p in parsed:
            ts = p['timestamp']
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    ts = None
            entry = LogEntry(
                timestamp=ts,
                ip_address=p.get('ip_address'),
                http_method=p.get('http_method'),
                request_url=p.get('request_url'),
                status_code=p.get('status_code'),
                user_agent=p.get('user_agent'),
                raw_log=p.get('raw_log', ''),
                uploaded_at=now,
            )
            db.session.add(entry)
            entries.append(entry)

        db.session.commit()

        new_alerts = run_detection(entries)
        for alert in new_alerts:
            db.session.add(alert)
        db.session.commit()

        flash(
            f'Processed {len(entries)} log entries. '
            f'Detected {len(new_alerts)} threats.',
            'success',
        )
        return redirect(url_for('logs.list_logs'))

    return render_template('logs/upload.html')


@logs_bp.route('/threats')
@login_required
def threats():
    page = request.args.get('page', 1, type=int)
    alert_log_ids = [r[0] for r in db.session.query(Alert.log_id).distinct().all()]
    pagination = LogEntry.query.options(joinedload(LogEntry.alerts)).filter(
        LogEntry.id.in_(alert_log_ids)
    ).order_by(LogEntry.uploaded_at.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template('logs/threats.html', logs=pagination.items, pagination=pagination)


@logs_bp.route('/<int:log_id>')
@login_required
def detail(log_id):
    entry = LogEntry.query.get_or_404(log_id)
    alerts = Alert.query.filter_by(log_id=log_id).all()
    return render_template('logs/detail.html', entry=entry, alerts=alerts)


@logs_bp.route('/<int:log_id>/delete', methods=['POST'])
@login_required
def delete(log_id):
    entry = LogEntry.query.get_or_404(log_id)
    db.session.delete(entry)
    db.session.commit()
    flash('Log entry deleted.', 'info')
    return redirect(url_for('logs.list_logs'))
