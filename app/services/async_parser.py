import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from flask import current_app
from app import db
from app.models import LogEntry, Alert
from app.utils.parsers import parse_file
from app.detection.engine import run_detection

_executor = ThreadPoolExecutor(max_workers=4)
_jobs_lock = threading.Lock()
UPLOAD_JOBS = {}


def get_job_status(job_id: str) -> dict:
    with _jobs_lock:
        return UPLOAD_JOBS.get(job_id, {'status': 'not_found'})


def process_log_file_async(app, job_id: str, content: str, filename: str):
    with app.app_context():
        try:
            with _jobs_lock:
                UPLOAD_JOBS[job_id]['status'] = 'processing'

            parsed = parse_file(content, filename=filename)
            if not parsed:
                with _jobs_lock:
                    UPLOAD_JOBS[job_id]['status'] = 'completed'
                    UPLOAD_JOBS[job_id]['total_entries'] = 0
                    UPLOAD_JOBS[job_id]['threats_detected'] = 0
                return

            total = len(parsed)
            with _jobs_lock:
                UPLOAD_JOBS[job_id]['total_entries'] = total

            now = datetime.now(timezone.utc)
            entries = []
            chunk_size = 1000

            for i, p in enumerate(parsed):
                ts = p.get('timestamp')
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

                if len(entries) >= chunk_size or i == total - 1:
                    db.session.commit()
                    with _jobs_lock:
                        UPLOAD_JOBS[job_id]['processed_entries'] += len(entries)

            alerts = run_detection(entries)
            for alert in alerts:
                db.session.add(alert)
            db.session.commit()

            with _jobs_lock:
                UPLOAD_JOBS[job_id]['status'] = 'completed'
                UPLOAD_JOBS[job_id]['threats_detected'] = len(alerts)

        except Exception as e:
            db.session.rollback()
            with _jobs_lock:
                UPLOAD_JOBS[job_id]['status'] = 'failed'
                UPLOAD_JOBS[job_id]['error'] = str(e)


def enqueue_log_upload(app, content: str, filename: str) -> str:
    job_id = str(uuid.uuid4())
    with _jobs_lock:
        UPLOAD_JOBS[job_id] = {
            'job_id': job_id,
            'filename': filename,
            'status': 'pending',
            'total_entries': 0,
            'processed_entries': 0,
            'threats_detected': 0,
            'error': None,
            'created_at': datetime.now(timezone.utc).isoformat(),
        }

    app_obj = getattr(app, '_get_current_object', lambda: app)()
    _executor.submit(process_log_file_async, app_obj, job_id, content, filename)
    return job_id

