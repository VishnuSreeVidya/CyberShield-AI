import pytest
import time
from app.services.async_parser import enqueue_log_upload, get_job_status
from app.models import LogEntry, Alert


def test_async_parser_workflow(app):
    content = (
        '192.168.1.50 - - [10/Jul/2026:08:30:15 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        '10.0.0.99 - - [10/Jul/2026:08:31:00 +0000] "POST /login?id=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1" 200 567 "-" "curl/7.68.0"\n'
    )
    job_id = enqueue_log_upload(app, content, 'test_async.log')
    assert job_id is not None

    # Wait up to 5 seconds for async task completion
    for _ in range(50):
        status = get_job_status(job_id)
        if status['status'] in ('completed', 'failed'):
            break
        time.sleep(0.1)

    status = get_job_status(job_id)
    assert status['status'] == 'completed'
    assert status['total_entries'] == 2

    with app.app_context():
        assert LogEntry.query.count() >= 2


def test_get_job_status_not_found(app):
    status = get_job_status('non-existent-job-id')
    assert status['status'] == 'not_found'
