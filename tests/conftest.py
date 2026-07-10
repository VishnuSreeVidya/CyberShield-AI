import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app, db as _db
from app.models import User, LogEntry, Alert, Report
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret'


@pytest.fixture(scope='function')
def app():
    application = create_app(TestConfig)
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()


@pytest.fixture(scope='function')
def db(app):
    return _db


@pytest.fixture(scope='function')
def auth_headers(client):
    client.post('/auth/register', data={
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'testpass123',
        'confirm_password': 'testpass123',
    })
    client.post('/auth/login', data={
        'username': 'testuser',
        'password': 'testpass123',
    })
    return {}


@pytest.fixture(scope='function')
def sample_apache_log():
    return (
        '192.168.1.1 - - [10/Jul/2026:08:30:15 +0000] '
        '"GET /index.html HTTP/1.1" 200 1234 '
        '"http://referer.com" "Mozilla/5.0 (Windows NT 10.0)"\n'
        '10.0.0.1 - - [10/Jul/2026:08:31:00 +0000] '
        '"POST /login HTTP/1.1" 401 567 '
        '"-" "curl/7.68.0"\n'
    )


@pytest.fixture(scope='function')
def sample_auth_log():
    return (
        'Jul 10 08:30:00 server sshd[1234]: Failed password for root '
        'from 10.0.0.99 port 22 ssh2\n'
    )


@pytest.fixture(scope='function')
def sample_malicious_json():
    import json
    return json.dumps([
        {
            'ip_address': '5.5.5.5',
            'method': 'GET',
            'url': '/page?id=1 UNION SELECT * FROM users',
            'status_code': 200,
            'user_agent': '<script>alert(1)</script>',
        }
    ])
