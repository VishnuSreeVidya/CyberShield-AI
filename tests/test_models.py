import pytest
from app.models import User, LogEntry, Alert, Report
from datetime import datetime, timezone


class TestUserModel:
    def test_create_user(self, db):
        user = User(username='alice', email='alice@test.com', role='analyst')
        user.set_password('secret')
        db.session.add(user)
        db.session.commit()
        assert user.id is not None
        assert user.username == 'alice'

    def test_password_hashing(self, db):
        user = User(username='bob', email='bob@test.com')
        user.set_password('mypassword')
        db.session.add(user)
        db.session.commit()
        assert user.check_password('mypassword') is True
        assert user.check_password('wrong') is False

    def test_user_repr(self, db):
        user = User(username='charlie', email='charlie@test.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
        assert 'charlie' in repr(user)

    def test_unique_username(self, db):
        u1 = User(username='dup', email='dup1@test.com')
        u1.set_password('testpass')
        u2 = User(username='dup', email='dup2@test.com')
        u2.set_password('testpass')
        db.session.add(u1)
        db.session.commit()
        db.session.add(u2)
        with pytest.raises(Exception):
            db.session.commit()
        db.session.rollback()

    def test_default_role(self, db):
        user = User(username='default', email='default@test.com')
        user.set_password('testpass')
        db.session.add(user)
        db.session.commit()
        assert user.role == 'analyst'


class TestLogEntryModel:
    def test_create_log_entry(self, db):
        entry = LogEntry(
            ip_address='10.0.0.1',
            http_method='GET',
            request_url='/test',
            status_code=200,
            raw_log='GET /test HTTP/1.1 200',
        )
        db.session.add(entry)
        db.session.commit()
        assert entry.id is not None
        assert entry.ip_address == '10.0.0.1'

    def test_log_entry_repr(self, db):
        entry = LogEntry(ip_address='1.2.3.4', raw_log='test')
        db.session.add(entry)
        db.session.commit()
        assert '1.2.3.4' in repr(entry)

    def test_alert_relationship(self, db):
        entry = LogEntry(raw_log='test log')
        db.session.add(entry)
        db.session.flush()
        alert = Alert(log_id=entry.id, attack_type='SQL Injection', severity='Critical')
        db.session.add(alert)
        db.session.commit()
        assert len(entry.alerts.all()) == 1
        assert entry.alerts.first().attack_type == 'SQL Injection'

    def test_cascade_delete(self, db):
        entry = LogEntry(raw_log='cascade test')
        db.session.add(entry)
        db.session.flush()
        db.session.add(Alert(log_id=entry.id, attack_type='XSS', severity='High'))
        db.session.commit()
        assert Alert.query.count() == 1
        db.session.delete(entry)
        db.session.commit()
        assert Alert.query.count() == 0


class TestAlertModel:
    def test_create_alert(self, db):
        entry = LogEntry(raw_log='alert test')
        db.session.add(entry)
        db.session.flush()
        alert = Alert(
            log_id=entry.id,
            attack_type='Brute Force',
            severity='High',
            description='10 failed logins from 10.0.0.1',
        )
        db.session.add(alert)
        db.session.commit()
        assert alert.id is not None
        assert alert.attack_type == 'Brute Force'
        assert alert.severity == 'High'

    def test_alert_repr(self, db):
        entry = LogEntry(raw_log='repr test')
        db.session.add(entry)
        db.session.flush()
        alert = Alert(log_id=entry.id, attack_type='DoS', severity='Critical')
        db.session.add(alert)
        db.session.commit()
        assert 'DoS' in repr(alert)
        assert 'Critical' in repr(alert)


class TestReportModel:
    def test_create_report(self, db):
        report = Report(report_name='Daily Summary', report_type='pdf')
        db.session.add(report)
        db.session.commit()
        assert report.id is not None
        assert report.report_name == 'Daily Summary'

    def test_report_repr(self, db):
        report = Report(report_name='Weekly', report_type='csv')
        db.session.add(report)
        db.session.commit()
        assert 'Weekly' in repr(report)
