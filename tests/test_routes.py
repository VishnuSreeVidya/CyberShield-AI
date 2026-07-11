import io


class TestDashboardRoutes:
    def test_dashboard_requires_auth(self, client):
        rv = client.get('/dashboard/', follow_redirects=False)
        assert rv.status_code == 302

    def test_dashboard_authenticated(self, client, auth_headers):
        rv = client.get('/dashboard/', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Dashboard' in rv.data

    def test_dashboard_shows_stats(self, client, auth_headers):
        rv = client.get('/dashboard/', follow_redirects=True)
        assert b'Total Logs' in rv.data
        assert b'Alerts' in rv.data


class TestLogsRoutes:
    def test_logs_list_requires_auth(self, client):
        rv = client.get('/logs/', follow_redirects=False)
        assert rv.status_code == 302

    def test_logs_list_empty(self, client, auth_headers):
        rv = client.get('/logs/', follow_redirects=True)
        assert rv.status_code == 200

    def test_logs_upload_page(self, client, auth_headers):
        rv = client.get('/logs/upload', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Upload' in rv.data

    def test_logs_upload_file(self, client, auth_headers):
        data = {
            'file': (io.BytesIO(
                b'192.168.1.1 - - [10/Jul/2026:08:30:15 +0000] '
                b'"GET /index.html HTTP/1.1" 200 1234 '
                b'"-" "Mozilla/5.0"\n'
            ), 'test.log'),
        }
        rv = client.post('/logs/upload', data=data,
                         content_type='multipart/form-data', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Processed' in rv.data

    def test_logs_upload_no_file(self, client, auth_headers):
        rv = client.post('/logs/upload', data={},
                         content_type='multipart/form-data', follow_redirects=True)
        assert b'No file selected' in rv.data

    def test_logs_upload_invalid_extension(self, client, auth_headers):
        data = {'file': (io.BytesIO(b'data'), 'test.exe')}
        rv = client.post('/logs/upload', data=data,
                         content_type='multipart/form-data', follow_redirects=True)
        assert b'Unsupported file type' in rv.data

    def test_logs_detail(self, client, auth_headers):
        data = {'file': (io.BytesIO(
            b'192.168.1.1 - - [10/Jul/2026:08:30:15 +0000] '
            b'"GET /index.html HTTP/1.1" 200 1234 '
            b'"-" "Mozilla/5.0"\n'
        ), 'test.log')}
        client.post('/logs/upload', data=data,
                    content_type='multipart/form-data', follow_redirects=True)

        rv = client.get('/logs/1')
        assert rv.status_code == 200
        assert b'Log Entry' in rv.data

    def test_logs_detail_not_found(self, client, auth_headers):
        rv = client.get('/logs/999')
        assert rv.status_code == 404

    def test_logs_delete(self, client, auth_headers):
        data = {'file': (io.BytesIO(
            b'192.168.1.1 - - [10/Jul/2026:08:30:15 +0000] '
            b'"GET /index.html HTTP/1.1" 200 1234 '
            b'"-" "Mozilla/5.0"\n'
        ), 'test.log')}
        client.post('/logs/upload', data=data,
                    content_type='multipart/form-data', follow_redirects=True)
        rv = client.post('/logs/1/delete', follow_redirects=True)
        assert rv.status_code == 200


class TestAPIRoutes:
    def test_stats_requires_auth(self, client):
        rv = client.get('/api/dashboard/stats')
        assert rv.status_code in (302, 401)

    def test_stats_authenticated(self, client, auth_headers):
        rv = client.get('/api/dashboard/stats')
        assert rv.status_code == 200
        data = rv.get_json()
        assert 'total_logs' in data
        assert 'total_alerts' in data

    def test_alerts_by_type(self, client, auth_headers):
        rv = client.get('/api/dashboard/alerts_by_type')
        assert rv.status_code == 200
        assert isinstance(rv.get_json(), dict)

    def test_recent_alerts(self, client, auth_headers):
        rv = client.get('/api/dashboard/recent_alerts')
        assert rv.status_code == 200
        assert isinstance(rv.get_json(), list)

    def test_stats_after_upload(self, client, auth_headers):
        data = {'file': (io.BytesIO(b'test data\n'), 'test.txt')}
        client.post('/logs/upload', data=data,
                    content_type='multipart/form-data', follow_redirects=True)
        rv = client.get('/api/dashboard/stats')
        stats = rv.get_json()
        assert stats['total_logs'] >= 0

    def test_attack_timeline(self, client, auth_headers):
        rv = client.get('/api/dashboard/timeline')
        assert rv.status_code == 200
        data = rv.get_json()
        assert 'labels' in data
        assert 'data' in data
        assert len(data['labels']) == 24
        assert len(data['data']) == 24

    def test_top_ips(self, client, auth_headers):
        rv = client.get('/api/dashboard/top_ips')
        assert rv.status_code == 200
        data = rv.get_json()
        assert 'labels' in data
        assert 'data' in data
        assert isinstance(data['labels'], list)
        assert isinstance(data['data'], list)

    def test_timeline_requires_auth(self, client):
        rv = client.get('/api/dashboard/timeline')
        assert rv.status_code in (302, 401)

    def test_top_ips_requires_auth(self, client):
        rv = client.get('/api/dashboard/top_ips')
        assert rv.status_code in (302, 401)


class TestReportExports:
    def test_export_csv(self, client, auth_headers):
        rv = client.get('/dashboard/reports/export/csv')
        assert rv.status_code == 200
        assert rv.mimetype == 'text/csv'

    def test_export_json(self, client, auth_headers):
        rv = client.get('/dashboard/reports/export/json')
        assert rv.status_code == 200
        assert rv.mimetype == 'application/json'

    def test_export_pdf(self, client, auth_headers):
        rv = client.get('/dashboard/reports/export/pdf')
        assert rv.status_code == 200
        assert rv.mimetype == 'application/pdf'
        assert b'%PDF' in rv.data

    def test_reports_page(self, client, auth_headers):
        rv = client.get('/dashboard/reports', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Reports' in rv.data

    def test_settings_page(self, client, auth_headers):
        rv = client.get('/dashboard/settings', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Settings' in rv.data


class TestMainRoutes:
    def test_health_endpoint(self, client):
        rv = client.get('/health')
        assert rv.status_code == 200
        assert rv.get_json()['status'] == 'ok'

    def test_index_page(self, client):
        rv = client.get('/', follow_redirects=True)
        assert rv.status_code == 200
        assert b'CyberShield AI' in rv.data
