import pytest
import io
from app.models import AnalysisHistory, URLAnalysis, TextAnalysis, PDFAnalysis, IPAnalysis, HashAnalysis


class TestAnalysisRoutes:
    def test_choose_analysis_requires_auth(self, client):
        rv = client.get('/analysis/', follow_redirects=False)
        assert rv.status_code == 302
        assert '/auth/login' in rv.location

    def test_choose_analysis_authenticated(self, client, auth_headers):
        rv = client.get('/analysis/')
        assert rv.status_code == 200
        assert b'URL' in rv.data or b'Choose' in rv.data or b'Analysis' in rv.data

    def test_url_analysis_get(self, client, auth_headers):
        rv = client.get('/analysis/url')
        assert rv.status_code == 200

    def test_url_analysis_post_empty(self, client, auth_headers):
        rv = client.post('/analysis/url', data={'url': ''})
        assert rv.status_code == 200
        assert b'Please enter a URL' in rv.data

    def test_url_analysis_post_success(self, client, auth_headers):
        rv = client.post('/analysis/url', data={'url': 'http://192.168.1.1/login'})
        assert rv.status_code == 200
        assert b'URL analysis complete' in rv.data
        assert URLAnalysis.query.count() == 1

    def test_text_analysis_get(self, client, auth_headers):
        rv = client.get('/analysis/text')
        assert rv.status_code == 200

    def test_text_analysis_post_empty(self, client, auth_headers):
        rv = client.post('/analysis/text', data={'text': ''})
        assert rv.status_code == 200
        assert b'Please enter text' in rv.data

    def test_text_analysis_post_success(self, client, auth_headers):
        rv = client.post('/analysis/text', data={'text': 'Urgent verify your account at http://fake.com'})
        assert rv.status_code == 200
        assert b'Text analysis complete' in rv.data
        assert TextAnalysis.query.count() == 1

    def test_pdf_analysis_get(self, client, auth_headers):
        rv = client.get('/analysis/pdf')
        assert rv.status_code == 200

    def test_pdf_analysis_post_no_file(self, client, auth_headers):
        rv = client.post('/analysis/pdf', data={})
        assert rv.status_code == 200
        assert b'Please select a PDF file' in rv.data

    def test_pdf_analysis_post_invalid_extension(self, client, auth_headers):
        data = {'file': (io.BytesIO(b'not a pdf'), 'document.txt')}
        rv = client.post('/analysis/pdf', data=data, content_type='multipart/form-data')
        assert rv.status_code == 200
        assert b'Only PDF files are supported' in rv.data

    def test_pdf_analysis_post_success(self, client, auth_headers):
        pdf_bytes = b"%PDF-1.4\n/Title (Sample PDF)\n/Author (Analyst)\n"
        data = {'file': (io.BytesIO(pdf_bytes), 'sample.pdf')}
        rv = client.post('/analysis/pdf', data=data, content_type='multipart/form-data')
        assert rv.status_code == 200
        assert b'PDF analysis complete' in rv.data
        assert PDFAnalysis.query.count() == 1

    def test_ip_analysis_get(self, client, auth_headers):
        rv = client.get('/analysis/ip')
        assert rv.status_code == 200

    def test_ip_analysis_post_empty(self, client, auth_headers):
        rv = client.post('/analysis/ip', data={'ip': ''})
        assert rv.status_code == 200
        assert b'Please enter an IP address' in rv.data

    def test_ip_analysis_post_success(self, client, auth_headers):
        rv = client.post('/analysis/ip', data={'ip': '8.8.8.8'})
        assert rv.status_code == 200
        assert b'IP analysis complete' in rv.data
        assert IPAnalysis.query.count() == 1

    def test_hash_analysis_get(self, client, auth_headers):
        rv = client.get('/analysis/hash')
        assert rv.status_code == 200

    def test_hash_analysis_post_empty(self, client, auth_headers):
        rv = client.post('/analysis/hash', data={'hash': ''})
        assert rv.status_code == 200
        assert b'Please enter a file hash' in rv.data

    def test_hash_analysis_post_success(self, client, auth_headers):
        rv = client.post('/analysis/hash', data={'hash': 'e99a18c428cb38d5f260853678922e03'})
        assert rv.status_code == 200
        assert b'Hash analysis complete' in rv.data
        assert HashAnalysis.query.count() == 1

    def test_history_list_and_filter(self, client, auth_headers):
        client.post('/analysis/ip', data={'ip': '1.1.1.1'})
        client.post('/analysis/hash', data={'hash': 'e99a18c428cb38d5f260853678922e03'})

        rv = client.get('/analysis/history')
        assert rv.status_code == 200

        rv_filtered = client.get('/analysis/history?type=IP&threat=Low')
        assert rv_filtered.status_code == 200

    def test_history_detail_view_and_delete(self, client, auth_headers):
        client.post('/analysis/ip', data={'ip': '1.1.1.1'})
        history_item = AnalysisHistory.query.first()
        assert history_item is not None

        rv_detail = client.get(f'/analysis/history/{history_item.id}')
        assert rv_detail.status_code == 200

        rv_delete = client.post(f'/analysis/history/{history_item.id}/delete', follow_redirects=True)
        assert rv_delete.status_code == 200
        assert b'Analysis deleted' in rv_delete.data
        assert AnalysisHistory.query.get(history_item.id) is None
