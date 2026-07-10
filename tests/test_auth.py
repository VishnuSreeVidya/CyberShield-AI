import io
import json


class TestAuthRoutes:
    def test_register_page(self, client):
        rv = client.get('/auth/register')
        assert rv.status_code == 200

    def test_register_user(self, client):
        rv = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'password123',
            'confirm_password': 'password123',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert b'Account created' in rv.data

    def test_register_duplicate_username(self, client):
        client.post('/auth/register', data={
            'username': 'dupuser', 'email': 'dup1@test.com',
            'password': 'pass123', 'confirm_password': 'pass123',
        })
        rv = client.post('/auth/register', data={
            'username': 'dupuser', 'email': 'dup2@test.com',
            'password': 'pass123', 'confirm_password': 'pass123',
        }, follow_redirects=True)
        assert b'Username already taken' in rv.data

    def test_login_page(self, client):
        rv = client.get('/auth/login')
        assert rv.status_code == 200

    def test_login_success(self, client):
        client.post('/auth/register', data={
            'username': 'logintest', 'email': 'login@test.com',
            'password': 'pass123', 'confirm_password': 'pass123',
        })
        rv = client.post('/auth/login', data={
            'username': 'logintest', 'password': 'pass123',
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert b'Welcome back' in rv.data

    def test_login_invalid(self, client):
        rv = client.post('/auth/login', data={
            'username': 'nobody', 'password': 'wrong',
        }, follow_redirects=True)
        assert b'Invalid username or password' in rv.data

    def test_logout(self, client):
        client.post('/auth/register', data={
            'username': 'logoutuser', 'email': 'logout@test.com',
            'password': 'pass123', 'confirm_password': 'pass123',
        })
        client.post('/auth/login', data={
            'username': 'logoutuser', 'password': 'pass123',
        })
        rv = client.get('/auth/logout', follow_redirects=True)
        assert b'logged out' in rv.data

    def test_protected_route_redirect(self, client):
        rv = client.get('/dashboard/', follow_redirects=False)
        assert rv.status_code == 302

    def test_protected_route_authenticated(self, client, auth_headers):
        rv = client.get('/dashboard/', follow_redirects=True)
        assert rv.status_code == 200
        assert b'Dashboard' in rv.data

    def test_authenticated_user_redirected_from_login(self, client):
        client.post('/auth/register', data={
            'username': 'alreadyin', 'email': 'in@test.com',
            'password': 'pass123', 'confirm_password': 'pass123',
        })
        client.post('/auth/login', data={
            'username': 'alreadyin', 'password': 'pass123',
        })
        rv = client.get('/auth/login', follow_redirects=True)
        assert b'Dashboard' in rv.data or b'Welcome back' in rv.data

    def test_register_password_mismatch(self, client):
        rv = client.post('/auth/register', data={
            'username': 'mismatch', 'email': 'mismatch@test.com',
            'password': 'abc123', 'confirm_password': 'xyz789',
        }, follow_redirects=True)
        assert b'Passwords must match' in rv.data
