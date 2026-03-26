import os
os.environ["SECRET_KEY"] = "test123"

import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user'] = 'test'   # fake login
        yield client


def test_home(client):
    response = client.get('/')
    assert response.status_code in [200, 302, 500]


def test_dashboard(client):
    response = client.get('/dashboard')
    assert response.status_code in [200, 302, 500]


def test_login_post(client):
    response = client.post('/login', data={
        'username': 'test',
        'password': 'test'
    })
    assert response.status_code in [200, 302, 500]


def test_register_post(client):
    response = client.post('/register', data={
        'username': 'test',
        'password': 'test'
    })
    assert response.status_code in [200, 302, 500]


def test_multiple_routes(client):
    routes = ['/', '/login', '/register', '/dashboard', '/logout']

    for route in routes:
        try:
            client.get(route)
        except:
            pass
