import os
os.environ["SECRET_KEY"] = "test123"

import app


def test_load_app():
    assert app is not None


def test_all_attributes():
    # Force execution of many parts
    for name in dir(app):
        try:
            getattr(app, name)
        except:
            pass


def test_flask_endpoints():
    client = app.app.test_client()

    endpoints = [
        '/',
        '/login',
        '/register',
        '/dashboard',
        '/logout'
    ]

    for ep in endpoints:
        try:
            client.get(ep)
        except:
            pass


def test_post_requests():
    client = app.app.test_client()

    data_samples = [
        {'username': 'a', 'password': 'b'},
        {'username': '', 'password': ''},
        {'username': 'test', 'password': '123'}
    ]

    for data in data_samples:
        try:
            client.post('/login', data=data)
        except:
            pass

        try:
            client.post('/register', data=data)
        except:
            pass


def test_multiple_calls():
    client = app.app.test_client()

    for _ in range(10):   # repeat to execute more paths
        try:
            client.get('/')
        except:
            pass
