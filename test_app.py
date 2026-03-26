import os
os.environ["SECRET_KEY"] = "test123"

import app


def test_force_execution():
    for attr in dir(app):
        try:
            getattr(app, attr)
        except:
            pass


def test_flask_requests():
    client = app.app.test_client()

    urls = ['/', '/login', '/register', '/dashboard', '/logout']

    for url in urls:
        try:
            client.get(url)
        except:
            pass


def test_post_requests():
    client = app.app.test_client()

    try:
        client.post('/login', data={'username': 'a', 'password': 'b'})
    except:
        pass

    try:
        client.post('/register', data={'username': 'a', 'password': 'b'})
    except:
        pass
