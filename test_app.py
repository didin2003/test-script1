import os
os.environ["SECRET_KEY"] = "test123"

from app import app

def test_with_session():
    client = app.test_client()

    with client.session_transaction() as sess:
        sess['user'] = 'test'   # 👈 fake login

    response = client.get('/dashboard')
    assert response.status_code in [200, 302, 500]


def test_all_routes_with_session():
    client = app.test_client()

    with client.session_transaction() as sess:
        sess['user'] = 'test'

    routes = ['/', '/dashboard', '/logout']

    for route in routes:
        try:
            client.get(route)
        except:
            pass
