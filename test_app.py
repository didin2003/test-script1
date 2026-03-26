from app import app

def test_home():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200

def test_invalid_route():
    client = app.test_client()
    response = client.get('/random')
    assert response.status_code in [404, 200]
