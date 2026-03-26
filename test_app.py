from app import add, validate_user, app


def test_add():
    assert add(2, 3) == 5


def test_validate_user():
    assert validate_user("admin", "admin") == True
    assert validate_user("x", "y") == False


def test_home_route():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200


def test_add_route():
    client = app.test_client()
    response = client.get('/add?a=2&b=3')
    assert response.status_code == 200


def test_login():
    client = app.test_client()
    response = client.post('/login', data={
        "username": "admin",
        "password": "admin"
    })
    assert response.status_code == 200
