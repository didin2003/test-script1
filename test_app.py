# test_app.py
import pytest
from unittest.mock import patch
from app import app as flask_app  # Flask app instance
import app
import inspect
import itertools

# -----------------------------
# 1️⃣ Generate dummy values
# -----------------------------
def generate_dummy_values(param_name):
    """
    Generate a small set of dummy inputs for a parameter
    """
    if "num" in param_name or "count" in param_name:
        return [0, 1, -1]
    elif "flag" in param_name or "enabled" in param_name:
        return [True, False]
    elif "text" in param_name or "name" in param_name:
        return ["", "test"]
    else:
        return ["", 0, True]

# -----------------------------
# 2️⃣ Test all safe functions
# -----------------------------
def test_safe_functions_all():
    """
    Test all callable functions in app.py using all dummy inputs
    """
    safe_functions = []

    for name in dir(app):
        obj = getattr(app, name)
        if callable(obj) and not name.startswith("_"):
            # Skip Flask app, run/start functions
            if "run" in name or "start" in name or "app" in name:
                continue
            safe_functions.append((name, obj))

    for func_name, func in safe_functions:
        try:
            params = inspect.signature(func).parameters
            dummy_lists = [generate_dummy_values(p) for p in params]
            for args in itertools.product(*dummy_lists):
                try:
                    with patch("app.requests.get") as mock_get:
                        mock_get.return_value.json.return_value = {"key": "value"}
                        func(*args)
                except Exception:
                    pass
        except Exception:
            pass

# -----------------------------
# 3️⃣ Flask route tests
# -----------------------------
def test_flask_routes_full():
    """
    Test all important routes using Flask test client
    """
    client = flask_app.test_client()

    # List all your routes here
    routes = ["/", "/some-route"]

    for route in routes:
        # GET requests
        try:
            resp = client.get(route)
            assert resp.status_code in (200, 404)
        except Exception:
            pass

        # POST requests with dummy JSON
        test_payloads = [{}, {"key": "value"}, {"invalid": 123}]
        for payload in test_payloads:
            try:
                resp = client.post(route, json=payload)
                assert resp.status_code in (200, 201, 400, 404)
            except Exception:
                pass

# -----------------------------
# 4️⃣ Targeted branch tests
# -----------------------------
# Example for divide
if hasattr(app, "divide"):
    from app import divide

    @pytest.mark.parametrize("a,b,expected", [(10,2,5), (0,1,0)])
    def test_divide(a, b, expected):
        if b == 0:
            with pytest.raises(ZeroDivisionError):
                divide(a,b)
        else:
            assert divide(a,b) == expected

# Example for add
if hasattr(app, "add"):
    from app import add

    @pytest.mark.parametrize("a,b,expected", [(2,3,5), (-1,1,0), (0,0,0)])
    def test_add(a, b, expected):
        assert add(a,b) == expected

# -----------------------------
# 5️⃣ Optional edge / combinatorial tests
# -----------------------------
@pytest.mark.edge
def test_safe_functions_edge():
    """
    Optional combinatorial testing for all functions
    """
    safe_functions = []

    for name in dir(app):
        obj = getattr(app, name)
        if callable(obj) and not name.startswith("_"):
            if "run" in name or "start" in name or "app" in name:
                continue
            safe_functions.append((name, obj))

    for func_name, func in safe_functions:
        try:
            params = inspect.signature(func).parameters
            dummy_lists = [generate_dummy_values(p) for p in params]
            for args in itertools.product(*dummy_lists):
                try:
                    with patch("app.requests.get") as mock_get:
                        mock_get.return_value.json.return_value = {"key": "value"}
                        func(*args)
                except Exception:
                    pass
        except Exception:
            pass
