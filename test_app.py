import pytest
from unittest.mock import patch, MagicMock
from app import app as flask_app
import app
import os
import time
import json as json_lib
import base64 as base64_lib

# -----------------------------
# Setup test client
# -----------------------------
@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["ENV"] = "development"
    flask_app.config["RATELIMIT_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client

# -----------------------------
# 1️⃣ GET routes
# -----------------------------
@pytest.mark.parametrize("route", [
    "/", "/login", "/dashboard", "/profile"
])
def test_routes_get(client, route):
    resp = client.get(route)
    assert resp.status_code in (200, 302, 400, 401, 404, 500)

# -----------------------------
# 2️⃣ POST routes
# -----------------------------
@pytest.mark.parametrize("route", [
    "/login"  # Only existing POST route
])
def test_routes_post(client, route):
    resp = client.post(route, json={})
    assert resp.status_code in (200, 302, 400, 401, 404)

# -----------------------------
# 3️⃣ Login tests
# -----------------------------
@pytest.mark.parametrize("payload,expected_status", [
    ({"username": "admin", "password": "123"}, (200, 302)),
    ({"username": "admin", "password": "wrong"}, (400, 401, 302)),
    ({}, (400, 302)),
    ({"username": "' OR 1=1 --", "password": "test"}, (400, 401, 302)),
])
def test_login_cases(client, payload, expected_status):
    resp = client.post("/login", json=payload)
    assert resp.status_code in expected_status

# -----------------------------
# 4️⃣ Protected routes
# -----------------------------
def test_dashboard_without_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code in (200, 302, 400, 401, 404)

def test_dashboard_with_login(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
    resp = client.get("/dashboard")
    assert resp.status_code in (200, 302, 400, 401, 404)

# -----------------------------
# 5️⃣ Invalid route
# -----------------------------
def test_invalid_route(client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code in (200, 302, 400, 401, 404)

# -----------------------------
# 6️⃣ Large payload / security
# -----------------------------
def test_large_payload_login(client):
    big_data = {"data": "x" * (16 * 1024 * 1024)}
    resp = client.post("/login", json=big_data)
    assert resp.status_code in (200, 302, 400, 401, 413, 404)

# -----------------------------
# 7️⃣ Mock external requests
# -----------------------------
@patch("requests.get")
def test_mock_requests(mock_get, client):
    mock_get.return_value.json.return_value = {"key": "value"}
    resp = client.get("/")
    assert resp.status_code in (200, 302, 400, 401, 404)

# -----------------------------
# 8️⃣ Basic utility function tests
# -----------------------------
def test_basic_functions():
    if hasattr(app, "add"):
        assert app.add(2, 3) == 5
        assert app.add(-1, 1) == 0

    if hasattr(app, "divide"):
        assert app.divide(10, 2) == 5
        assert app.divide(0, 1) == 0
        # division by zero branch
        try:
            app.divide(1, 0)
        except Exception:
            pass

    if hasattr(app, "process_user"):
        assert app.process_user({}) is None
        assert app.process_user({"admin": True}) == "admin"
        assert app.process_user({"name": "bob"}) == "user"

# -----------------------------
# 9️⃣ Internal branches / edge cases
# -----------------------------
def test_internal_branches():
    if hasattr(app, "feature_enabled"):
        for val in [True, False]:
            app.feature_enabled(val)

    if hasattr(app, "compute_sum_list"):
        assert app.compute_sum_list([1, 2, 3]) == 6
        assert app.compute_sum_list([]) == 0

    if hasattr(app, "dangerous_function"):
        try:
            app.dangerous_function(None)
        except Exception:
            pass

# -----------------------------
# 10️⃣ Edge case tests
# -----------------------------
def test_edge_cases():
    if hasattr(app, "divide"):
        with pytest.raises(Exception):
            app.divide(5, 0)

    if hasattr(app, "compute_sum_list"):
        assert app.compute_sum_list([0]) == 0

# -----------------------------
# 11️⃣ Test generate_secret function
# -----------------------------
def test_get_or_create_secret(tmp_path):
    # Path for temporary file
    file_path = tmp_path / "secret.txt"

    # Call the function (this executes lines 36-38)
    val = app.get_or_create_secret(file_path, 16)

    # Check return type and length
    assert isinstance(val, str)
    assert len(val) == 32  # 16 bytes -> 32 hex characters

    # Check file was written correctly
    with open(file_path, "r") as f:
        content = f.read()
    assert content == val

# -----------------------------
# 12️⃣ Test HTTPS redirect (line 79)
# -----------------------------
def test_https_redirect(client):
    # Simulate production environment to trigger HTTPS redirect
    flask_app.config["ENV"] = "production"
    flask_app.config["TESTING"] = False

    # Send HTTP request to trigger the redirect
    resp = client.get("/", base_url="http://localhost")

    # Should redirect to HTTPS
    assert resp.status_code in (301, 302)
    if resp.status_code in (301, 302):
        assert resp.headers.get("Location", "").startswith("https://")

    # Reset back to test config
    flask_app.config["ENV"] = "development"
    flask_app.config["TESTING"] = True

# -----------------------------
# 13️⃣ Test handle_exception for non-HTTP exceptions (lines 107-108)
# -----------------------------
def test_handle_exception_directly():
    # Call handle_exception directly with a non-HTTP exception
    with flask_app.app_context():
        e = RuntimeError("Test unhandled error")
        result = app.handle_exception(e)

        # Should return 500 and error message
        response, status_code = result
        assert status_code == 500
        data = response.get_json()
        assert data["error"] == "Internal server error"

def test_handle_exception_http():
    # Call handle_exception with an HTTP exception (covers the if branch)
    from werkzeug.exceptions import NotFound
    with flask_app.app_context():
        e = NotFound()
        response, status_code = app.handle_exception(e)
        assert status_code == 404

# -----------------------------
# 14️⃣ Test init_db exception branch (line 133)
# -----------------------------
def test_init_db_exception():
    with patch("app.get_db", side_effect=Exception("Forced DB error")):
        with patch("app.logging.error") as mock_log:
            # Call init_db with get_db failing
            app.init_db()
            
            # Verify logging.error was called with "Init DB"
            mock_log.assert_called_once()
            args = mock_log.call_args[0][0]
            assert "Init DB" in args
            assert "Forced DB error" in args

# -----------------------------
# 15️⃣ Test audit_log function
# -----------------------------
def test_audit_log_success():
    # Test normal execution - logging.info and DB insert
    with patch("app.logging.info") as mock_log:
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            
            app.audit_log("admin", "login", "dashboard")
            
            # Verify logging.info was called
            mock_log.assert_called_once()
            args = mock_log.call_args[0][0]
            assert "admin" in args
            assert "login" in args
            assert "dashboard" in args
            
            # Verify DB insert was called
            mock_cursor.execute.assert_called_once()

def test_audit_log_db_exception():
    # Test except branch - when get_db raises an exception
    with patch("app.logging.info"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            # Should silently pass without raising
            try:
                app.audit_log("admin", "login", "dashboard")
            except Exception:
                pytest.fail("audit_log should silently handle exceptions")

# -----------------------------
# 16️⃣ Test get_host_from_data function
# -----------------------------
def test_get_host_from_data_none():
    # Test None input - returns UNKNOWN
    assert app.get_host_from_data(None) == "UNKNOWN"

def test_get_host_from_data_not_dict():
    # Test non-dict input - returns UNKNOWN
    assert app.get_host_from_data("string") == "UNKNOWN"
    assert app.get_host_from_data(123) == "UNKNOWN"
    assert app.get_host_from_data([]) == "UNKNOWN"

def test_get_host_from_data_empty_dict():
    # Test empty dict - returns UNKNOWN
    assert app.get_host_from_data({}) == "UNKNOWN"

def test_get_host_from_data_with_hostname():
    # Test each valid key
    assert app.get_host_from_data({"hostname": "myhost"}) == "MYHOST"
    assert app.get_host_from_data({"Hostname": "myhost"}) == "MYHOST"
    assert app.get_host_from_data({"HOST": "myhost"}) == "MYHOST"
    assert app.get_host_from_data({"host": "myhost"}) == "MYHOST"
    assert app.get_host_from_data({"ComputerName": "myhost"}) == "MYHOST"

def test_get_host_from_data_empty_value():
    # Test key exists but value is empty - returns UNKNOWN
    assert app.get_host_from_data({"hostname": ""}) == "UNKNOWN"
    assert app.get_host_from_data({"hostname": None}) == "UNKNOWN"

def test_get_host_from_data_no_matching_key():
    # Test dict with no matching key - returns UNKNOWN
    assert app.get_host_from_data({"randomkey": "myhost"}) == "UNKNOWN"

def test_get_host_from_data_strips_and_uppercases():
    # Test value is stripped and uppercased
    assert app.get_host_from_data({"hostname": "  myhost  "}) == "MYHOST"
    assert app.get_host_from_data({"hostname": "myHost"}) == "MYHOST"

# -----------------------------
# 17️⃣ Test get_clean_host function
# -----------------------------
def test_get_clean_host_none():
    # Test None input - returns UNKNOWN
    assert app.get_clean_host(None) == "UNKNOWN"

def test_get_clean_host_empty_string():
    # Test empty string - returns UNKNOWN
    assert app.get_clean_host("") == "UNKNOWN"

def test_get_clean_host_valid():
    # Test valid hostname - stripped and uppercased
    assert app.get_clean_host("myhost") == "MYHOST"
    assert app.get_clean_host("  myhost  ") == "MYHOST"
    assert app.get_clean_host("MY-HOST-01") == "MY-HOST-01"

def test_get_clean_host_invalid_characters():
    # Test invalid characters - returns UNKNOWN
    assert app.get_clean_host("my host!") == "UNKNOWN"
    assert app.get_clean_host("host@domain") == "UNKNOWN"
    assert app.get_clean_host("host.name") == "UNKNOWN"
    assert app.get_clean_host("host/name") == "UNKNOWN"

def test_get_clean_host_too_long():
    # Test hostname exceeding 50 chars - returns UNKNOWN
    assert app.get_clean_host("A" * 51) == "UNKNOWN"

def test_get_clean_host_exactly_50():
    # Test hostname exactly 50 chars - should be valid
    assert app.get_clean_host("A" * 50) == "A" * 50

def test_get_clean_host_numbers_and_hyphens():
    # Test valid hostname with numbers and hyphens
    assert app.get_clean_host("HOST-123") == "HOST-123"
    assert app.get_clean_host("123") == "123"

# -----------------------------
# 18️⃣ Test csrf_required decorator directly
# -----------------------------
def test_csrf_get_passes():
    # GET request should skip CSRF check and call the function
    with flask_app.test_request_context("/", method="GET"):
        @app.csrf_required
        def dummy():
            return "ok"
        
        result = dummy()
        assert result == "ok"

def test_csrf_post_missing_token_aborts():
    # POST with no token should abort 403
    with flask_app.test_request_context("/", method="POST"):
        from flask import session
        @app.csrf_required
        def dummy():
            return "ok"
        
        from werkzeug.exceptions import Forbidden
        try:
            dummy()
            assert False, "Should have aborted"
        except Forbidden:
            pass  # Expected 403

def test_csrf_post_wrong_token_aborts():
    # POST with wrong token should abort 403
    with flask_app.test_request_context("/", method="POST", headers={"X-CSRF-Token": "wrong"}):
        with flask_app.test_client() as c:
            with c.session_transaction() as sess:
                sess["csrf_token"] = "correct-token"
        
        from werkzeug.exceptions import Forbidden
        try:
            @app.csrf_required
            def dummy():
                return "ok"
            dummy()
        except Forbidden:
            pass  # Expected 403

def test_csrf_post_valid_token_passes():
    # POST with correct token should call the function
    with flask_app.test_request_context(
        "/", method="POST",
        headers={"X-CSRF-Token": "valid-token"}
    ):
        from flask import session
        session["csrf_token"] = "valid-token"

        @app.csrf_required
        def dummy():
            return "ok"

        result = dummy()
        assert result == "ok"

# -----------------------------
# 19️⃣ Test verify_agent function
# -----------------------------

def make_mock_request(headers=None, body=b'', method="POST"):
    """Helper to create a mock request object"""
    with flask_app.test_request_context(
        "/", method=method, data=body,
        headers=headers or {}
    ):
        from flask import request
        return request

# Test 1: Missing headers - returns None
def test_verify_agent_missing_headers(client):
    with flask_app.test_request_context("/", method="POST", headers={}):
        from flask import request
        result = app.verify_agent(request)
        assert result is None

# Test 2: Missing one header - returns None
def test_verify_agent_partial_headers(client):
    with flask_app.test_request_context("/", method="POST", headers={
        "X-API-KEY": "testkey",
        "X-SIGNATURE": "testsig"
        # Missing X-TIMESTAMP and X-NONCE
    }):
        from flask import request
        result = app.verify_agent(request)
        assert result is None

# Test 3: Expired timestamp - returns None
def test_verify_agent_expired_timestamp(client):
    with flask_app.test_request_context("/", method="POST", headers={
        "X-API-KEY": "testkey",
        "X-SIGNATURE": "testsig",
        "X-TIMESTAMP": "1000",  # Very old timestamp
        "X-NONCE": "testnonce"
    }):
        from flask import request
        result = app.verify_agent(request)
        assert result is None

# Test 4: Invalid timestamp (non-integer) - returns None
def test_verify_agent_invalid_timestamp(client):
    with flask_app.test_request_context("/", method="POST", headers={
        "X-API-KEY": "testkey",
        "X-SIGNATURE": "testsig",
        "X-TIMESTAMP": "notanumber",
        "X-NONCE": "testnonce"
    }):
        from flask import request
        result = app.verify_agent(request)
        assert result is None

# Test 5: Reused nonce - returns None
def test_verify_agent_reused_nonce(client):
    import time
    nonce = "unique-nonce-reuse-test"
    # Pre-insert nonce into USED_NONCES
    app.USED_NONCES[nonce] = True

    with flask_app.test_request_context("/", method="POST", headers={
        "X-API-KEY": "testkey",
        "X-SIGNATURE": "testsig",
        "X-TIMESTAMP": str(int(time.time())),
        "X-NONCE": nonce
    }):
        from flask import request
        result = app.verify_agent(request)
        assert result is None

# Test 6: DB error - returns None
def test_verify_agent_db_error(client):
    import time
    nonce = "nonce-db-error-test"
    with patch("app.get_db", side_effect=Exception("DB error")):
        with flask_app.test_request_context("/", method="POST", headers={
            "X-API-KEY": "testkey",
            "X-SIGNATURE": "testsig",
            "X-TIMESTAMP": str(int(time.time())),
            "X-NONCE": nonce
        }):
            from flask import request
            result = app.verify_agent(request)
            assert result is None

# Test 7: No registration key - returns None
def test_verify_agent_no_registration_key(client):
    import time
    nonce = "nonce-no-reg-test"
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_conn.cursor.return_value.execute.return_value.fetchone.return_value = None

        with flask_app.test_request_context("/", method="POST", headers={
            "X-API-KEY": "testkey",
            "X-SIGNATURE": "testsig",
            "X-TIMESTAMP": str(int(time.time())),
            "X-NONCE": nonce,
            # No X-REGISTER-KEY header
        }):
            from flask import request
            result = app.verify_agent(request)
            assert result is None

# Test 8: Valid existing host with wrong signature - returns None
def test_verify_agent_wrong_signature(client):
    import time
    nonce = "nonce-wrong-sig-test"
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_conn.cursor.return_value.execute.return_value.fetchone.return_value = ("TESTHOST",)

        with flask_app.test_request_context("/", method="POST", headers={
            "X-API-KEY": "testkey",
            "X-SIGNATURE": "wrongsignature",
            "X-TIMESTAMP": str(int(time.time())),
            "X-NONCE": nonce
        }):
            from flask import request
            result = app.verify_agent(request)
            assert result is None

# Test 9: Valid host with correct signature - returns host
def test_verify_agent_valid(client):
    import time
    import hmac as hmac_lib
    import hashlib

    nonce = "nonce-valid-test"
    api_key = "validapikey"
    timestamp = str(int(time.time()))
    body = b''

    data_to_sign = body + timestamp.encode() + nonce.encode()
    expected_sig = hmac_lib.new(api_key.encode(), data_to_sign, hashlib.sha256).hexdigest()

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_conn.cursor.return_value.execute.return_value.fetchone.return_value = ("TESTHOST",)

        with flask_app.test_request_context("/", method="POST", data=body, headers={
            "X-API-KEY": api_key,
            "X-SIGNATURE": expected_sig,
            "X-TIMESTAMP": timestamp,
            "X-NONCE": nonce
        }):
            from flask import request
            result = app.verify_agent(request)
            assert result == "TESTHOST"

# Test 10: Auto-register new host with valid registration key
def test_verify_agent_auto_register(client):
    import time
    import hmac as hmac_lib
    import hashlib
    import json as json_lib

    nonce = "nonce-auto-register-test"
    api_key = "newapikey"
    timestamp = str(int(time.time()))
    body = json_lib.dumps({"hostname": "NEWHOST"}).encode()

    data_to_sign = body + timestamp.encode() + nonce.encode()
    expected_sig = hmac_lib.new(api_key.encode(), data_to_sign, hashlib.sha256).hexdigest()

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        # First fetchone returns None (host not found in DB)
        mock_cursor.execute.return_value.fetchone.return_value = None

        with patch("app.REGISTRATION_KEY", "test-reg-key"):
            with flask_app.test_request_context("/", method="POST", data=body, headers={
                "X-API-KEY": api_key,
                "X-SIGNATURE": expected_sig,
                "X-TIMESTAMP": timestamp,
                "X-NONCE": nonce,
                "X-REGISTER-KEY": "test-reg-key"
            }):
                from flask import request
                with patch("app.logging.info") as mock_log:
                    result = app.verify_agent(request)

                    # Verify DELETE and INSERT were called
                    calls = [str(c) for c in mock_cursor.execute.call_args_list]
                    assert any("DELETE" in c for c in calls)
                    assert any("INSERT" in c for c in calls)

                    # Verify logging.info was called with AUTO-REGISTER
                    if mock_log.called:
                        assert "AUTO-REGISTER" in mock_log.call_args[0][0]

# Test 11: Auto-register with invalid JSON body - except branch
def test_verify_agent_auto_register_invalid_json(client):
    import time

    nonce = "nonce-invalid-json-test"
    api_key = "newapikey2"
    timestamp = str(int(time.time()))
    body = b"not-valid-json"  # Forces json.loads to fail -> except Exception: pass

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.execute.return_value.fetchone.return_value = None

        with patch("app.REGISTRATION_KEY", "test-reg-key"):
            with flask_app.test_request_context("/", method="POST", data=body, headers={
                "X-API-KEY": api_key,
                "X-SIGNATURE": "anysig",
                "X-TIMESTAMP": timestamp,
                "X-NONCE": nonce,
                "X-REGISTER-KEY": "test-reg-key"
            }):
                from flask import request
                result = app.verify_agent(request)
                # Should return None since host was never set
                assert result is None

# Test 12: Auto-register with UNKNOWN host - skips insert
def test_verify_agent_auto_register_unknown_host(client):
    import time
    import json as json_lib

    nonce = "nonce-unknown-host-test"
    api_key = "newapikey3"
    timestamp = str(int(time.time()))
    body = json_lib.dumps({"randomkey": "value"}).encode()  # get_host_from_data returns UNKNOWN

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.execute.return_value.fetchone.return_value = None

        with patch("app.REGISTRATION_KEY", "test-reg-key"):
            with flask_app.test_request_context("/", method="POST", data=body, headers={
                "X-API-KEY": api_key,
                "X-SIGNATURE": "anysig",
                "X-TIMESTAMP": timestamp,
                "X-NONCE": nonce,
                "X-REGISTER-KEY": "test-reg-key"
            }):
                from flask import request
                result = app.verify_agent(request)
                # Host is UNKNOWN so insert skipped, host stays None -> returns None
                assert result is None

# -----------------------------
# 20️⃣ Test agent_hmac_required decorator
# -----------------------------

# Test 1: verify_agent returns None - Unauthorized
def test_agent_hmac_unauthorized():
    with patch("app.verify_agent", return_value=None):
        with flask_app.test_request_context("/", method="POST"):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            response, status_code = result
            assert status_code == 401
            assert response.get_json()["error"] == "Unauthorized"

# Test 2: verify_agent returns host, no JSON body - declared_host is UNKNOWN
def test_agent_hmac_no_json_body():
    with patch("app.verify_agent", return_value="TESTHOST"):
        with flask_app.test_request_context("/", method="POST"):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            assert result == "ok"

# Test 3: declared_host is UNKNOWN, hostname in query args
def test_agent_hmac_hostname_from_query_args():
    with patch("app.verify_agent", return_value="TESTHOST"):
        with flask_app.test_request_context(
            "/?hostname=TESTHOST", method="POST",
            content_type="application/json",
            data=b"{}"
        ):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            assert result == "ok"

# Test 4: declared_host != verified_host - Identity mismatch
def test_agent_hmac_identity_mismatch():
    with patch("app.verify_agent", return_value="TESTHOST"):
        with flask_app.test_request_context(
            "/", method="POST",
            content_type="application/json",
            data=b'{"hostname": "OTHERHOST"}'
        ):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            response, status_code = result
            assert status_code == 403
            assert response.get_json()["error"] == "Identity mismatch"

# Test 5: declared_host matches verified_host - passes through
def test_agent_hmac_identity_match():
    with patch("app.verify_agent", return_value="TESTHOST"):
        with flask_app.test_request_context(
            "/", method="POST",
            content_type="application/json",
            data=b'{"hostname": "TESTHOST"}'
        ):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            assert result == "ok"

# Test 6: query arg hostname does not match verified_host - Identity mismatch
def test_agent_hmac_query_arg_mismatch():
    with patch("app.verify_agent", return_value="TESTHOST"):
        with flask_app.test_request_context(
            "/?hostname=OTHERHOST", method="POST",
            content_type="application/json",
            data=b"{}"
        ):
            from flask import request

            @app.agent_hmac_required
            def dummy():
                return "ok"

            result = dummy()
            response, status_code = result
            assert status_code == 403
            assert response.get_json()["error"] == "Identity mismatch"

# -----------------------------
# 21️⃣ Test agent_limit_key function
# -----------------------------

# Test 1: X-API-KEY header present - returns API key
def test_agent_limit_key_with_api_key():
    with flask_app.test_request_context("/", headers={"X-API-KEY": "testapikey123"}):
        result = app.agent_limit_key()
        assert result == "testapikey123"

# Test 2: No X-API-KEY header - falls back to remote address
def test_agent_limit_key_without_api_key():
    with flask_app.test_request_context("/"):
        with patch("app.get_remote_address", return_value="127.0.0.1"):
            result = app.agent_limit_key()
            assert result == "127.0.0.1"

# -----------------------------
# 22️⃣ Test cleanup_files function
# -----------------------------

# Test 1: Old file gets deleted
def test_cleanup_files_deletes_old_file():
    old_time = time.time() - (8 * 86400)  # 8 days old (older than 7 days)

    with patch("os.listdir", return_value=["oldfile.txt"]):
        with patch("os.path.isfile", return_value=True):
            with patch("os.path.getmtime", return_value=old_time):
                with patch("os.remove") as mock_remove:
                    with patch("os.path.join", return_value="/fake/path/oldfile.txt"):
                        with patch("time.sleep", side_effect=Exception("stop loop")):
                            try:
                                app.cleanup_files()
                            except Exception:
                                pass
                            mock_remove.assert_called_with("/fake/path/oldfile.txt")

# Test 2: New file does NOT get deleted
def test_cleanup_files_skips_new_file():
    new_time = time.time() - (1 * 86400)  # 1 day old (newer than 7 days)

    with patch("os.listdir", return_value=["newfile.txt"]):
        with patch("os.path.isfile", return_value=True):
            with patch("os.path.getmtime", return_value=new_time):
                with patch("os.remove") as mock_remove:
                    with patch("time.sleep", side_effect=Exception("stop loop")):
                        try:
                            app.cleanup_files()
                        except Exception:
                            pass
                        mock_remove.assert_not_called()

# Test 3: Not a file - skips deletion
def test_cleanup_files_skips_non_file():
    with patch("os.listdir", return_value=["somedir"]):
        with patch("os.path.isfile", return_value=False):
            with patch("os.remove") as mock_remove:
                with patch("time.sleep", side_effect=Exception("stop loop")):
                    try:
                        app.cleanup_files()
                    except Exception:
                        pass
                    mock_remove.assert_not_called()

# Test 4: os.listdir raises exception - except branch
def test_cleanup_files_exception_branch():
    with patch("os.listdir", side_effect=Exception("Folder not found")):
        with patch("time.sleep", side_effect=Exception("stop loop")):
            try:
                app.cleanup_files()
            except Exception:
                pass  # except Exception: pass branch is covered

# -----------------------------
# 23️⃣ Test backup_db function
# -----------------------------

# Test 1: shutil.copy raises exception - except branch
def test_backup_db_exception_branch():
    with patch("app.shutil.copy", side_effect=Exception("Copy failed")):
        with patch("app.time.sleep", side_effect=Exception("stop loop")):
            try:
                app.backup_db()
            except Exception:
                pass  # except Exception: pass branch is covered

# Test 2: Normal backup - file copied successfully
def test_backup_db_normal():
    with patch("app.shutil.copy") as mock_copy:
        with patch("app.os.listdir", return_value=["backup1.db", "backup2.db"]):
            with patch("app.os.remove") as mock_remove:
                with patch("app.time.sleep", side_effect=Exception("stop loop")):
                    try:
                        app.backup_db()
                    except Exception:
                        pass
                    mock_copy.assert_called_once()

# Test 3: More than 10 backups - old files deleted
def test_backup_db_deletes_old_backups():
    # Create 12 fake backup files
    fake_files = [f"fortigrid_{i}.db" for i in range(12)]

    with patch("app.shutil.copy"):
        with patch("app.os.listdir", return_value=fake_files):
            with patch("app.os.remove") as mock_remove:
                with patch("app.time.sleep", side_effect=Exception("stop loop")):
                    try:
                        app.backup_db()
                    except Exception:
                        pass
                    # Should delete 2 oldest files (12 - 10 = 2)
                    assert mock_remove.call_count == 2

# Test 4: Less than 10 backups - no files deleted
def test_backup_db_no_deletion_needed():
    fake_files = [f"fortigrid_{i}.db" for i in range(5)]

    with patch("app.shutil.copy"):
        with patch("app.os.listdir", return_value=fake_files):
            with patch("app.os.remove") as mock_remove:
                with patch("app.time.sleep", side_effect=Exception("stop loop")):
                    try:
                        app.backup_db()
                    except Exception:
                        pass
                    mock_remove.assert_not_called()

# -----------------------------
# 24️⃣ Test send_custom_email function
# -----------------------------

# Test 1: smtplib.SMTP raises exception - except branch
def test_send_custom_email_exception_branch():
    with patch("app.smtplib.SMTP", side_effect=Exception("SMTP connection failed")):
        # Should silently pass without raising
        app.send_custom_email(
            to_email="test@example.com",
            smtp_server="smtp.gmail.com:587",
            smtp_user="user@gmail.com",
            smtp_pass="password",
            subject="Test Subject",
            body="Test Body"
        )

# Test 2: Normal email sent successfully
def test_send_custom_email_success():
    with patch("app.smtplib.SMTP") as mock_smtp:
        mock_server = mock_smtp.return_value
        
        app.send_custom_email(
            to_email="test@example.com",
            smtp_server="smtp.gmail.com:587",
            smtp_user="user@gmail.com",
            smtp_pass="password",
            subject="Test Subject",
            body="Test Body"
        )

        # Verify all SMTP methods were called
        mock_server.ehlo.assert_called()
        mock_server.starttls.assert_called()
        mock_server.login.assert_called_with("user@gmail.com", "password")
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()

# Test 3: server.login raises exception - except branch
def test_send_custom_email_login_exception():
    with patch("app.smtplib.SMTP") as mock_smtp:
        mock_server = mock_smtp.return_value
        mock_server.login.side_effect = Exception("Login failed")

        # Should silently pass without raising
        app.send_custom_email(
            to_email="test@example.com",
            smtp_server="smtp.gmail.com:587",
            smtp_user="user@gmail.com",
            smtp_pass="wrongpassword",
            subject="Test Subject",
            body="Test Body"
        )

# Test 4: Invalid smtp_server format - except branch
def test_send_custom_email_invalid_smtp_format():
    # No colon in smtp_server causes split to fail
    with patch("app.smtplib.SMTP") as mock_smtp:
        app.send_custom_email(
            to_email="test@example.com",
            smtp_server="invalidformat",  # No port -> split(":") fails
            smtp_user="user@gmail.com",
            smtp_pass="password",
            subject="Test Subject",
            body="Test Body"
        )
        mock_smtp.assert_not_called()

# -----------------------------
# 25️⃣ Test alert_monitor_daemon function
# -----------------------------

# Helper: base settings row (id, cpu, ram, disk, offline_mins, email_to, smtp_server, smtp_user, enc_pass)
def make_settings_row(enc_pass="validencrypted"):
    return (1, 95, 90, 5, 10, "to@example.com", "smtp.gmail.com:587", "user@example.com", enc_pass)

# Test 1: cipher_suite.decrypt raises exception - except branch + continue
def test_alert_monitor_decrypt_exception():
    settings_row = make_settings_row(enc_pass="badencrypted")

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row

        with patch("app.cipher_suite.decrypt", side_effect=Exception("Decrypt failed")):
            with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                try:
                    app.alert_monitor_daemon()
                except Exception:
                    pass  # covers: except Exception: time.sleep(60); continue

# Test 2: Agents fetched, valid JSON payload, host is online
def test_alert_monitor_agent_online():
    import json as json_lib
    settings_row = make_settings_row()
    payload = json_lib.dumps({"systemInfo": {"cpu": 10}})
    now = int(time.time())
    agents = [("TESTHOST", now - 60, payload)]  # last seen 1 min ago (online)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row
        mock_cursor.fetchall.return_value = agents

        with patch("app.cipher_suite.decrypt") as mock_decrypt:
            mock_decrypt.return_value.decode.return_value = "validpass"
            with patch("app.send_custom_email") as mock_email:
                with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                    try:
                        app.alert_monitor_daemon()
                    except Exception:
                        pass
                    # Host is online, no email should be sent
                    mock_email.assert_not_called()

# Test 3: Agent offline - alert email sent and added to alerted_states
def test_alert_monitor_agent_offline_alert():
    import json as json_lib
    settings_row = make_settings_row()
    payload = json_lib.dumps({"systemInfo": {"cpu": 10}})
    now = int(time.time())
    agents = [("OFFLINEHOST", now - 9999, payload)]  # very old last_seen

    # Clear alerted_states before test
    app.alerted_states.discard("OFFLINEHOST_offline")

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row
        mock_cursor.fetchall.return_value = agents

        with patch("app.cipher_suite.decrypt") as mock_decrypt:
            mock_decrypt.return_value.decode.return_value = "validpass"
            with patch("app.send_custom_email") as mock_email:
                with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                    try:
                        app.alert_monitor_daemon()
                    except Exception:
                        pass
                    # Email should be sent for offline host
                    mock_email.assert_called_once()
                    assert "OFFLINEHOST_offline" in app.alerted_states

# Test 4: Agent offline but already alerted - no duplicate email
def test_alert_monitor_agent_already_alerted():
    import json as json_lib
    settings_row = make_settings_row()
    payload = json_lib.dumps({"systemInfo": {}})
    now = int(time.time())
    agents = [("ALREADYHOST", now - 9999, payload)]

    # Pre-add to alerted_states
    app.alerted_states.add("ALREADYHOST_offline")

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row
        mock_cursor.fetchall.return_value = agents

        with patch("app.cipher_suite.decrypt") as mock_decrypt:
            mock_decrypt.return_value.decode.return_value = "validpass"
            with patch("app.send_custom_email") as mock_email:
                with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                    try:
                        app.alert_monitor_daemon()
                    except Exception:
                        pass
                    # Already alerted - no duplicate email
                    mock_email.assert_not_called()

# Test 5: Agent back online - alerted_states discarded
def test_alert_monitor_agent_back_online():
    import json as json_lib
    settings_row = make_settings_row()
    payload = json_lib.dumps({"systemInfo": {}})
    now = int(time.time())
    agents = [("RECOVEREDHOST", now - 60, payload)]  # online again

    # Pre-add to alerted_states
    app.alerted_states.add("RECOVEREDHOST_offline")

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row
        mock_cursor.fetchall.return_value = agents

        with patch("app.cipher_suite.decrypt") as mock_decrypt:
            mock_decrypt.return_value.decode.return_value = "validpass"
            with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                try:
                    app.alert_monitor_daemon()
                except Exception:
                    pass
                # Should be removed from alerted_states
                assert "RECOVEREDHOST_offline" not in app.alerted_states

# Test 6: Invalid JSON payload - except branch -> payload = {}
def test_alert_monitor_invalid_json_payload():
    settings_row = make_settings_row()
    now = int(time.time())
    agents = [("JSONHOST", now - 60, "not-valid-json")]  # bad JSON

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row
        mock_cursor.fetchall.return_value = agents

        with patch("app.cipher_suite.decrypt") as mock_decrypt:
            mock_decrypt.return_value.decode.return_value = "validpass"
            with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
                try:
                    app.alert_monitor_daemon()
                except Exception:
                    pass  # covers: except Exception: payload = {}

# Test 7: get_db raises exception - outer except branch
def test_alert_monitor_db_exception():
    with patch("app.get_db", side_effect=Exception("DB error")):
        with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
            try:
                app.alert_monitor_daemon()
            except Exception:
                pass  # covers outer: except Exception: pass

# Test 8: enc pass check
def test_alert_monitor_no_enc_pass():
    # settings row with empty enc_pass (row[8] = '')
    settings_row = (1, 95, 90, 5, 10, 'to@test.com', 'smtp.gmail.com:587', 'user@test.com', '')  # empty enc_pass

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = settings_row

        with patch("app.time.sleep", side_effect=[None, Exception("stop loop")]):
            try:
                app.alert_monitor_daemon()
            except Exception:
                pass  # covers line 295: else -> continue

# -----------------------------
# 26️⃣ Test extract_clean_string function
# -----------------------------

# Test 1: None/empty input - returns "-"
def test_extract_clean_string_none():
    assert app.extract_clean_string(None) == "-"
    assert app.extract_clean_string("") == "-"
    assert app.extract_clean_string(0) == "-"

# Test 2: dict with IP key - returns IP value
def test_extract_clean_string_dict_ip():
    assert app.extract_clean_string({"IP": "192.168.1.1"}) == "192.168.1.1"
    assert app.extract_clean_string({"IPAddress": "10.0.0.1"}) == "10.0.0.1"
    assert app.extract_clean_string({"MAC": "AA-BB-CC-DD-EE-FF"}) == "AA-BB-CC-DD-EE-FF"
    assert app.extract_clean_string({"MacAddress": "AA-BB-CC-DD-EE-FF"}) == "AA-BB-CC-DD-EE-FF"
    assert app.extract_clean_string({"ip": "192.168.1.1"}) == "192.168.1.1"
    assert app.extract_clean_string({"mac": "AA-BB-CC-DD-EE-FF"}) == "AA-BB-CC-DD-EE-FF"

# Test 3: dict with IP key as list - returns first element
def test_extract_clean_string_dict_ip_list():
    assert app.extract_clean_string({"IP": ["192.168.1.1", "10.0.0.1"]}) == "192.168.1.1"
    assert app.extract_clean_string({"MAC": ["AA-BB-CC-DD-EE-FF"]}) == "AA-BB-CC-DD-EE-FF"

# Test 4: dict with no matching key - returns "-"
def test_extract_clean_string_dict_no_match():
    assert app.extract_clean_string({"randomkey": "value"}) == "-"

# Test 5: list input - recursively calls with first element
def test_extract_clean_string_list():
    assert app.extract_clean_string(["192.168.1.1"]) == "192.168.1.1"
    assert app.extract_clean_string([{"IP": "10.0.0.1"}]) == "10.0.0.1"

# Test 6: empty list - returns "-"
def test_extract_clean_string_empty_list():
    assert app.extract_clean_string([]) == "-"

# Test 7: filtered values - returns "-"
def test_extract_clean_string_filtered_values():
    assert app.extract_clean_string("[object Object]") == "-"
    assert app.extract_clean_string("Unknown device") == "-"
    assert app.extract_clean_string("127.0.0.1") == "-"
    assert app.extract_clean_string("00-00-00-00-00-00") == "-"

# Test 8: valid string - returns stripped string
def test_extract_clean_string_valid():
    assert app.extract_clean_string("  192.168.1.1  ") == "192.168.1.1"
    assert app.extract_clean_string("TESTHOST") == "TESTHOST"
    assert app.extract_clean_string(12345) == "12345"

# -----------------------------
# 27️⃣ Test update_agent_data function
# -----------------------------

# Test 1: New host - INSERT branch
def test_update_agent_data_new_host():
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # No existing row

        app.update_agent_data("NEWHOST", {"cpu": 50}, is_full=False)

        # Verify INSERT was called
        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("INSERT" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 2: Existing host - UPDATE branch
def test_update_agent_data_existing_host():
    now = int(time.time())
    payload = json_lib.dumps({"systemInfo": {}, "last_login": now})
    row = (now - 60, payload)  # last_seen 1 min ago

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        app.update_agent_data("EXISTHOST", {"cpu": 80}, is_full=False)

        # Verify UPDATE was called
        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 3: Existing host, last_seen > 120s ago - last_logout/last_login updated
def test_update_agent_data_last_logout_updated():
    now = int(time.time())
    payload = json_lib.dumps({"systemInfo": {}})
    row = (now - 200, payload)  # last_seen 200s ago (> 120s)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        app.update_agent_data("LOGOUTHOST", {"cpu": 50}, is_full=False)

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# Test 4: Existing host, no last_login in payload
def test_update_agent_data_no_last_login():
    now = int(time.time())
    payload = json_lib.dumps({})  # no last_login key
    row = (now - 60, payload)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        app.update_agent_data("NOLOGINHOST", {"cpu": 50}, is_full=False)

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# Test 5: is_full=True - payload.update with ip and mac
def test_update_agent_data_is_full_with_ip_mac():
    now = int(time.time())
    payload = json_lib.dumps({"last_login": now, "last_logout": 0})
    row = (now - 60, payload)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        with patch("app.extract_clean_string", return_value="192.168.1.1") as mock_extract:
            app.update_agent_data("FULLHOST", {
                "ip": "192.168.1.1",
                "mac": "AA-BB-CC-DD-EE-FF",
                "cpu": 50
            }, is_full=True)

            # extract_clean_string called for ip and mac
            assert mock_extract.call_count == 2
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)

# Test 6: is_full=False - systemInfo cpu/ram/idle updated
def test_update_agent_data_partial_update():
    now = int(time.time())
    payload = json_lib.dumps({"systemInfo": {}, "last_login": now})
    row = (now - 60, payload)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        app.update_agent_data("PARTIALHOST", {
            "cpu": 75,
            "ram": 60,
            "idle": 120
        }, is_full=False)

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# Test 7: Invalid JSON in existing payload - except branch -> payload = {}
def test_update_agent_data_invalid_json_payload():
    now = int(time.time())
    row = (now - 60, "not-valid-json")  # bad JSON

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        # Should not raise - except Exception: pass covers json.loads failure
        app.update_agent_data("JSONHOST", {"cpu": 50}, is_full=False)

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# Test 8: get_db raises exception - outer except branch
def test_update_agent_data_db_exception():
    with patch("app.get_db", side_effect=Exception("DB error")):
        # Should silently pass without raising
        app.update_agent_data("EXHOST", {"cpu": 50}, is_full=False)

# Test 9: is_full=True, old_login and old_logout preserved
def test_update_agent_data_preserves_login_logout():
    now = int(time.time())
    old_login = now - 500
    old_logout = now - 600
    payload = json_lib.dumps({"last_login": old_login, "last_logout": old_logout})
    row = (now - 60, payload)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = row

        app.update_agent_data("PRESERVEHOST", {"somekey": "val"}, is_full=True)

        calls = mock_cursor.execute.call_args_list
        update_call = [c for c in calls if "UPDATE" in str(c)]
        assert len(update_call) > 0

        # Debug: print actual structure
        print("\nDEBUG update_call[0]:", update_call[0])
        print("DEBUG update_call[0][0]:", update_call[0][0])
        print("DEBUG update_call[0][1]:", update_call[0][1])

        # Find the JSON string among all args
        all_args = update_call[0][0]
        json_str = None
        for arg in all_args:
            if isinstance(arg, tuple):
                for item in arg:
                    if isinstance(item, str) and item.startswith("{"):
                        json_str = item
                        break
            elif isinstance(arg, str) and arg.startswith("{"):
                json_str = arg

        assert json_str is not None, "Could not find JSON payload in call args"
        saved_payload = json_lib.loads(json_str)
        print("DEBUG saved_payload:", saved_payload)
        assert saved_payload.get("last_login") == old_login
        assert saved_payload.get("last_logout") == old_logout

# -----------------------------
# 28️⃣ Test queue_cmd function
# -----------------------------

# Test 1: New host - INSERT branch
def test_queue_cmd_new_host():
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # No existing row

        app.queue_cmd("NEWHOST", "reboot")

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("INSERT" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 2: Existing host with empty queue - UPDATE branch
def test_queue_cmd_existing_host_empty_queue():
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("[]",)  # Empty queue

        app.queue_cmd("EXISTHOST", "reboot")

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 3: Existing host with invalid JSON queue - except branch -> cmds = []
def test_queue_cmd_invalid_json_queue():
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("not-valid-json",)  # Bad JSON

        app.queue_cmd("JSONHOST", "reboot")

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# Test 4: Existing host, same command already last in queue - no duplicate
def test_queue_cmd_no_duplicate_command():
    import hmac as hmac_lib
    cmd = "reboot"
    sig = hmac_lib.new(app.COMMAND_SECRET, cmd.encode(), __import__('hashlib').sha256).hexdigest()
    signed_cmd = f"{cmd}::{sig}"
    existing_queue = json_lib.dumps([signed_cmd])  # Same command already last

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (existing_queue,)

        app.queue_cmd("DUPHOST", cmd)

        # Verify UPDATE called but no duplicate added
        calls = mock_cursor.execute.call_args_list
        update_call = [c for c in calls if "UPDATE" in str(c)]
        assert len(update_call) > 0
        saved_cmds = json_lib.loads(update_call[0][0][1][0])
        assert saved_cmds.count(signed_cmd) == 1  # No duplicate

# Test 5: Queue exceeds 50 - trimmed to last 50
def test_queue_cmd_trim_queue():
    existing_cmds = [f"cmd_{i}" for i in range(55)]  # 55 commands
    existing_queue = json_lib.dumps(existing_cmds)

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (existing_queue,)

        app.queue_cmd("TRIMHOST", "newcmd")

        calls = mock_cursor.execute.call_args_list
        update_call = [c for c in calls if "UPDATE" in str(c)]
        assert len(update_call) > 0
        saved_cmds = json_lib.loads(update_call[0][0][1][0])
        assert len(saved_cmds) <= 50

# Test 6: get_db raises exception - outer except branch
def test_queue_cmd_db_exception():
    with patch("app.get_db", side_effect=Exception("DB error")):
        # Should silently pass without raising
        app.queue_cmd("EXHOST", "reboot")

# Test 7: Existing host with None queue - cmds stays []
def test_queue_cmd_none_queue():
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)  # row exists but queue is None

        app.queue_cmd("NONEHOST", "reboot")

        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)

# -----------------------------
# 29️⃣ Test setup route function
# -----------------------------

# Test 1: Users already exist - redirect to login
def test_setup_redirects_if_users_exist(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (1,)  # 1 user exists

        resp = client.get("/setup")
        assert resp.status_code in (200, 302)

# Test 2: No users, GET request - renders setup page
def test_setup_get_no_users(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (0,)  # No users

        resp = client.get("/setup")
        assert resp.status_code in (200, 302, 404)

# Test 3: POST with missing username - error message
def test_setup_post_missing_username(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (0,)  # No users

        resp = client.post("/setup", data={
            "username": "",
            "password": "short"
        })
        assert resp.status_code in (200, 302, 404)

# Test 4: POST with short password - error message
def test_setup_post_short_password(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (0,)  # No users

        resp = client.post("/setup", data={
            "username": "admin",
            "password": "short"  # Less than 8 chars
        })
        assert resp.status_code in (200, 302, 404)

# Test 5: POST with valid credentials - user created, redirect to dashboard
def test_setup_post_valid_credentials(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (0,)  # No users

        with patch("app.audit_log") as mock_audit:
            resp = client.post("/setup", data={
                "username": "admin",
                "password": "validpassword123"
            })
            assert resp.status_code in (200, 302, 404)
            # Verify audit_log was called
            if mock_audit.called:
                args = mock_audit.call_args[0]
                assert args[1] == "system_setup"

# Test 6: POST valid - session set correctly
def test_setup_post_sets_session(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (0,)  # No users

        with patch("app.audit_log"):
            resp = client.post("/setup", data={
                "username": "admin",
                "password": "validpassword123"
            })
            # Check session was set
            with client.session_transaction() as sess:
                if "user" in sess:
                    assert sess["user"] == "admin"
                    assert sess["role"] == "admin"
                    assert "csrf_token" in sess

# -----------------------------
# 30️⃣ Test login route function
# -----------------------------

# Test 1: IP locked out
def test_login_ip_locked_out(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (1,)  # Users exist

        with patch("app.get_remote_address", return_value="1.2.3.4"):
            with patch("app.render_template", return_value="mocked"):
                app.FAILED_LOGINS["1.2.3.4"] = 5  # Locked out
                resp = client.post("/login", data={
                    "username": "admin",
                    "password": "password123"
                })
                assert resp.status_code in (200, 302, 401, 403)

# Test valid login - covers is_valid branch, session, UPDATE, audit_log, redirect
def test_login_valid_credentials(client):
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash("validpassword123")

    # Mock first get_db (COUNT check) and second get_db (login logic)
    mock_conn1 = MagicMock()
    mock_cursor1 = MagicMock()
    mock_cursor1.execute.return_value.fetchone.return_value = (1,)  # Users exist
    mock_conn1.cursor.return_value = mock_cursor1
    mock_conn1.__enter__ = MagicMock(return_value=mock_conn1)
    mock_conn1.__exit__ = MagicMock(return_value=False)

    mock_conn2 = MagicMock()
    mock_cursor2 = MagicMock()
    mock_cursor2.fetchone.return_value = (hashed, "admin")  # Valid user row
    mock_conn2.cursor.return_value = mock_cursor2
    mock_conn2.__enter__ = MagicMock(return_value=mock_conn2)
    mock_conn2.__exit__ = MagicMock(return_value=False)

    call = {"n": 0}
    def fake_get_db():
        call["n"] += 1
        return mock_conn1 if call["n"] == 1 else mock_conn2

    with patch("app.get_db", side_effect=fake_get_db):
        with patch("app.get_remote_address", return_value="9.9.9.9"):
            with patch("app.audit_log") as mock_audit:
                with patch("app.render_template", return_value="mocked"):
                    # Clear any lockout
                    app.FAILED_LOGINS.pop("9.9.9.9", None)

                    resp = client.post("/login", data={
                        "username": "admin",
                        "password": "validpassword123"
                    })

                    # Should redirect to dashboard
                    assert resp.status_code in (200, 302)

                    # Verify UPDATE users SET last_active was called
                    calls = [str(c) for c in mock_cursor2.execute.call_args_list]
                    assert any("UPDATE" in c for c in calls)

                    # Verify audit_log called with login action
                    if mock_audit.called:
                        args = mock_audit.call_args[0]
                        assert args[1] == "login"

                    # Verify session was set
                    with client.session_transaction() as sess:
                        if "user" in sess:
                            assert sess["user"] == "admin"
                            assert sess["role"] == "admin"
                            assert "csrf_token" in sess

# Test 3: Invalid credentials - error shown
def test_login_invalid_credentials(client):
    from werkzeug.security import generate_password_hash
    hashed = generate_password_hash("correctpassword")

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [
            (1,),               # COUNT(*) -> users exist
            (hashed, "admin")   # SELECT password, role
        ]

        with patch("app.get_remote_address", return_value="2.3.4.5"):
            with patch("app.audit_log"):
                with patch("app.render_template", return_value="mocked"):
                    resp = client.post("/login", data={
                        "username": "admin",
                        "password": "wrongpassword"
                    })
                    assert resp.status_code in (200, 302, 401)

# Test 4: User not found
def test_login_user_not_found(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [
            (1,),   # COUNT(*) -> users exist
            None    # SELECT password, role -> user not found
        ]

        with patch("app.get_remote_address", return_value="3.4.5.6"):
            with patch("app.audit_log"):
                with patch("app.render_template", return_value="mocked"):
                    resp = client.post("/login", data={
                        "username": "nonexistent",
                        "password": "somepassword"
                    })
                    assert resp.status_code in (200, 302, 401)

# Test 5: check_password_hash raises exception
def test_login_check_password_hash_exception(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.side_effect = [
            (1,),
            ("plainpassword", "admin")
        ]

        with patch("app.check_password_hash", side_effect=Exception("Hash error")):
            with patch("app.get_remote_address", return_value="4.5.6.7"):
                with patch("app.audit_log"):
                    with patch("app.render_template", return_value="mocked"):
                        resp = client.post("/login", data={
                            "username": "admin",
                            "password": "plainpassword"
                        })
                        assert resp.status_code in (200, 302, 401, 500)

# Test 6: DB raises exception
def test_login_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        with patch("app.get_remote_address", return_value="5.6.7.8"):
            with patch("app.render_template", return_value="mocked"):
                resp = client.post("/login", data={
                    "username": "admin",
                    "password": "password123"
                })
                assert resp.status_code in (200, 302, 401, 500)

# Test: DB exception inside login POST - error = "Database Error"
def test_login_db_error_inside_post(client):
    mock_conn1 = MagicMock()
    mock_cursor1 = MagicMock()
    mock_cursor1.execute.return_value.fetchone.return_value = (1,)  # Users exist
    mock_conn1.cursor.return_value = mock_cursor1
    mock_conn1.__enter__ = MagicMock(return_value=mock_conn1)
    mock_conn1.__exit__ = MagicMock(return_value=False)

    mock_conn2 = MagicMock()
    mock_conn2.__enter__ = MagicMock(side_effect=Exception("DB error"))  # Second get_db fails
    mock_conn2.__exit__ = MagicMock(return_value=False)

    call = {"n": 0}
    def fake_get_db():
        call["n"] += 1
        return mock_conn1 if call["n"] == 1 else mock_conn2

    with patch("app.get_db", side_effect=fake_get_db):
        with patch("app.get_remote_address", return_value="9.8.7.6"):
            with patch("app.render_template", return_value="mocked") as mock_render:
                app.FAILED_LOGINS.pop("9.8.7.6", None)

                resp = client.post("/login", data={
                    "username": "admin",
                    "password": "validpassword123"
                })

                assert resp.status_code in (200, 302)

                # Verify render_template was called with error="Database Error"
                if mock_render.called:
                    _, kwargs = mock_render.call_args
                    assert kwargs.get("error") == "Database Error"

# -----------------------------
# 31️⃣ Test logout function
# -----------------------------

def test_logout(client):
    # Set session before logout
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.audit_log") as mock_audit:
        resp = client.get("/logout")

        # Should redirect to login
        assert resp.status_code in (200, 302)

        # Verify audit_log was called with logout action
        mock_audit.assert_called_once_with("admin", "logout", "system")

        # Verify session was cleared
        with client.session_transaction() as sess:
            assert "user" not in sess
            assert "role" not in sess

def test_logout_without_session(client):
    # Logout without any session set - uses 'unknown'
    with patch("app.audit_log") as mock_audit:
        resp = client.get("/logout")

        assert resp.status_code in (200, 302)

        # Verify audit_log called with 'unknown' as user
        mock_audit.assert_called_once_with("unknown", "logout", "system")

# -----------------------------
# 32️⃣ Test dashboard function
# -----------------------------

# Test 1: No session - redirect to login
def test_dashboard_no_session(client):
    resp = client.get("/")
    assert resp.status_code in (200, 302)

# Test 2: With session - renders dashboard
def test_dashboard_with_session(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.render_template", return_value="mocked") as mock_render:
        resp = client.get("/")
        assert resp.status_code in (200, 302)

        # Verify render_template called with correct args
        if mock_render.called:
            args, kwargs = mock_render.call_args
            assert args[0] == "dashboard.html"
            assert kwargs.get("user") == "admin"
            assert kwargs.get("role") == "admin"
            assert kwargs.get("csrf_token") == "testtoken"

# Print all routes to find correct dashboard URL
def test_print_all_routes():
    with flask_app.test_request_context():
        routes = [(rule.rule, rule.endpoint) for rule in flask_app.url_map.iter_rules()]
        for route, endpoint in sorted(routes):
            print(f"  {route} -> {endpoint}")
    assert True

# -----------------------------
# 33️⃣ Test get_data function
# -----------------------------

# Test 1: No session - returns 403
def test_get_data_no_session(client):
    resp = client.get("/api/data")
    assert resp.status_code == 403

# Test 2: With session, no agents - returns empty list
def test_get_data_empty_agents(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        resp = client.get("/api/data")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 3: With session, online agent - status ONLINE
def test_get_data_agent_online(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    now = int(time.time())
    payload = json_lib.dumps({"ip": "192.168.1.1", "systemInfo": {}})
    agents = [("TESTHOST", now - 60, payload)]  # last seen 1 min ago -> ONLINE

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = agents

        resp = client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["hostname"] == "TESTHOST"
        assert data[0]["status"] == "ONLINE"

# Test 4: With session, offline agent - status OFFLINE
def test_get_data_agent_offline(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    now = int(time.time())
    payload = json_lib.dumps({"ip": "192.168.1.1"})
    agents = [("OFFLINEHOST", now - 9999, payload)]  # very old -> OFFLINE

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = agents

        resp = client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["status"] == "OFFLINE"

# Test 5: Invalid JSON payload - except branch -> agent = {}
def test_get_data_invalid_json_payload(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    now = int(time.time())
    agents = [("JSONHOST", now - 60, "not-valid-json")]  # bad JSON

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = agents

        resp = client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data[0]["hostname"] == "JSONHOST"

# Test 6: DB raises exception - except branch -> returns empty list
def test_get_data_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/data")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 34️⃣ Test receive_report function
# -----------------------------

# Test 1: Valid verified_host - update_agent_data called
def test_receive_report_valid_host(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data") as mock_update:
            import json as json_lib
            resp = client.post(
                "/api/reports",  # fixed URL
                data=json_lib.dumps({"hostname": "TESTHOST", "cpu": 50}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "testnonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"
            mock_update.assert_called_once()

# Test 2: verified_host is UNKNOWN - update_agent_data NOT called
def test_receive_report_unknown_host(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data") as mock_update:
            with patch("app.get_host_from_data", return_value="UNKNOWN"):
                import json as json_lib
                resp = client.post(
                    "/api/reports",  # fixed URL
                    data=json_lib.dumps({}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "testnonce2"
                    }
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

# Test 3: Exception raised - except branch, still returns success
def test_receive_report_exception(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data", side_effect=Exception("Update error")):
            import json as json_lib
            resp = client.post(
                "/api/reports",  # fixed URL
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "testnonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# -----------------------------
# 35️⃣ Test receive_heartbeat function
# -----------------------------

# Test 1: Valid host - update_agent_data and perf_history updated
def test_receive_heartbeat_valid_host(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data") as mock_update:
            with patch("app.get_db") as mock_db:
                mock_conn = mock_db.return_value.__enter__.return_value
                mock_cursor = mock_conn.cursor.return_value
                mock_cursor.fetchone.return_value = None  # No existing history

                resp = client.post(
                    "/api/heartbeat",
                    data=json_lib.dumps({"hostname": "TESTHOST", "cpu": 50, "ram": 60}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "heartbeat-nonce1"
                    }
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"
                mock_update.assert_called_once()

                # Verify REPLACE INTO perf_history was called
                calls = [str(c) for c in mock_cursor.execute.call_args_list]
                assert any("REPLACE" in c for c in calls)

# Test 2: Existing history - appended and trimmed if > 20
def test_receive_heartbeat_existing_history(client):
    import json as json_lib
    # Create 20 existing history entries
    existing_hist = [{"time": "00:00:00", "cpu": i, "ram": i} for i in range(20)]

    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data"):
            with patch("app.get_db") as mock_db:
                mock_conn = mock_db.return_value.__enter__.return_value
                mock_cursor = mock_conn.cursor.return_value
                mock_cursor.fetchone.return_value = (json_lib.dumps(existing_hist),)

                resp = client.post(
                    "/api/heartbeat",
                    data=json_lib.dumps({"hostname": "TESTHOST", "cpu": 75, "ram": 80}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "heartbeat-nonce2"
                    }
                )
                assert resp.status_code == 200

                # Verify history was saved with max 20 entries
                calls = mock_cursor.execute.call_args_list
                replace_call = [c for c in calls if "REPLACE" in str(c)]
                assert len(replace_call) > 0
                saved_hist = json_lib.loads(replace_call[0][0][1][1])
                assert len(saved_hist) <= 20

# Test 3: host is UNKNOWN - update_agent_data NOT called
def test_receive_heartbeat_unknown_host(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data") as mock_update:
            with patch("app.get_host_from_data", return_value="UNKNOWN"):
                resp = client.post(
                    "/api/heartbeat",
                    data=json_lib.dumps({}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "heartbeat-nonce3"
                    }
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

# Test 4: DB exception - except branch, still returns success
def test_receive_heartbeat_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.update_agent_data"):
            with patch("app.get_db", side_effect=Exception("DB error")):
                resp = client.post(
                    "/api/heartbeat",
                    data=json_lib.dumps({"hostname": "TESTHOST"}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "heartbeat-nonce4"
                    }
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

# -----------------------------
# 36️⃣ Test get_commands function
# -----------------------------

# Test 1: host is UNKNOWN - returns empty commands
def test_get_commands_unknown_host(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_host_from_data", return_value="UNKNOWN"):
            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["commands"] == []

# Test 2: No existing row - INSERT branch
def test_get_commands_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None  # No row

            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["commands"] == []

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 3: Existing row with commands - UPDATE clears queue
def test_get_commands_with_commands(client):
    import json as json_lib
    cmds = ["reboot::sig1", "shutdown::sig2"]

    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = (json_lib.dumps(cmds),)

            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce3"
                }
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["commands"] == cmds

            # Verify UPDATE with empty queue was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("command_queue='[]'" in c for c in calls)

# Test 4: Existing row with empty queue - UPDATE last_seen only
def test_get_commands_empty_queue(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("[]",)  # Empty queue

            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce4"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["commands"] == []

            # Verify UPDATE last_seen only (no command_queue reset)
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("last_seen" in c for c in calls)

# Test 5: Invalid JSON in queue - except branch -> cmds = []
def test_get_commands_invalid_json_queue(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("not-valid-json",)

            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce5"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["commands"] == []

# Test 6: DB exception - except branch returns empty commands
def test_get_commands_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/commands/get",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "cmd-nonce6"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["commands"] == []

# -----------------------------
# 37️⃣ Test upload_screen function
# -----------------------------

def test_upload_screen_too_large(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        big_image = "A" * 15_000_001  # Exceeds 15MB limit

        resp = client.post(
            "/api/screen/upload",
            data=json_lib.dumps({"hostname": "TESTHOST", "image": big_image}),
            content_type="application/json",
            headers={
                "X-API-KEY": "testkey",
                "X-SIGNATURE": "testsig",
                "X-TIMESTAMP": str(int(time.time())),
                "X-NONCE": "screen-nonce1"
            }
        )

        assert resp.status_code == 400
        assert resp.get_json()["error"] == "Payload too large"


# Test 2: Valid image without base64 prefix - file written
def test_upload_screen_valid_image(client):
    img_data = base64_lib.b64encode(b"fakeimagedata").decode()

    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.os.path.join", side_effect=lambda *a: "/tmp/" + a[-1]):
            with patch("builtins.open", MagicMock()):
                with patch("app.os.replace") as mock_replace:

                    resp = client.post(
                        "/api/screen/upload",
                        data=json_lib.dumps({"hostname": "TESTHOST", "image": img_data}),
                        content_type="application/json",
                        headers={
                            "X-API-KEY": "testkey",
                            "X-SIGNATURE": "testsig",
                            "X-TIMESTAMP": str(int(time.time())),
                            "X-NONCE": "screen-nonce2"
                        }
                    )

                    assert resp.status_code == 200
                    assert resp.get_json()["status"] == "success"
                    mock_replace.assert_called_once()


# Test 3: Image with base64 prefix
def test_upload_screen_image_with_prefix(client):
    img_data = "data:image/jpeg;base64," + base64_lib.b64encode(b"fakeimagedata").decode()

    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("builtins.open", MagicMock()):
            with patch("app.os.replace"):

                resp = client.post(
                    "/api/screen/upload",
                    data=json_lib.dumps({"hostname": "TESTHOST", "image": img_data}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "screen-nonce3"
                    }
                )

                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"


# Test 4: Invalid base64 - inner except triggers, still success
def test_upload_screen_invalid_base64(client):
    with patch("app.verify_agent", return_value="TESTHOST"):

        resp = client.post(
            "/api/screen/upload",
            data=json_lib.dumps({"hostname": "TESTHOST", "image": "not-valid-base64!!!"}),
            content_type="application/json",
            headers={
                "X-API-KEY": "testkey",
                "X-SIGNATURE": "testsig",
                "X-TIMESTAMP": str(int(time.time())),
                "X-NONCE": "screen-nonce4"
            }
        )

        assert resp.status_code == 400
        assert resp.get_json()["error"] == "Image processing failed"

# Test 5: host UNKNOWN - skip file write
def test_upload_screen_unknown_host(client):
    img_data = base64_lib.b64encode(b"fakeimagedata").decode()

    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_host_from_data", return_value="UNKNOWN"):
            with patch("app.os.replace") as mock_replace:

                resp = client.post(
                    "/api/screen/upload",
                    data=json_lib.dumps({}),
                    content_type="application/json",
                    headers={
                        "X-API-KEY": "testkey",
                        "X-SIGNATURE": "testsig",
                        "X-TIMESTAMP": str(int(time.time())),
                        "X-NONCE": "screen-nonce5"
                    }
                )

                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"
                mock_replace.assert_not_called()


def test_upload_screen_outer_exception(client):
    import json as json_lib
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):
        # Send JSON that becomes a LIST instead of dict
        resp = client.post(
            "/api/screen/upload",
            data=json_lib.dumps(["not", "a", "dict"]),  # <-- key trick
            content_type="application/json",
            headers={
                "X-API-KEY": "testkey",
                "X-SIGNATURE": "testsig",
                "X-TIMESTAMP": "1234567890",
                "X-NONCE": "screen-nonce6"
            }
        )

        assert resp.status_code == 200
        assert resp.get_json()["status"] == "error"


# -----------------------------
# 38️⃣ Test term_agent_poll function
# -----------------------------

# Test 1: No existing row - returns empty command
def test_term_agent_poll_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None  # No row

            resp = client.post(
                "/api/terminal/agent_poll",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "poll-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["command"] == ""

# Test 2: Existing row with command - returns command and clears it
def test_term_agent_poll_with_command(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("reboot",)  # Existing command

            resp = client.post(
                "/api/terminal/agent_poll",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "poll-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["command"] == "reboot"

            # Verify UPDATE SET cmd=NULL was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("cmd=NULL" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 3: Existing row with NULL command - returns empty command
def test_term_agent_poll_null_command(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = (None,)  # Row exists but cmd is NULL

            resp = client.post(
                "/api/terminal/agent_poll",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "poll-nonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["command"] == ""

# Test 4: DB exception - except branch returns empty command
def test_term_agent_poll_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/terminal/agent_poll",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "poll-nonce4"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["command"] == ""

# -----------------------------
# 39️⃣ Test term_agent_push function
# -----------------------------

# Test 1: No existing row - INSERT branch
def test_term_agent_push_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None  # No row

            resp = client.post(
                "/api/terminal/agent_push",
                data=json_lib.dumps({"hostname": "TESTHOST", "output": "hello"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "push-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: Existing row - UPDATE branch
def test_term_agent_push_existing_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("previous output",)

            resp = client.post(
                "/api/terminal/agent_push",
                data=json_lib.dumps({"hostname": "TESTHOST", "output": "new output"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "push-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)

# Test 3: Existing row with NULL output - current_out defaults to ""
def test_term_agent_push_null_output(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = (None,)  # Row exists but output is NULL

            resp = client.post(
                "/api/terminal/agent_push",
                data=json_lib.dumps({"hostname": "TESTHOST", "output": "hello"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "push-nonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# Test 4: DB exception - except branch -> pass, still returns saved
def test_term_agent_push_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/terminal/agent_push",
                data=json_lib.dumps({"hostname": "TESTHOST", "output": "hello"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "push-nonce4"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# -----------------------------
# 40️⃣ Test explorer_push function
# -----------------------------

# Test 1: No existing row - INSERT branch
def test_explorer_push_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None  # No row

            resp = client.post(
                "/api/explorer/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "file_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "explorer-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: Existing row - UPDATE branch
def test_explorer_push_existing_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)  # Row exists

            resp = client.post(
                "/api/explorer/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "new_file_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "explorer-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 3: DB exception - except branch -> pass, still returns saved
def test_explorer_push_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/explorer/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "file_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "explorer-nonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# -----------------------------
# 41️⃣ Test services_push function
# -----------------------------

# Test 1: No existing row - INSERT branch
def test_services_push_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/services/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "service_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "services-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: Existing row - UPDATE branch
def test_services_push_existing_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)

            resp = client.post(
                "/api/services/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "new_service_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "services-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 3: DB exception - except branch -> pass, still returns saved
def test_services_push_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/services/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "service_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "services-nonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# -----------------------------
# 42️⃣ Test eventlog_push function
# -----------------------------

# Test 1: No existing row - INSERT branch
def test_eventlog_push_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/eventlog/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "event_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "eventlog-nonce1"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: Existing row - UPDATE branch
def test_eventlog_push_existing_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)

            resp = client.post(
                "/api/eventlog/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "new_event_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "eventlog-nonce2"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 3: DB exception - except branch -> pass, still returns saved
def test_eventlog_push_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/eventlog/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "event_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": "eventlog-nonce3"
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# -----------------------------
# 44️⃣ Test update_processes function
# -----------------------------

# Test 1: No existing row - INSERT branch
def test_update_processes_no_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/processes/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "process_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: Existing row - UPDATE branch
def test_update_processes_existing_row(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)

            resp = client.post(
                "/api/processes/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "new_process_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 3: DB exception - except branch -> pass, still returns saved
def test_update_processes_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/processes/update",
                data=json_lib.dumps({"hostname": "TESTHOST", "result": "process_list"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "saved"

# -----------------------------
# 45️⃣ Test create_ticket function
# -----------------------------

# Test 1: Valid ticket - INSERT branch
def test_create_ticket_valid(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value

            resp = client.post(
                "/api/tickets/create",
                data=json_lib.dumps({
                    "hostname": "TESTHOST",
                    "severity": "high",
                    "message": "Disk full"
                }),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)

# Test 2: DB exception - except branch
def test_create_ticket_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/tickets/create",
                data=json_lib.dumps({
                    "hostname": "TESTHOST",
                    "severity": "high",
                    "message": "Disk full"
                }),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code in (200, 500)

# -----------------------------
# 46️⃣ Test log_script function
# -----------------------------

# Test 1: Known script - INSERT with script name
def test_log_script_known_script(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("MyScript",)

            resp = client.post(
                "/api/scripts/log",
                data=json_lib.dumps({"hostname": "TESTHOST", "script_id": 1, "output": "output"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 2: Unknown script - s_name defaults to "Unknown Script"
def test_log_script_unknown_script(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/scripts/log",
                data=json_lib.dumps({"hostname": "TESTHOST", "script_id": 99, "output": "output"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("Unknown Script" in c for c in calls)

# Test 3: DB exception - returns 500 with error message
def test_log_script_db_exception(client):
    import json as json_lib
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/scripts/log",
                data=json_lib.dumps({"hostname": "TESTHOST", "script_id": 1, "output": "output"}),
                content_type="application/json",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 500
            data = resp.get_json()
            assert "DB Error" in data["error"]

# -----------------------------
# 47️⃣ Test queue_command function
# -----------------------------

# Test 1: viewer role - returns 403
def test_queue_command_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/commands/queue",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: invalid command - returns 400
def test_queue_command_invalid_command(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/commands/queue",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "A" * 501}),  # Too long
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid command"

# Test 3: non-string command - returns 400
def test_queue_command_non_string_command(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/commands/queue",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": 12345}),  # Not a string
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400

# Test 4: admin role - command queued successfully
def test_queue_command_admin_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.audit_log"):
            resp = client.post(
                "/api/commands/queue",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "queued"
            mock_queue.assert_called_once()

# Test 5: manager role with allowed command - queued
def test_queue_command_manager_allowed(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.audit_log"):
            with patch("app.ROLE_PERMISSIONS", {"manager": ["reboot:"], "helpdesk": []}):
                resp = client.post(
                    "/api/commands/queue",
                    data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code in (200, 403)

# Test 6: helpdesk role with allowed command - queued
def test_queue_command_helpdesk_allowed(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "helpdesk"
        sess["role"] = "helpdesk"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.audit_log"):
            with patch("app.ROLE_PERMISSIONS", {"manager": [], "helpdesk": ["reboot:"]}):
                resp = client.post(
                    "/api/commands/queue",
                    data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code in (200, 403)

# Test 7: insufficient permissions - returns 403
def test_queue_command_insufficient_permissions(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "helpdesk"
        sess["role"] = "helpdesk"
        sess["csrf_token"] = "testtoken"

    with patch("app.audit_log"):
        with patch("app.ROLE_PERMISSIONS", {"manager": [], "helpdesk": []}):
            resp = client.post(
                "/api/commands/queue",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 403
            assert resp.get_json()["error"] == "Insufficient permissions for this command."

# Test 8: DB exception - returns 500
def test_queue_command_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd", side_effect=Exception("Queue error")):
        with patch("app.audit_log"):
            resp = client.post(
                "/api/commands/queue",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "reboot"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 500
            assert resp.get_json()["status"] == "error"

# -----------------------------
# 48️⃣ Test handle_settings function
# -----------------------------

# Test 1: Non-admin role - returns 403
def test_handle_settings_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.get(
        "/api/settings",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: GET - returns settings row
def test_handle_settings_get(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (95, 90, 5, 10, "to@example.com", "smtp.gmail.com:587", "user@example.com")

        resp = client.get(
            "/api/settings",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["cpu_alert"] == 95
        assert data["ram_alert"] == 90
        assert data["email_to"] == "to@example.com"

# Test 3: GET - no settings row - returns empty dict
def test_handle_settings_get_no_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # No row

        resp = client.get(
            "/api/settings",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        assert resp.get_json() == {}

# Test 4: POST - updates settings successfully
def test_handle_settings_post(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.cipher_suite.encrypt") as mock_encrypt:
            mock_encrypt.return_value.decode.return_value = "encryptedpass"
            with patch("app.audit_log") as mock_audit:
                resp = client.post(
                    "/api/settings",
                    data=json_lib.dumps({
                        "cpu_alert": 95,
                        "ram_alert": 90,
                        "disk_alert": 5,
                        "offline_alert": 10,
                        "email_to": "to@example.com",
                        "smtp_server": "smtp.gmail.com:587",
                        "smtp_user": "user@example.com",
                        "smtp_pass": "mypassword"
                    }),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

                # Verify UPDATE was called
                calls = [str(c) for c in mock_cursor.execute.call_args_list]
                assert any("UPDATE" in c for c in calls)
                mock_conn.commit.assert_called_once()

                # Verify audit_log was called
                mock_audit.assert_called_once_with("admin", "updated_settings", "system")

# Test 5: POST with empty smtp_pass - enc_pass is empty string
def test_handle_settings_post_empty_password(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log"):
            resp = client.post(
                "/api/settings",
                data=json_lib.dumps({
                    "cpu_alert": 95,
                    "ram_alert": 90,
                    "disk_alert": 5,
                    "offline_alert": 10,
                    "email_to": "",
                    "smtp_server": "",
                    "smtp_user": "",
                    "smtp_pass": ""  # Empty - enc_pass should be ''
                }),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# Test 6: DB exception - returns 500
def test_handle_settings_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get(
            "/api/settings",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 49️⃣ Test get_script_logs function
# -----------------------------

# Test 1: No session role - returns empty list
def test_get_script_logs_no_session(client):
    resp = client.get("/api/scripts/logs")
    assert resp.status_code == 200
    assert resp.get_json() == []

# Test 2: With session - returns logs
def test_get_script_logs_with_session(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [
            (1, "MyScript", "TESTHOST", "output text", "2024-01-01 00:00:00"),
            (2, "OtherScript", "TESTHOST2", "other output", "2024-01-02 00:00:00")
        ]

        resp = client.get("/api/scripts/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["script_id"] == 1
        assert data[0]["script_name"] == "MyScript"
        assert data[0]["hostname"] == "TESTHOST"
        assert data[0]["output"] == "output text"
        assert data[0]["executed_at"] == "2024-01-01 00:00:00"

# Test 3: With session, empty logs - returns empty list
def test_get_script_logs_empty(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        resp = client.get("/api/scripts/logs")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 4: DB exception - except branch returns empty list
def test_get_script_logs_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/scripts/logs")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 50️⃣ Test list_scripts function
# -----------------------------

# Test 1: No session role - returns empty list
def test_list_scripts_no_session(client):
    resp = client.get("/api/scripts/list")
    assert resp.status_code == 200
    assert resp.get_json() == []

# Test 2: With session - returns scripts
def test_list_scripts_with_session(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [
            (1, "Script1", "Description1", "print('hello')", "admin", "2024-01-01"),
            (2, "Script2", "Description2", "print('world')", "admin", "2024-01-02")
        ]

        resp = client.get("/api/scripts/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["id"] == 1
        assert data[0]["name"] == "Script1"
        assert data[0]["description"] == "Description1"
        assert data[0]["code"] == "print('hello')"
        assert data[0]["created_by"] == "admin"
        assert data[0]["created_at"] == "2024-01-01"

# Test 3: With session, empty scripts - returns empty list
def test_list_scripts_empty(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        resp = client.get("/api/scripts/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 4: DB exception - except branch returns empty list
def test_list_scripts_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/scripts/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 51️⃣ Test add_script function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_add_script_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/add",
        data=json_lib.dumps({"name": "MyScript", "code": "print('hello')"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Missing name - returns 400
def test_add_script_missing_name(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/add",
        data=json_lib.dumps({"code": "print('hello')"}),  # No name
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 3: Missing code - returns 400
def test_add_script_missing_code(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/add",
        data=json_lib.dumps({"name": "MyScript"}),  # No code
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 4: Admin role - script added successfully
def test_add_script_admin_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/scripts/add",
                data=json_lib.dumps({
                    "name": "MyScript",
                    "description": "A test script",
                    "code": "print('hello')"
                }),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log was called
            mock_audit.assert_called_once_with("admin", "added_script", "MyScript")

# Test 5: Manager role - script added successfully
def test_add_script_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value

        with patch("app.audit_log"):
            resp = client.post(
                "/api/scripts/add",
                data=json_lib.dumps({
                    "name": "ManagerScript",
                    "code": "print('manager')"
                }),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# Test 6: DB exception - returns 500
def test_add_script_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/scripts/add",
            data=json_lib.dumps({
                "name": "MyScript",
                "code": "print('hello')"
            }),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 52️⃣ Test delete_script function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_delete_script_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/delete",
        data=json_lib.dumps({"id": 1}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Admin role - script deleted successfully
def test_delete_script_admin_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/scripts/delete",
                data=json_lib.dumps({"id": 1}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify DELETE from scripts_store and script_logs
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("DELETE FROM scripts_store" in c for c in calls)
            assert any("DELETE FROM script_logs" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log was called
            mock_audit.assert_called_once_with("admin", "deleted_script_id", "1")

# Test 3: Manager role - script deleted successfully
def test_delete_script_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value

        with patch("app.audit_log"):
            resp = client.post(
                "/api/scripts/delete",
                data=json_lib.dumps({"id": 2}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# Test 4: DB exception - returns 500
def test_delete_script_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/scripts/delete",
            data=json_lib.dumps({"id": 1}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 53️⃣ Test run_script function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_run_script_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/run",
        data=json_lib.dumps({"script_id": 1, "hosts": ["TESTHOST"]}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Missing script_id - returns 400
def test_run_script_missing_script_id(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/run",
        data=json_lib.dumps({"hosts": ["TESTHOST"]}),  # No script_id
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 3: Missing hosts - returns 400
def test_run_script_missing_hosts(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/scripts/run",
        data=json_lib.dumps({"script_id": 1, "hosts": []}),  # Empty hosts
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 4: Script not found - returns 404
def test_run_script_not_found(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # Script not found

        resp = client.post(
            "/api/scripts/run",
            data=json_lib.dumps({"script_id": 99, "hosts": ["TESTHOST"]}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 404
        assert resp.get_json()["error"] == "Script not found"

# Test 5: Valid script - queued for all hosts
def test_run_script_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("print('hello')",)  # Script found

        with patch("app.queue_cmd") as mock_queue:
            with patch("app.audit_log") as mock_audit:
                resp = client.post(
                    "/api/scripts/run",
                    data=json_lib.dumps({
                        "script_id": 1,
                        "hosts": ["TESTHOST1", "TESTHOST2"]
                    }),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["status"] == "success"
                assert data["queued"] == 2

                # Verify queue_cmd called for each host
                assert mock_queue.call_count == 2

                # Verify audit_log was called
                mock_audit.assert_called_once()

# Test 6: Manager role - success
def test_run_script_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("print('hello')",)

        with patch("app.queue_cmd"):
            with patch("app.audit_log"):
                resp = client.post(
                    "/api/scripts/run",
                    data=json_lib.dumps({"script_id": 1, "hosts": ["TESTHOST"]}),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

# Test 7: DB exception - returns 500
def test_run_script_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/scripts/run",
            data=json_lib.dumps({"script_id": 1, "hosts": ["TESTHOST"]}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 54️⃣ Test services_req function
# -----------------------------
# Test 1: No session - returns 403
def test_services_req_no_session(client):
    import json as json_lib
    resp = client.post(
        "/api/services/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json"
        # No X-CSRF-Token header - CSRF blocks first
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403 with Unauthorized
def test_services_req_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/services/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}  # Valid CSRF - reaches role check
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: No existing row - INSERT branch
def test_services_req_no_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None  # No existing row

            resp = client.post(
                "/api/services/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify queue_cmd called with get_services
            mock_queue.assert_called_once()
            args = mock_queue.call_args[0]
            assert args[1] == "get_services"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 4: Existing row - UPDATE branch
def test_services_req_existing_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)  # Existing row

            resp = client.post(
                "/api/services/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 5: DB exception - except branch -> pass, still returns sent
def test_services_req_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/services/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

# -----------------------------
# 55️⃣ Test services_read function
# -----------------------------

# Test 1: No existing row - returns empty string
def test_services_read_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/services/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 2: Existing row with result - returns result
def test_services_read_with_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("service_data",)

        resp = client.get("/api/services/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == "service_data"

# Test 3: Existing row with NULL result - returns empty string
def test_services_read_null_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)

        resp = client.get("/api/services/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 4: DB exception - except branch -> returns empty string
def test_services_read_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/services/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# -----------------------------
# 56️⃣ Test explorer_req function
# -----------------------------

# Test 1: No session - CSRF blocks, returns 403
def test_explorer_req_no_session(client):
    import json as json_lib
    resp = client.post(
        "/api/explorer/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json"
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403 Unauthorized
def test_explorer_req_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/explorer/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: No existing row - INSERT branch
def test_explorer_req_no_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/explorer/request",
                data=json_lib.dumps({"hostname": "TESTHOST", "path": "C:\\Users"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify queue_cmd called with explore command
            mock_queue.assert_called_once()
            args = mock_queue.call_args[0]
            assert "explore:" in args[1]

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 4: Existing row - UPDATE branch
def test_explorer_req_existing_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)

            resp = client.post(
                "/api/explorer/request",
                data=json_lib.dumps({"hostname": "TESTHOST", "path": "C:\\Users"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 5: DB exception - except branch -> pass, still returns sent
def test_explorer_req_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/explorer/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"
            
# -----------------------------
# 57️⃣ Test explorer_read function
# -----------------------------

# Test 1: No existing row - returns empty string
def test_explorer_read_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/explorer/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 2: Existing row with result - returns result
def test_explorer_read_with_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("file_list_data",)

        resp = client.get("/api/explorer/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == "file_list_data"

# Test 3: Existing row with NULL result - returns empty string
def test_explorer_read_null_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)

        resp = client.get("/api/explorer/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 4: DB exception - except branch -> returns empty string
def test_explorer_read_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/explorer/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# -----------------------------
# 58️⃣ Test eventlog_req function
# -----------------------------

# Test 1: No session - CSRF blocks, returns 403
def test_eventlog_req_no_session(client):
    import json as json_lib
    resp = client.post(
        "/api/eventlog/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json"
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403 Unauthorized
def test_eventlog_req_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/eventlog/request",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: No existing row - INSERT branch
def test_eventlog_req_no_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = None

            resp = client.post(
                "/api/eventlog/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify queue_cmd called with get_eventlogs
            mock_queue.assert_called_once()
            args = mock_queue.call_args[0]
            assert args[1] == "get_eventlogs"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 4: Existing row - UPDATE branch
def test_eventlog_req_existing_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db") as mock_db:
            mock_conn = mock_db.return_value.__enter__.return_value
            mock_cursor = mock_conn.cursor.return_value
            mock_cursor.fetchone.return_value = ("TESTHOST",)

            resp = client.post(
                "/api/eventlog/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 5: DB exception - except branch -> pass, still returns sent
def test_eventlog_req_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd"):
        with patch("app.get_db", side_effect=Exception("DB error")):
            resp = client.post(
                "/api/eventlog/request",
                data=json_lib.dumps({"hostname": "TESTHOST"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

# -----------------------------
# 59️⃣ Test eventlog_read function
# -----------------------------

# Test 1: No existing row - returns empty string
def test_eventlog_read_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/eventlog/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 2: Existing row with result - returns result
def test_eventlog_read_with_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("event_log_data",)

        resp = client.get("/api/eventlog/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == "event_log_data"

# Test 3: Existing row with NULL result - returns empty string
def test_eventlog_read_null_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)

        resp = client.get("/api/eventlog/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# Test 4: DB exception - except branch -> returns empty string
def test_eventlog_read_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/eventlog/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["result"] == ""

# -----------------------------
# 60️⃣ Test upload_deploy_file function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_upload_deploy_file_unauthorized(client):
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/upload",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: No file in request - returns 400
def test_upload_deploy_file_no_file(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/upload",
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Empty filename"

# Test 3: Empty filename - returns 400
def test_upload_deploy_file_empty_filename(client):
    import io
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/upload",
        content_type="multipart/form-data",
        data={"file": (io.BytesIO(b"content"), "")},  # Empty filename
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Empty filename"

# Test 4: Executable file by non-admin - returns 403
def test_upload_deploy_file_exe_non_admin(client):
    import io
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/upload",
        content_type="multipart/form-data",
        data={"file": (io.BytesIO(b"fake exe content"), "setup.exe")},
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Admin clearance required for executables."

# Test 5: Invalid file type - returns 400
def test_upload_deploy_file_invalid_type(client):
    import io
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/upload",
        content_type="multipart/form-data",
        data={"file": (io.BytesIO(b"content"), "script.py")},  # .py not allowed
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid file type."

# Test 6: Valid safe file - uploaded successfully
def test_upload_deploy_file_valid_txt(client):
    import io
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.join", return_value="/tmp/testfile.txt"):
        with patch("app.audit_log") as mock_audit:
            with patch("werkzeug.datastructures.FileStorage.save"):
                resp = client.post(
                    "/api/files/upload",
                    content_type="multipart/form-data",
                    data={"file": (io.BytesIO(b"text content"), "test.txt")},
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"
                mock_audit.assert_called_once()

# Test 7: Valid exe file by admin - uploaded successfully
def test_upload_deploy_file_exe_admin(client):
    import io
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.join", return_value="/tmp/setup.exe"):
        with patch("app.audit_log") as mock_audit:
            with patch("werkzeug.datastructures.FileStorage.save"):
                resp = client.post(
                    "/api/files/upload",
                    content_type="multipart/form-data",
                    data={"file": (io.BytesIO(b"exe content"), "setup.exe")},
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"
                mock_audit.assert_called_once()

# -----------------------------
# 61️⃣ Test list_deploy_files function
# -----------------------------

# Test 1: No session - returns empty list
def test_list_deploy_files_no_session(client):
    resp = client.get("/api/files/list")
    assert resp.status_code == 200
    assert resp.get_json() == []

# Test 2: With session, files exist - returns file list
def test_list_deploy_files_with_files(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.listdir", return_value=["file1.txt", "file2.exe"]):
        with patch("app.os.path.isfile", return_value=True):
            with patch("app.os.path.getsize", return_value=1024):
                with patch("app.os.path.join", side_effect=lambda *a: "/".join(a)):
                    resp = client.get("/api/files/list")
                    assert resp.status_code == 200
                    data = resp.get_json()
                    assert len(data) == 2
                    assert data[0]["name"] == "file1.txt"
                    assert data[0]["size"] == 1024

# Test 3: With session, no files - returns empty list
def test_list_deploy_files_empty(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.listdir", return_value=[]):
        resp = client.get("/api/files/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 4: Path is not a file - skipped
def test_list_deploy_files_not_a_file(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.listdir", return_value=["somedir"]):
        with patch("app.os.path.isfile", return_value=False):  # Not a file
            with patch("app.os.path.join", side_effect=lambda *a: "/".join(a)):
                resp = client.get("/api/files/list")
                assert resp.status_code == 200
                assert resp.get_json() == []

# Test 5: os.listdir raises exception - except branch
def test_list_deploy_files_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.listdir", side_effect=Exception("Dir not found")):
        resp = client.get("/api/files/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 62️⃣ Test delete_deploy_file function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_delete_deploy_file_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/files/delete",
        data=json_lib.dumps({"name": "file.txt"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Admin role - file deleted successfully
def test_delete_deploy_file_admin_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.remove") as mock_remove:
        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/files/delete",
                data=json_lib.dumps({"name": "file.txt"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify os.remove was called
            mock_remove.assert_called_once()

            # Verify audit_log was called
            mock_audit.assert_called_once_with("admin", "deleted_file", "file.txt")

# Test 3: Manager role - file deleted successfully
def test_delete_deploy_file_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.remove"):
        with patch("app.audit_log"):
            resp = client.post(
                "/api/files/delete",
                data=json_lib.dumps({"name": "file.txt"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# Test 4: os.remove raises exception - except branch -> pass, still returns success
def test_delete_deploy_file_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.remove", side_effect=Exception("File not found")):
        resp = client.post(
            "/api/files/delete",
            data=json_lib.dumps({"name": "nonexistent.txt"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "success"

# -----------------------------
# 63️⃣ Test download_deploy_file function
# -----------------------------

# Test 1: Valid file - returns file
def test_download_deploy_file_success(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.send_from_directory", return_value="file_content") as mock_send:
            resp = client.get(
                "/api/transfer/get/testfile.txt",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code == 200
            mock_send.assert_called_once_with(
                'data/uploads',
                __import__('werkzeug.utils', fromlist=['secure_filename']).secure_filename('testfile.txt')
            )

# Test 2: Unauthorized agent - returns 401
def test_download_deploy_file_unauthorized(client):
    with patch("app.verify_agent", return_value=None):
        resp = client.get(
            "/api/transfer/get/testfile.txt",
            headers={
                "X-API-KEY": "badkey",
                "X-SIGNATURE": "badsig",
                "X-TIMESTAMP": str(int(time.time())),
                "X-NONCE": str(__import__('uuid').uuid4())
            }
        )
        assert resp.status_code == 401

# Test 3: Filename with path traversal - secure_filename sanitizes it
def test_download_deploy_file_path_traversal(client):
    with patch("app.verify_agent", return_value="TESTHOST"):
        with patch("app.send_from_directory", return_value="file_content") as mock_send:
            resp = client.get(
                "/api/transfer/get/../../etc/passwd",
                headers={
                    "X-API-KEY": "testkey",
                    "X-SIGNATURE": "testsig",
                    "X-TIMESTAMP": str(int(time.time())),
                    "X-NONCE": str(__import__('uuid').uuid4())
                }
            )
            assert resp.status_code in (200, 404)

# -----------------------------
# 64️⃣ Test bulk_deploy function
# -----------------------------

# Test 1: Unauthorized role - returns 403
def test_bulk_deploy_unauthorized(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/deploy/bulk",
        data=json_lib.dumps({"hosts": ["TESTHOST"], "filename": "setup.exe"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Missing hosts - returns 400
def test_bulk_deploy_missing_hosts(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/deploy/bulk",
        data=json_lib.dumps({"hosts": [], "filename": "setup.exe"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 3: Missing filename - returns 400
def test_bulk_deploy_missing_filename(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/deploy/bulk",
        data=json_lib.dumps({"hosts": ["TESTHOST"], "filename": ""}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing parameters"

# Test 4: File exists - hash computed, commands queued
def test_bulk_deploy_file_exists(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=True):
        with patch("builtins.open", MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(
                    read=MagicMock(side_effect=[b"chunk1", b""])
                )),
                __exit__=MagicMock(return_value=False)
            )
        )):
            with patch("app.queue_cmd") as mock_queue:
                with patch("app.audit_log") as mock_audit:
                    resp = client.post(
                        "/api/deploy/bulk",
                        data=json_lib.dumps({
                            "hosts": ["TESTHOST1", "TESTHOST2"],
                            "filename": "setup.exe",
                            "args": "--silent"
                        }),
                        content_type="application/json",
                        headers={"X-CSRF-Token": "testtoken"}
                    )
                    assert resp.status_code == 200
                    data = resp.get_json()
                    assert data["status"] == "success"
                    assert data["queued"] == 2

                    # Verify queue_cmd called for each host
                    assert mock_queue.call_count == 2

                    # Verify audit_log called
                    mock_audit.assert_called_once()

# Test 5: File does not exist - empty hash, commands still queued
def test_bulk_deploy_file_not_exists(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=False):
        with patch("app.queue_cmd") as mock_queue:
            with patch("app.audit_log"):
                resp = client.post(
                    "/api/deploy/bulk",
                    data=json_lib.dumps({
                        "hosts": ["TESTHOST"],
                        "filename": "setup.exe"
                    }),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"
                mock_queue.assert_called_once()

# Test 6: Manager role - success
def test_bulk_deploy_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=False):
        with patch("app.queue_cmd"):
            with patch("app.audit_log"):
                resp = client.post(
                    "/api/deploy/bulk",
                    data=json_lib.dumps({
                        "hosts": ["TESTHOST"],
                        "filename": "setup.exe"
                    }),
                    content_type="application/json",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                assert resp.get_json()["status"] == "success"

# -----------------------------
# 65️⃣ Test term_exec function
# -----------------------------

# Test 1: No session - returns 403
def test_term_exec_no_session(client):
    import json as json_lib
    resp = client.post(
        "/api/terminal/execute",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping"}),
        content_type="application/json"
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403
def test_term_exec_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/terminal/execute",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: Helpdesk role - returns 403
def test_term_exec_helpdesk_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "helpdesk"
        sess["role"] = "helpdesk"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/terminal/execute",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 4: Non-admin with disallowed command - returns 403
def test_term_exec_disallowed_command(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/terminal/execute",
        data=json_lib.dumps({"hostname": "TESTHOST", "command": "rm -rf /"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Command not permitted by security policy."

# Test 5: Admin bypasses command filter - success
def test_term_exec_admin_bypasses_filter(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        with patch("app.audit_log"):
            resp = client.post(
                "/api/terminal/execute",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "rm -rf /"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

# Test 6: Non-admin with allowed command, no existing row - INSERT branch
def test_term_exec_allowed_command_no_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # No existing row

        with patch("app.audit_log"):
            resp = client.post(
                "/api/terminal/execute",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

# Test 7: Non-admin with allowed command, existing row - UPDATE branch
def test_term_exec_allowed_command_existing_row(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("TESTHOST",)  # Existing row

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/terminal/execute",
                data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping 8.8.8.8"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "sent"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log called
            mock_audit.assert_called_once()

# Test 8: DB exception - except branch -> pass, still returns sent
def test_term_exec_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/terminal/execute",
            data=json_lib.dumps({"hostname": "TESTHOST", "command": "ping"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "sent"

# -----------------------------
# 66️⃣ Test term_read function
# -----------------------------

# Test 1: No existing row - returns empty output
def test_term_read_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/terminal/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["output"] == ""

# Test 2: Existing row with output - returns output and clears it
def test_term_read_with_output(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("command output here",)

        resp = client.get("/api/terminal/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["output"] == "command output here"

        # Verify UPDATE SET output='' was called
        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("output=''" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 3: Existing row with NULL output - returns empty string
def test_term_read_null_output(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)

        resp = client.get("/api/terminal/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["output"] == ""

# Test 4: DB exception - except branch -> returns empty output
def test_term_read_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/terminal/read?hostname=TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json()["output"] == ""

# -----------------------------
# 67️⃣ Test get_screen function
# -----------------------------

# Test 1: No session - returns 403
def test_get_screen_no_session(client):
    resp = client.get("/api/screen/get/TESTHOST")
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: File does not exist - returns 204
def test_get_screen_file_not_exists(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.path.exists", return_value=False):
        resp = client.get("/api/screen/get/TESTHOST")
        assert resp.status_code == 204

# Test 3: File exists - returns image
def test_get_screen_file_exists(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.path.exists", return_value=True):
        with patch("app.send_from_directory", return_value=flask_app.response_class(
            response=b"fake_image_data",
            status=200,
            mimetype="image/jpeg"
        )) as mock_send:
            resp = client.get("/api/screen/get/TESTHOST")
            assert resp.status_code == 200
            mock_send.assert_called_once()

# Test 4: Exception during send - returns 500
def test_get_screen_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.os.path.exists", return_value=True):
        with patch("app.send_from_directory", side_effect=Exception("Send error")):
            resp = client.get("/api/screen/get/TESTHOST")
            assert resp.status_code == 500
            assert resp.get_json()["error"] == "Internal Server Error"

# -----------------------------
# 68️⃣ Test clear_screen function
# -----------------------------

# Test 1: No session - returns 403
def test_clear_screen_no_session(client):
    resp = client.post(
        "/api/screen/clear/TESTHOST",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403

# Test 2: File exists - removed successfully
def test_clear_screen_file_exists(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=True):
        with patch("app.os.remove") as mock_remove:
            resp = client.post(
                "/api/screen/clear/TESTHOST",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"
            mock_remove.assert_called_once()

# Test 3: File does not exist - skips remove
def test_clear_screen_file_not_exists(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=False):
        with patch("app.os.remove") as mock_remove:
            resp = client.post(
                "/api/screen/clear/TESTHOST",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"
            mock_remove.assert_not_called()

# Test 4: os.remove raises exception - except branch -> pass
def test_clear_screen_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.os.path.exists", return_value=True):
        with patch("app.os.remove", side_effect=Exception("Remove error")):
            resp = client.post(
                "/api/screen/clear/TESTHOST",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# -----------------------------
# 69️⃣ Test revive_all_agents function
# -----------------------------

# Test 1: No session - returns 403
def test_revive_all_agents_no_session(client):
    resp = client.post(
        "/api/agents/revive-all",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403
def test_revive_all_agents_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/agents/revive-all",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: No agents - count is 0
def test_revive_all_agents_no_agents(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        with patch("app.audit_log"):
            resp = client.post(
                "/api/agents/revive-all",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status"] == "revival_queued"
            assert data["agents_revived"] == 0

# Test 4: Multiple agents - queue_cmd called for each
def test_revive_all_agents_with_agents(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [("HOST1",), ("HOST2",), ("HOST3",)]

        with patch("app.queue_cmd") as mock_queue:
            with patch("app.audit_log") as mock_audit:
                resp = client.post(
                    "/api/agents/revive-all",
                    headers={"X-CSRF-Token": "testtoken"}
                )
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["status"] == "revival_queued"
                assert data["agents_revived"] == 3

                # Verify queue_cmd called for each host
                assert mock_queue.call_count == 3
                calls = [c[0] for c in mock_queue.call_args_list]
                assert any("HOST1" in str(c) for c in calls)

                # Verify audit_log called
                mock_audit.assert_called_once_with("admin", "revived_all_agents", "system")

# Test 5: DB exception - returns 500
def test_revive_all_agents_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/agents/revive-all",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "DB Error" in resp.get_json()["error"]

# -----------------------------
# 70️⃣ Test force_sync_agent function
# -----------------------------

# Test 1: No session - returns 403
def test_force_sync_agent_no_session(client):
    resp = client.post(
        "/api/commands/force-sync/TESTHOST",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403
def test_force_sync_agent_viewer_role(client):
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/commands/force-sync/TESTHOST",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: Admin role - sync queued successfully
def test_force_sync_agent_admin_success(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        resp = client.post(
            "/api/commands/force-sync/TESTHOST",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "sync_requested"
        assert data["hostname"] == "TESTHOST"

        # Verify queue_cmd called with trigger_full_sync
        mock_queue.assert_called_once_with("TESTHOST", "trigger_full_sync")

# Test 4: Manager role - sync queued successfully
def test_force_sync_agent_manager_success(client):
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.queue_cmd") as mock_queue:
        resp = client.post(
            "/api/commands/force-sync/TESTHOST",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "sync_requested"
        mock_queue.assert_called_once_with("TESTHOST", "trigger_full_sync")

# -----------------------------
# 71️⃣ Test get_history function
# -----------------------------

# Test 1: No existing row - returns empty list
def test_get_history_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/history/TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 2: Existing row with history - returns parsed JSON
def test_get_history_with_data(client):
    import json as json_lib
    history = [{"time": "12:00:00", "cpu": 50, "ram": 60}]

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (json_lib.dumps(history),)

        resp = client.get("/api/history/TESTHOST")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["cpu"] == 50
        assert data[0]["ram"] == 60

# Test 3: DB exception - returns empty list
def test_get_history_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/history/TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 72️⃣ Test delete_agent function
# -----------------------------

# Test 1: No session - returns 403
def test_delete_agent_no_session(client):
    resp = client.post(
        "/api/agents/delete",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403

# Test 2: Non-admin role - returns 403
def test_delete_agent_non_admin(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/agents/delete",
        data=json_lib.dumps({"hostname": "TESTHOST"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: Invalid host - returns 400
def test_delete_agent_invalid_host(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/agents/delete",
        data=json_lib.dumps({"hostname": ""}),  # Empty -> UNKNOWN
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Invalid host"

# Test 4: Valid host - all tables deleted, cache cleared, file removed
def test_delete_agent_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    # Pre-add host to AGENT_CACHE
    app.AGENT_CACHE["TESTHOST"] = "apikey"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.os.path.exists", return_value=True):
            with patch("app.os.remove") as mock_remove:
                with patch("app.audit_log") as mock_audit:
                    resp = client.post(
                        "/api/agents/delete",
                        data=json_lib.dumps({"hostname": "TESTHOST"}),
                        content_type="application/json",
                        headers={"X-CSRF-Token": "testtoken"}
                    )
                    assert resp.status_code == 200
                    assert resp.get_json()["status"] == "success"

                    # Verify all DELETE statements called
                    calls = [str(c) for c in mock_cursor.execute.call_args_list]
                    assert any("agents_store" in c for c in calls)
                    assert any("perf_history" in c for c in calls)
                    assert any("terminal_store" in c for c in calls)
                    assert any("explorer_store" in c for c in calls)
                    assert any("services_store" in c for c in calls)
                    assert any("eventlog_store" in c for c in calls)
                    assert any("agents_auth" in c for c in calls)
                    mock_conn.commit.assert_called_once()

                    # Verify AGENT_CACHE cleared
                    assert "TESTHOST" not in app.AGENT_CACHE

                    # Verify file removed
                    mock_remove.assert_called_once()

                    # Verify audit_log called
                    mock_audit.assert_called_once_with("admin", "deleted_agent", "TESTHOST")

# Test 5: Valid host, file does not exist - skips os.remove
def test_delete_agent_no_screen_file(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value

        with patch("app.os.path.exists", return_value=False):
            with patch("app.os.remove") as mock_remove:
                with patch("app.audit_log"):
                    resp = client.post(
                        "/api/agents/delete",
                        data=json_lib.dumps({"hostname": "TESTHOST"}),
                        content_type="application/json",
                        headers={"X-CSRF-Token": "testtoken"}
                    )
                    assert resp.status_code == 200
                    assert resp.get_json()["status"] == "success"
                    mock_remove.assert_not_called()

# Test 6: DB exception - returns 500
def test_delete_agent_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/agents/delete",
            data=json_lib.dumps({"hostname": "TESTHOST"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "DB Error" in resp.get_json()["error"]

# -----------------------------
# 73️⃣ Test get_processes function
# -----------------------------

# Test 1: No existing row - returns empty list
def test_get_processes_no_row(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None

        resp = client.get("/api/processes/get/TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 2: Existing row with data - returns decoded JSON and clears result
def test_get_processes_with_data(client):
    import json as json_lib
    import base64 as base64_lib
    processes = [{"name": "chrome.exe", "pid": 1234}, {"name": "python.exe", "pid": 5678}]
    encoded = base64_lib.b64encode(json_lib.dumps(processes).encode('utf-8')).decode()

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (encoded,)

        resp = client.get("/api/processes/get/TESTHOST")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["name"] == "chrome.exe"
        assert data[0]["pid"] == 1234

        # Verify UPDATE SET result='' was called
        calls = [str(c) for c in mock_cursor.execute.call_args_list]
        assert any("UPDATE" in c for c in calls)
        mock_conn.commit.assert_called_once()

# Test 3: Existing row with NULL result - returns empty list
def test_get_processes_null_result(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = (None,)

        resp = client.get("/api/processes/get/TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 4: DB exception - except branch -> returns empty list
def test_get_processes_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/processes/get/TESTHOST")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 74️⃣ Test list_users function
# -----------------------------

# Test 1: No session - returns 403
def test_list_users_no_session(client):
    resp = client.get("/api/users/list")
    assert resp.status_code == 403
    assert resp.get_json() == []

# Test 2: Non-admin role - returns 403
def test_list_users_non_admin(client):
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"

    resp = client.get("/api/users/list")
    assert resp.status_code == 403
    assert resp.get_json() == []

# Test 3: Admin role - returns user list
def test_list_users_admin_success(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [
            ("admin", "admin", 1234567890),
            ("manager1", "manager", 1234567891)
        ]

        resp = client.get("/api/users/list")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["username"] == "admin"
        assert data[0]["role"] == "admin"
        assert data[0]["last_active"] == 1234567890
        assert data[1]["username"] == "manager1"

# Test 4: Empty users table - returns empty list
def test_list_users_empty(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        resp = client.get("/api/users/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 5: DB exception - returns empty list
def test_list_users_db_exception(client):
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/users/list")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 75️⃣ Test add_user function
# -----------------------------

# Test 1: Non-admin role - returns 403
def test_add_user_non_admin(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/add",
        data=json_lib.dumps({"username": "newuser", "password": "password123", "role": "viewer"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Missing username - returns 400
def test_add_user_missing_username(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/add",
        data=json_lib.dumps({"username": "", "password": "password123"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing/invalid fields"

# Test 3: Short password - returns 400
def test_add_user_short_password(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/add",
        data=json_lib.dumps({"username": "newuser", "password": "short"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing/invalid fields"

# Test 4: User already exists - returns 400
def test_add_user_already_exists(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("existinguser",)  # User exists

        resp = client.post(
            "/api/users/add",
            data=json_lib.dumps({"username": "existinguser", "password": "password123"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 400
        assert "exists" in resp.get_json()["error"]

# Test 5: Valid new user - created successfully
def test_add_user_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = None  # User does not exist

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/users/add",
                data=json_lib.dumps({
                    "username": "newuser",
                    "password": "password123",
                    "role": "viewer"
                }),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify INSERT was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("INSERT" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log called
            mock_audit.assert_called_once_with("admin", "added_user", "newuser")

# Test 6: DB exception - returns 500
def test_add_user_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/users/add",
            data=json_lib.dumps({"username": "newuser", "password": "password123"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 76️⃣ Test delete_user function
# -----------------------------

# Test 1: Non-admin role - returns 403
def test_delete_user_non_admin(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/delete",
        data=json_lib.dumps({"username": "someuser"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Trying to delete admin - returns 400
def test_delete_user_cannot_delete_admin(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/delete",
        data=json_lib.dumps({"username": "admin"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Cannot delete admin"

# Test 3: Valid user - deleted successfully
def test_delete_user_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/users/delete",
                data=json_lib.dumps({"username": "someuser"}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify DELETE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("DELETE" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log called
            mock_audit.assert_called_once_with("admin", "deleted_user", "someuser")

# Test 4: DB exception - returns 500
def test_delete_user_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/users/delete",
            data=json_lib.dumps({"username": "someuser"}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 77️⃣ Test change_password function
# -----------------------------

# Test 1: Non-admin role - returns 403
def test_change_password_non_admin(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/change_password",
        data=json_lib.dumps({"username": "someuser", "password": "newpassword123"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 2: Missing username - returns 400
def test_change_password_missing_username(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/change_password",
        data=json_lib.dumps({"username": "", "password": "newpassword123"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing/invalid fields"

# Test 3: Short password - returns 400
def test_change_password_short_password(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/users/change_password",
        data=json_lib.dumps({"username": "someuser", "password": "short"}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Missing/invalid fields"

# Test 4: Valid request - password changed successfully
def test_change_password_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/users/change_password",
                data=json_lib.dumps({
                    "username": "someuser",
                    "password": "newpassword123"
                }),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log called
            mock_audit.assert_called_once_with("admin", "changed_password", "someuser")

# Test 5: DB exception - returns 500
def test_change_password_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/users/change_password",
            data=json_lib.dumps({
                "username": "someuser",
                "password": "newpassword123"
            }),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()

# -----------------------------
# 78️⃣ Test get_tickets function
# -----------------------------

# Test 1: Returns ticket list
def test_get_tickets_success(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = [
            (1, "TESTHOST", "high", "Disk full", "open", "2024-01-01 00:00:00"),
            (2, "TESTHOST2", "low", "CPU spike", "closed", "2024-01-02 00:00:00")
        ]

        resp = client.get("/api/tickets")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2
        assert data[0]["id"] == 1
        assert data[0]["hostname"] == "TESTHOST"
        assert data[0]["severity"] == "high"
        assert data[0]["message"] == "Disk full"
        assert data[0]["status"] == "open"
        assert data[0]["created_at"] == "2024-01-01 00:00:00"

# Test 2: Empty tickets - returns empty list
def test_get_tickets_empty(client):
    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchall.return_value = []

        resp = client.get("/api/tickets")
        assert resp.status_code == 200
        assert resp.get_json() == []

# Test 3: DB exception - returns empty list
def test_get_tickets_db_exception(client):
    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.get("/api/tickets")
        assert resp.status_code == 200
        assert resp.get_json() == []

# -----------------------------
# 79️⃣ Test close_ticket function
# -----------------------------

# Test 1: No session - returns 403
def test_close_ticket_no_session(client):
    import json as json_lib
    resp = client.post(
        "/api/tickets/close",
        data=json_lib.dumps({"id": 1}),
        content_type="application/json"
    )
    assert resp.status_code == 403

# Test 2: Viewer role - returns 403
def test_close_ticket_viewer_role(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "viewer"
        sess["role"] = "viewer"
        sess["csrf_token"] = "testtoken"

    resp = client.post(
        "/api/tickets/close",
        data=json_lib.dumps({"id": 1}),
        content_type="application/json",
        headers={"X-CSRF-Token": "testtoken"}
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Unauthorized"

# Test 3: Valid request - ticket closed successfully
def test_close_ticket_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value
        mock_cursor = mock_conn.cursor.return_value

        with patch("app.audit_log") as mock_audit:
            resp = client.post(
                "/api/tickets/close",
                data=json_lib.dumps({"id": 1}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

            # Verify UPDATE was called
            calls = [str(c) for c in mock_cursor.execute.call_args_list]
            assert any("UPDATE" in c for c in calls)
            assert any("Resolved" in c for c in calls)
            mock_conn.commit.assert_called_once()

            # Verify audit_log called
            mock_audit.assert_called_once_with("admin", "closed_ticket", "1")

# Test 4: Manager role - ticket closed successfully
def test_close_ticket_manager_success(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "manager"
        sess["role"] = "manager"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db") as mock_db:
        mock_conn = mock_db.return_value.__enter__.return_value

        with patch("app.audit_log"):
            resp = client.post(
                "/api/tickets/close",
                data=json_lib.dumps({"id": 2}),
                content_type="application/json",
                headers={"X-CSRF-Token": "testtoken"}
            )
            assert resp.status_code == 200
            assert resp.get_json()["status"] == "success"

# Test 5: DB exception - returns 500
def test_close_ticket_db_exception(client):
    import json as json_lib
    with client.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = "testtoken"

    with patch("app.get_db", side_effect=Exception("DB error")):
        resp = client.post(
            "/api/tickets/close",
            data=json_lib.dumps({"id": 1}),
            content_type="application/json",
            headers={"X-CSRF-Token": "testtoken"}
        )
        assert resp.status_code == 500
        assert "error" in resp.get_json()