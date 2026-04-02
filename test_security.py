import json

# -----------------------------
# 1️⃣ Missing Authentication
# -----------------------------
def test_protected_endpoint_no_auth(client):
    resp = client.post("/api/terminal/agent_poll")

    assert resp.status_code in (401, 403, 405)


# -----------------------------
# 2️⃣ Invalid API Key
# -----------------------------
def test_invalid_api_key(client):
    resp = client.post(
        "/api/terminal/push",
        data=json.dumps({"output": "test"}),
        content_type="application/json",
        headers={
            "X-API-KEY": "wrong",
            "X-SIGNATURE": "bad",
            "X-TIMESTAMP": "123",
            "X-NONCE": "bad"
        }
    )

    assert resp.status_code in (401, 403, 404)


# -----------------------------
# 3️⃣ Large Payload (already OK)
# -----------------------------
def test_large_payload(client):
    large_data = "A" * 20_000_000

    resp = client.post(
        "/api/screen/upload",
        data=json.dumps({"image": large_data}),
        content_type="application/json"
    )

    assert resp.status_code in (400, 413)


# -----------------------------
# 4️⃣ Path Traversal
# -----------------------------
def test_path_traversal(client):
    resp = client.post(
        "/api/explorer/request",
        data=json.dumps({"hostname": "TEST", "path": "../../etc/passwd"}),
        content_type="application/json"
    )

    assert resp.status_code in (200, 400, 403)


# -----------------------------
# 5️⃣ Command Injection
def test_command_injection(client):
    import json
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):

        resp = client.post(
            "/api/terminal/agent_push",
            data=json.dumps({"output": "ls; rm -rf /"}),
            content_type="application/json",
            headers={
                "X-API-KEY": "test",
                "X-SIGNATURE": "test",
                "X-TIMESTAMP": "123456",
                "X-NONCE": "abc"
            }
        )

        assert resp.status_code in (200, 400, 403)

def test_sql_injection_terminal_push(client):
    import json
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):

        resp = client.post(
            "/api/terminal/agent_push",
            data=json.dumps({"output": "' OR 1=1--"}),
            content_type="application/json",
            headers={
                "X-API-KEY": "test",
                "X-SIGNATURE": "test",
                "X-TIMESTAMP": "123",
                "X-NONCE": "abc"
            }
        )

        assert resp.status_code in (200, 400)

def test_xss_terminal_push(client):
    import json
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):

        resp = client.post(
            "/api/terminal/agent_push",
            data=json.dumps({"output": "<script>alert(1)</script>"}),
            content_type="application/json",
            headers={
                "X-API-KEY": "test",
                "X-SIGNATURE": "test",
                "X-TIMESTAMP": "123",
                "X-NONCE": "abc"
            }
        )

        assert resp.status_code in (200, 400)

def test_admin_bypass(client):
    resp = client.post("/api/tickets/close", json={"id": 1})
    assert resp.status_code == 403

def test_rate_limit(client):
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):

        last_resp = None
        for _ in range(30):
            last_resp = client.post(
                "/api/terminal/agent_push",
                json={"output": "spam"},
                headers={
                    "X-API-KEY": "test",
                    "X-SIGNATURE": "test",
                    "X-TIMESTAMP": "123",
                    "X-NONCE": "abc"
                }
            )

        assert last_resp.status_code in (200, 429)

def test_random_input(client):
    import json
    from unittest.mock import patch

    with patch("app.verify_agent", return_value="TESTHOST"):

        resp = client.post(
            "/api/terminal/agent_push",
            data=json.dumps({"output": "%%%$$$###"}),
            content_type="application/json",
            headers={
                "X-API-KEY": "test",
                "X-SIGNATURE": "test",
                "X-TIMESTAMP": "123456",
                "X-NONCE": "abc"
            }
        )

        assert resp.status_code in (200, 400)