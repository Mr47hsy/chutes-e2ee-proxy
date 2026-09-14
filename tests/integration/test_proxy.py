"""
Integration tests: real proxy container against tests/integration/mock_upstream.py.

Environment
  PROXY_URL           proxy running with defaults + API_BASE/MODELS_BASE -> mock
                      (default https://127.0.0.1:8443)
  PROXY_ENFORCE_URL   optional second proxy started with E2EE_ATTEST=enforce and
                      E2EE_ATTEST_TTL=1 (attestation rejection tests)
  PROXY_SMALL_BODY_URL optional proxy started with MAX_BODY_SIZE=1m (413 test)
  MOCK_URL            mock upstream control endpoint (default http://127.0.0.1:9100)

Run:  pytest -q tests/integration/test_proxy.py
"""
import json
import os
import re

import httpx
import pytest

PROXY = os.environ.get("PROXY_URL", "https://127.0.0.1:8443").rstrip("/")
PROXY_ENFORCE = os.environ.get("PROXY_ENFORCE_URL", "").rstrip("/")
PROXY_SMALL = os.environ.get("PROXY_SMALL_BODY_URL", "").rstrip("/")
MOCK = os.environ.get("MOCK_URL", "http://127.0.0.1:9100").rstrip("/")
KEY = "cpk_integration_test_key"
MODEL = "mock/TEE-model"
MODEL_B = "mock/TEE-model-b"  # separate chutes -> fresh routing state in the proxy
MODEL_C = "mock/TEE-model-c"
HDRS = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}


def client(base=PROXY, **kw):
    return httpx.Client(base_url=base, verify=False, timeout=30, **kw)


def mock_stats():
    return httpx.get(MOCK + "/_mock/stats", timeout=10).json()


def mock_config(**cfg):
    assert httpx.post(MOCK + "/_mock/config", json=cfg, timeout=10).status_code == 200


def mock_reset():
    assert httpx.post(MOCK + "/_mock/reset", timeout=10).status_code == 200


@pytest.fixture(autouse=True)
def _reset():
    mock_reset()
    yield


def chat(c, content="hello", stream=False, mode=None, model=MODEL, **extra):
    headers = dict(HDRS)
    if mode:
        headers["X-Route-Mode"] = mode
    body = {"model": model, "messages": [{"role": "user", "content": content}], "stream": stream}
    body.update(extra)
    return c.post("/v1/chat/completions", headers=headers, json=body)


# ---------------------------------------------------------------------------
# basics
# ---------------------------------------------------------------------------

def test_health():
    with client() as c:
        r = c.get("/health")
        assert r.status_code == 200
        j = r.json()
        assert j["status"] == "ok"
        assert "FIPS 203" in j["native"]
        assert "X-Request-Id" in r.headers


def test_models_passthrough():
    with client() as c:
        r = c.get("/v1/models", headers=HDRS)
        assert r.status_code == 200
        assert any(m["id"] == MODEL for m in r.json()["data"])
        # upstream's wildcard CORS must not leak; no Origin -> no ACAO at all
        assert "access-control-allow-origin" not in r.headers


def test_chat_non_streaming_round_trip():
    with client() as c:
        r = chat(c, "ping 123")
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["choices"][0]["message"]["content"].endswith("ping 123")
        assert j["usage"]["prompt_tokens"] > 0
        assert r.headers["X-E2EE-Instance-Id"].startswith("inst-")
        assert r.headers["X-E2EE-Route-Mode"] in ("agent", "balanced", "performance", "default")
        assert re.fullmatch(r"[0-9a-f]{32}", r.headers["X-Request-Id"])
    s = mock_stats()
    assert s["invoke"] == 1
    assert s["paths"].get("/v1/chat/completions") == 1


def test_request_id_is_echoed_when_supplied():
    with client() as c:
        r = c.get("/health", headers={"X-Request-Id": "my-trace-42"})
        assert r.headers["X-Request-Id"] == "my-trace-42"
        r = c.get("/health", headers={"X-Request-Id": "bad id with spaces"})
        assert r.headers["X-Request-Id"] != "bad id with spaces"


def test_chat_streaming_round_trip():
    with client() as c:
        with c.stream("POST", "/v1/chat/completions", headers=HDRS,
                      json={"model": MODEL, "messages": [{"role": "user", "content": "stream me"}], "stream": True}) as r:
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")
            lines = [ln for ln in r.iter_lines() if ln.startswith("data: ")]
    assert lines[-1] == "data: [DONE]"
    text = ""
    saw_usage = False
    for ln in lines[:-1]:
        ev = json.loads(ln[6:])
        assert "e2e" not in ev and "e2e_init" not in ev, "encrypted event leaked to client"
        delta = ev["choices"][0]["delta"]
        text += delta.get("content", "")
        if ev.get("usage"):
            saw_usage = True
    assert text.endswith("stream me")
    assert saw_usage


def test_claude_messages_api():
    with client() as c:
        r = c.post("/v1/messages", headers={"x-api-key": KEY, "anthropic-version": "2023-06-01"},
                   json={"model": MODEL, "max_tokens": 32, "messages": [{"role": "user", "content": "claude hi"}]})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["type"] == "message"
        assert j["content"][0]["text"].endswith("claude hi")
        with c.stream("POST", "/v1/messages", headers={"x-api-key": KEY},
                      json={"model": MODEL, "max_tokens": 32, "stream": True,
                            "messages": [{"role": "user", "content": "claude stream"}]}) as r:
            assert r.status_code == 200
            events = [ln for ln in r.iter_lines() if ln.startswith("event: ")]
    assert "event: message_start" in events
    assert "event: message_stop" in events


def test_responses_api():
    with client() as c:
        r = c.post("/v1/responses", headers=HDRS, json={"model": MODEL, "input": "responses hi"})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["object"] == "response"


def test_non_confidential_model_rejected_by_default():
    with client() as c:
        r = chat(c, model="mock/plain-model")
        assert r.status_code == 404
        assert "confidential compute" in r.json()["error"]["message"]


def test_missing_auth():
    with client() as c:
        r = c.post("/v1/chat/completions", json={"model": MODEL, "messages": []})
        assert r.status_code == 401


def test_cors_allowlist():
    with client() as c:
        r = c.options("/v1/chat/completions", headers={"Origin": "http://localhost:3000",
                                                       "Access-Control-Request-Method": "POST"})
        assert r.status_code == 204
        assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
        assert "X-Route-Mode" in r.headers["access-control-allow-headers"]
        r = c.options("/v1/chat/completions", headers={"Origin": "https://evil.example",
                                                       "Access-Control-Request-Method": "POST"})
        assert r.status_code == 204
        assert "access-control-allow-origin" not in r.headers
        r = c.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in r.headers


def test_404_json():
    with client() as c:
        r = c.get("/nope")
        assert r.status_code == 404
        assert r.json()["error"]["type"] == "proxy_error"


# ---------------------------------------------------------------------------
# routing modes
# ---------------------------------------------------------------------------

def instances_used(c, n, mode, content="affinity", model=MODEL):
    used = []
    for i in range(n):
        r = chat(c, f"{content} {i}", mode=mode, model=model)
        assert r.status_code == 200, r.text
        used.append(r.headers["X-E2EE-Instance-Id"])
    return used


def test_agent_mode_sticks_to_one_instance():
    with client() as c:
        used = instances_used(c, 8, "agent")
    assert len(set(used)) == 1, used


def test_balanced_mode_rotates_over_three():
    # Uses MODEL_B: the proxy keeps routing state per chute, and earlier tests
    # on MODEL may have exhausted one instance's 10-nonce batch (an exhausted
    # ring member is skipped, not evicted), which would break strict rotation.
    with client() as c:
        used = instances_used(c, 9, "balanced", model=MODEL_B)
    assert len(set(used)) == 3, used
    # strict round robin over the same three
    assert used[0:3] == used[3:6] == used[6:9], used


def test_balanced_mode_skips_exhausted_member_without_evicting():
    # Fresh chute (MODEL_C): 5 instances x 10 nonces per batch.
    #   3 balanced picks -> ring = 3 members, 9 nonces left each
    #   9 agent picks    -> agent sticks to the ring member with the lowest
    #                       TTFT EWMA and drains exactly its 9 remaining nonces
    #   6 balanced picks -> must alternate over the other two members, with no
    #                       nonce refresh and no fourth instance pulled in
    with client() as c:
        ring = instances_used(c, 3, "balanced", model=MODEL_C)
        assert len(set(ring)) == 3
        sticky = chat(c, mode="agent", model=MODEL_C).headers["X-E2EE-Instance-Id"]
        assert sticky in ring, "agent picks a warm ring member over cold instances"
        for _ in range(8):
            r = chat(c, mode="agent", model=MODEL_C)
            assert r.status_code == 200
            assert r.headers["X-E2EE-Instance-Id"] == sticky
        fetches_before = mock_stats()["instances_calls"]
        used = instances_used(c, 6, "balanced", model=MODEL_C)
        fetches_after = mock_stats()["instances_calls"]
    assert set(used) <= set(ring), (used, ring)
    assert sticky not in used, "exhausted member must be skipped until nonces refresh"
    assert len(set(used)) == 2 and used[0:2] == used[2:4] == used[4:6], used
    assert fetches_after == fetches_before, "no nonce refresh while other members still have nonces"


def test_performance_and_default_modes_serve_requests():
    with client() as c:
        for mode in ("performance", "default"):
            used = instances_used(c, 4, mode)
            assert all(u.startswith("inst-") for u in used)
            r = chat(c, mode=mode)
            assert r.headers["X-E2EE-Route-Mode"] == mode


def test_unknown_route_mode_falls_back_to_default_mode():
    with client() as c:
        r = chat(c, mode="bogus")
        assert r.status_code == 200
        assert r.headers["X-E2EE-Route-Mode"] != "bogus"


def test_nonce_rejection_triggers_retry_on_another_instance():
    with client() as c:
        first = chat(c, mode="agent").headers["X-E2EE-Instance-Id"]
        mock_config(reject_next_nonce=True)
        r = chat(c, mode="agent")
        assert r.status_code == 200, r.text
        assert r.headers["X-E2EE-Instance-Id"] != first, "retry must fail over to a different instance"
    s = mock_stats()
    assert s["nonce_rejects"] == 1
    assert s["invoke"] == 3  # 1 ok + 1 rejected + 1 retry


def test_down_instance_is_abandoned_on_next_request():
    with client() as c:
        first = chat(c, mode="agent").headers["X-E2EE-Instance-Id"]
        mock_config(down=[first])
        r = chat(c, mode="agent")
        assert r.status_code == 502  # passthrough of the upstream error
        r = chat(c, mode="agent")
        assert r.status_code == 200
        assert r.headers["X-E2EE-Instance-Id"] != first


# ---------------------------------------------------------------------------
# attestation
# ---------------------------------------------------------------------------

def test_observe_mode_verifies_and_allows():
    with client() as c:
        assert chat(c).status_code == 200
        m = c.get("/metrics").text
    s = mock_stats()
    assert s["attest_calls_total"] >= 1, "proxy must fetch attestation even in observe mode"
    assert 'e2ee_attestation_total{result="ok"}' in m or 'e2ee_attestation_total{result="cached"}' in m


@pytest.mark.skipif(not PROXY_ENFORCE, reason="PROXY_ENFORCE_URL not set")
def test_enforce_rejects_key_substitution():
    with client(PROXY_ENFORCE) as c:
        r = chat(c, "enforce ok")
        assert r.status_code == 200, r.text
        mock_config(attest_all_bad=True)
        import time
        time.sleep(1.5)  # E2EE_ATTEST_TTL=1 on the enforce proxy
        r = chat(c, "enforce bad")
        assert r.status_code == 502, r.text
        assert "attestation failed" in r.json()["error"]["message"].lower()
        mock_config(attest_all_bad=False)
        time.sleep(1.5)
        r = chat(c, "enforce ok again")
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# limits & metrics
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PROXY_SMALL, reason="PROXY_SMALL_BODY_URL not set")
def test_413_is_json():
    with client(PROXY_SMALL) as c:
        big = "x" * (2 * 1024 * 1024)
        r = chat(c, big)
        assert r.status_code == 413
        assert r.json()["error"]["type"] == "proxy_error"


def test_large_body_within_limit_round_trips():
    with client() as c:
        # ~3 MB of incompressible-ish content exercises gzip_bound sizing
        import base64
        import os as _os
        payload = base64.b64encode(_os.urandom(2 * 1024 * 1024)).decode()
        r = chat(c, payload)
        assert r.status_code == 200, r.text[:300]
        assert r.json()["choices"][0]["message"]["content"].endswith(payload[-32:])


def test_metrics_exposed():
    with client() as c:
        chat(c, mode="agent")
        r = c.get("/metrics")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        body = r.text
        assert "e2ee_requests_total{" in body
        assert 'e2ee_instance_picks_total{' in body
        assert "e2ee_ttft_seconds_bucket{" in body
        assert "e2ee_build_info{" in body
        assert "e2ee_nonce_refresh_total{" in body
        assert "e2ee_prompt_tokens_total{" in body
        assert "e2ee_attestation_total{" in body
