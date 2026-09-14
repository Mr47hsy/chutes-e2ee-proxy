#!/usr/bin/env python3
"""
mock_upstream.py - a fake api.chutes.ai / llm.chutes.ai for integration tests.

Implements the server side of the E2EE protocol with an INDEPENDENT
implementation (kyber-py for FIPS 203 ML-KEM-768, `cryptography` for
HKDF-SHA256 and ChaCha20-Poly1305, stdlib gzip). If the proxy can talk to
this mock, its wire format is right and its ML-KEM is FIPS 203; only the
question "does the real Chutes instance also speak FIPS 203" remains, and
that needs a real key.

Endpoints
  GET  /v1/models
  GET  /e2e/instances/{chute_id}
  POST /e2e/invoke
  GET  /instances/{instance_id}/attestation?nonce=<hex>
  GET  /_mock/stats            counters for assertions
  POST /_mock/reset
  POST /_mock/config           {"down": [...], "reject_next_nonce": bool,
                                "attest_all_bad": bool, "instances": N}

Run:  python3 tests/integration/mock_upstream.py --port 9100
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
import secrets
import struct
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

MLKEM_CT = 1088
MLKEM_PK = 1184
NONCE_TTL = 55

CHUTE_TEE = str(uuid.uuid5(uuid.NAMESPACE_DNS, "tee"))
CHUTE_PLAIN = str(uuid.uuid5(uuid.NAMESPACE_DNS, "plain"))
MODELS = [
    {"id": "mock/TEE-model", "chute_id": CHUTE_TEE, "confidential_compute": True},
    {"id": "mock/plain-model", "chute_id": CHUTE_PLAIN, "confidential_compute": False},
]


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


class Instance:
    def __init__(self, iid: str):
        self.id = iid
        self.ek, self.dk = ML_KEM_768.keygen()
        assert len(self.ek) == MLKEM_PK
        self.nonces = {}  # nonce -> expiry
        self.requests = 0
        self.attest_bad = iid.endswith("-bad")

    def issue_nonces(self, n=10):
        out = []
        for _ in range(n):
            nonce = secrets.token_hex(16)
            self.nonces[nonce] = time.time() + NONCE_TTL
            out.append(nonce)
        return out

    def consume(self, nonce):
        exp = self.nonces.pop(nonce, None)
        return exp is not None and exp > time.time()


class State:
    def __init__(self, n_instances):
        self.lock = threading.Lock()
        self.n_instances = n_instances
        self.reset()

    def reset(self):
        # Instances (and their ML-KEM keys) survive resets on purpose: the proxy
        # caches nonces for ~55 s and verified keys for 10 min, so regenerating
        # them between tests would inject artificial 403s/decrypt failures.
        if not hasattr(self, "instances"):
            self.instances = {f"inst-{i}": Instance(f"inst-{i}") for i in range(1, self.n_instances + 1)}
            self.attest_calls_total = 0
        self.down = set()
        self.reject_next_nonce = False
        self.attest_all_bad = False
        self.stats = {
            "invoke": 0, "invoke_by_instance": {}, "nonce_rejects": 0,
            "instances_calls": 0, "attest_calls": 0, "attest_by_instance": {},
            "models_calls": 0, "stream": 0, "paths": {},
        }


STATE = State(int(os.environ.get("MOCK_INSTANCES", "5")))


def build_quote(nonce_raw: bytes, ek: bytes, bad: bool) -> bytes:
    """TDX quote v4 header (48) + TDReport10 body (584) + fake signature blob."""
    header = struct.pack("<HHIHH", 4, 2, 0x81, 0, 0) + b"\0" * 16 + b"\0" * 20
    assert len(header) == 48
    pk_for_binding = ek if not bad else bytes(reversed(ek))
    report_data = hashlib.sha256(nonce_raw + pk_for_binding).digest() + b"\0" * 32
    body = (b"\1" * 16 + b"\2" * 48 + b"\3" * 48 + b"\4" * 8
            + b"\0" * 8                       # td_attributes (debug bit clear)
            + b"\5" * 8                       # xfam
            + b"\x66" * 48                    # mr_td
            + b"\7" * 48 + b"\x08" * 48 + b"\x09" * 48
            + b"\x0a" * 48 + b"\x0b" * 48 + b"\x0c" * 48 + b"\x0d" * 48
            + report_data)
    assert len(body) == 584
    return header + body + b"\xee" * 64


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("MOCK_VERBOSE"):
            super().log_message(fmt, *args)

    # -- helpers ---------------------------------------------------------
    def _json(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer cpk_")

    def _read_body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(n) if n else b""

    # -- GET --------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        with STATE.lock:
            if u.path == "/v1/models":
                STATE.stats["models_calls"] += 1
                if not self._auth_ok():
                    return self._json(401, {"detail": "unauthorized"})
                return self._json(200, {"object": "list", "data": MODELS},
                                  {"Access-Control-Allow-Origin": "*"})

            if len(parts) == 3 and parts[0] == "e2e" and parts[1] == "instances":
                STATE.stats["instances_calls"] += 1
                if not self._auth_ok():
                    return self._json(401, {"detail": "unauthorized"})
                chute = parts[2]
                if chute not in (CHUTE_TEE, CHUTE_PLAIN):
                    return self._json(404, {"detail": "chute not found"})
                insts = []
                for inst in STATE.instances.values():
                    insts.append({
                        "instance_id": inst.id,
                        "e2e_pubkey": base64.b64encode(inst.ek).decode(),
                        "nonces": inst.issue_nonces(),
                    })
                return self._json(200, {"instances": insts, "nonce_expires_in": NONCE_TTL})

            if len(parts) == 3 and parts[0] == "instances" and parts[2] == "attestation":
                STATE.stats["attest_calls"] += 1
                STATE.attest_calls_total += 1
                iid = parts[1]
                STATE.stats["attest_by_instance"][iid] = STATE.stats["attest_by_instance"].get(iid, 0) + 1
                inst = STATE.instances.get(iid)
                if not inst:
                    return self._json(404, {"detail": "instance not found"})
                nonce_hex = parse_qs(u.query).get("nonce", [""])[0]
                if len(nonce_hex) != 64:
                    return self._json(400, {"detail": "nonce must be 32 bytes hex"})
                bad = inst.attest_bad or STATE.attest_all_bad
                quote = build_quote(bytes.fromhex(nonce_hex), inst.ek, bad)
                return self._json(200, {
                    "instance_id": iid,
                    "evidence": {"tdx": {"quote": base64.b64encode(quote).decode(), "format": "TDX_v4"}},
                    "nonce": nonce_hex,
                })

            if u.path == "/_mock/stats":
                out = dict(STATE.stats)
                out["attest_calls_total"] = STATE.attest_calls_total
                return self._json(200, out)

        return self._json(404, {"detail": f"no route for {u.path}"})

    # -- POST -------------------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        body = self._read_body()

        if u.path == "/_mock/reset":
            with STATE.lock:
                STATE.reset()
            return self._json(200, {"ok": True})

        if u.path == "/_mock/config":
            cfg = json.loads(body or b"{}")
            with STATE.lock:
                if "down" in cfg:
                    STATE.down = set(cfg["down"])
                if "reject_next_nonce" in cfg:
                    STATE.reject_next_nonce = bool(cfg["reject_next_nonce"])
                if "attest_all_bad" in cfg:
                    STATE.attest_all_bad = bool(cfg["attest_all_bad"])
            return self._json(200, {"ok": True})

        if u.path != "/e2e/invoke":
            return self._json(404, {"detail": f"no route for {u.path}"})

        if not self._auth_ok():
            return self._json(401, {"detail": "unauthorized"})

        iid = self.headers.get("X-Instance-Id", "")
        nonce = self.headers.get("X-E2E-Nonce", "")
        streaming = self.headers.get("X-E2E-Stream", "false").lower() == "true"
        path = self.headers.get("X-E2E-Path", "")

        with STATE.lock:
            STATE.stats["invoke"] += 1
            STATE.stats["invoke_by_instance"][iid] = STATE.stats["invoke_by_instance"].get(iid, 0) + 1
            STATE.stats["paths"][path] = STATE.stats["paths"].get(path, 0) + 1
            inst = STATE.instances.get(iid)
            if not inst:
                return self._json(404, {"detail": "unknown instance"})
            if STATE.reject_next_nonce:
                STATE.reject_next_nonce = False
                STATE.stats["nonce_rejects"] += 1
                return self._json(403, {"detail": "invalid or expired nonce"})
            if not inst.consume(nonce):
                STATE.stats["nonce_rejects"] += 1
                return self._json(403, {"detail": "invalid or expired nonce"})
            if iid in STATE.down:
                return self._json(502, {"detail": "instance unavailable"})
            inst.requests += 1

        # ---- decrypt request -------------------------------------------------
        if len(body) < MLKEM_CT + 12 + 16:
            return self._json(400, {"detail": "blob too short"})
        mlkem_ct, aead_nonce, ct_tag = body[:MLKEM_CT], body[MLKEM_CT:MLKEM_CT + 12], body[MLKEM_CT + 12:]
        try:
            ss = ML_KEM_768.decaps(inst.dk, mlkem_ct)
            key = hkdf(ss, mlkem_ct[:16], b"e2e-req-v1")
            plain = ChaCha20Poly1305(key).decrypt(aead_nonce, ct_tag, None)
            payload = json.loads(gzip.decompress(plain))
        except Exception as e:  # noqa: BLE001
            return self._json(400, {"detail": f"decrypt failed: {type(e).__name__}: {e}"})

        resp_pk = base64.b64decode(payload.get("e2e_response_pk", ""))
        if len(resp_pk) != MLKEM_PK:
            return self._json(400, {"detail": "missing/invalid e2e_response_pk"})

        # ---- build a chat completion echoing the last user message ----------
        msgs = payload.get("messages") or []
        last = ""
        for m in reversed(msgs):
            if m.get("role") == "user":
                c = m.get("content")
                last = c if isinstance(c, str) else json.dumps(c)
                break
        prompt_chars = sum(len(json.dumps(m)) for m in msgs)
        prompt_tokens = max(1, prompt_chars // 4)
        cached = (prompt_tokens // 512) * 512 if inst.requests > 1 else 0
        text = f"echo({iid}): {last}"
        usage = {
            "prompt_tokens": prompt_tokens, "completion_tokens": 7,
            "total_tokens": prompt_tokens + 7,
            "prompt_tokens_details": {"cached_tokens": cached},
        }
        cid = "chatcmpl-mock-" + secrets.token_hex(4)
        model = payload.get("model", "mock/TEE-model")

        if not streaming:
            completion = {
                "id": cid, "object": "chat.completion", "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": usage,
            }
            ct2, ss2 = ML_KEM_768.encaps(resp_pk)
            key2 = hkdf(ss2, ct2[:16], b"e2e-resp-v1")
            n2 = secrets.token_bytes(12)
            sealed = ChaCha20Poly1305(key2).encrypt(n2, gzip.compress(json.dumps(completion).encode()), None)
            return self._bytes(200, ct2 + n2 + sealed)

        # ---- streaming: e2e_init + encrypted chunks + [DONE] ----------------
        with STATE.lock:
            STATE.stats["stream"] += 1
        ct2, ss2 = ML_KEM_768.encaps(resp_pk)
        skey = hkdf(ss2, ct2[:16], b"e2e-stream-v1")
        aead = ChaCha20Poly1305(skey)

        def enc_line(line: str) -> bytes:
            n = secrets.token_bytes(12)
            blob = n + aead.encrypt(n, line.encode(), None)
            return b"data: " + json.dumps({"e2e": base64.b64encode(blob).decode()}).encode() + b"\n\n"

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def chunk(data: bytes):
            self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
            self.wfile.flush()

        chunk(b"data: " + json.dumps({"e2e_init": base64.b64encode(ct2).decode()}).encode() + b"\n\n")
        words = text.split(" ")
        for i, w in enumerate(words):
            delta = {"id": cid, "object": "chat.completion.chunk", "created": int(time.time()), "model": model,
                     "choices": [{"index": 0, "delta": {"content": (w if i == 0 else " " + w)}, "finish_reason": None}]}
            if i == 0:
                delta["choices"][0]["delta"]["role"] = "assistant"
            chunk(enc_line("data: " + json.dumps(delta)))
            time.sleep(0.01)
        final = {"id": cid, "object": "chat.completion.chunk", "created": int(time.time()), "model": model,
                 "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage}
        chunk(enc_line("data: " + json.dumps(final)))
        chunk(b"data: [DONE]\n\n")
        chunk(b"")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock upstream on http://{args.host}:{args.port}  chute_tee={CHUTE_TEE}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
