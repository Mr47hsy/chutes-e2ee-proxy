# E2EE Local Proxy (independent fork)

An OpenResty-based reverse proxy that provides **end-to-end encryption** for the
Chutes AI API. It speaks the OpenAI Chat Completions, Claude Messages and OpenAI
Responses APIs locally, encrypts each request with post-quantum cryptography
(ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305) and forwards it to the GPU
instance, which is the only party able to decrypt it.

This is a fork of [chutesai/e2ee-proxy](https://github.com/chutesai/e2ee-proxy)
that can be **built from a clean clone**. The upstream image depends on a
private obfuscation toolchain and an embedded TLS certificate; this fork
replaces both with an open native library and standard TLS, and adds:

| Area | Change |
|---|---|
| Build | `docker build .` works with nothing but this repository; native crypto is plain C on OpenSSL + zlib + vendored PQClean ML-KEM-768, with NIST/RFC self-tests as a build gate |
| Image | `openresty/openresty:1.31.1.1-alpine` base (64 MB compressed) instead of the 285 MB jammy image; a Debian bookworm variant (`Dockerfile.debian`, 38 MB base) is one flag away |
| Routing | Instance selection modes `agent` / `balanced` / `performance` / `default`, per-request `X-Route-Mode` header, automatic failover |
| Security | TEE attestation of instance keys (observe/enforce), CORS allowlist, no API-key fragments in logs, unprivileged container user, HKDF/AEAD/gzip via OpenSSL |
| Operations | `/metrics` (Prometheus), `X-Request-Id`, structured 413, 64 MB bodies, 15-minute read timeout, health check |
| Hardening | Optional plaintext HTTP listener for local tooling, with explicit opt-in |

## Architecture

```
Client (OpenAI SDK / Anthropic SDK / curl)
    │
    ▼  HTTPS (self-signed or your cert)      [or plain HTTP on :80 if ALLOW_PLAINTEXT=true]
┌──────────────┐
│  E2EE Proxy  │  instance selection · attestation · encryption · SSE decryption
│  (OpenResty) │
└──────┬───────┘
       │  HTTPS + E2EE envelope (api.chutes.ai only sees ciphertext + routing headers)
       ▼
  api.chutes.ai ──▶ GPU instance in a TDX enclave (decrypts with its private key)
```

## Quick start

```bash
# build (linux/amd64 by default, Alpine base)
./build.sh                      # -> image e2ee-proxy
./build.sh --debian             # same, on the Debian bookworm base (glibc)

# run: self-signed TLS, balanced routing, attestation in observe mode
docker run --rm -p 8443:443 e2ee-proxy
```

The container prints how to trust its self-signed certificate. The certificate
covers `localhost`, `127.0.0.1`, `::1` and `e2ee-local-proxy.chutes.dev` (a
public DNS name that resolves to `127.0.0.1`), so either host name works:

```python
from openai import OpenAI
client = OpenAI(api_key="cpk_...", base_url="https://localhost:8443/v1")
resp = client.chat.completions.create(
    model="Qwen/Qwen3-32B-TEE",
    messages=[{"role": "user", "content": "Hello!"}],
)

import anthropic
client = anthropic.Anthropic(api_key="cpk_...", base_url="https://localhost:8443")
resp = client.messages.create(model="Qwen/Qwen3-32B-TEE", max_tokens=128,
                              messages=[{"role": "user", "content": "Hello!"}])
```

To keep the same certificate across container restarts mount a state directory:

```bash
docker run --rm -p 8443:443 -v e2ee-tls:/tls -e TLS_STATE_DIR=/tls e2ee-proxy
```

## Verifying the ML-KEM variant (do this once after building)

Kyber round-3 and FIPS 203 ML-KEM have identical key/ciphertext sizes but do
**not** interoperate. This fork ships FIPS 203 (PQClean `ml-kem-768/clean`);
the build's self-test proves the implementation against NIST ACVP vectors, and
the evidence that Chutes speaks FIPS 203 is laid out in
[`native/mlkem_backend.h`](native/mlkem_backend.h). The only conclusive proof
is a real request:

```bash
curl -sk https://localhost:8443/v1/chat/completions \
  -H "Authorization: Bearer cpk_..." -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen3-32B-TEE","messages":[{"role":"user","content":"ping"}]}'
```

- A normal completion: the variant is right, done.
- HTTP 400/500 from upstream with everything else healthy (`/health` ok,
  `/v1/models` lists the model, `/e2e/instances` succeeded in the logs): the
  instances likely speak Kyber round-3. Rebuild with
  `./build.sh --mlkem-backend kyber-r3` after vendoring the round-3 sources as
  described in [`native/mlkem/README.md`](native/mlkem/README.md).

Then run a streaming request as well (`"stream": true`); it exercises the
separate `e2e-stream-v1` key derivation. `tests/e2e_real.sh` does all of the
above (health, model listing, non-streaming, streaming, metrics) and reads the
key from `CHUTES_API_KEY` without echoing it:

```bash
docker run -d --name e2ee-proxy -p 8443:443 e2ee-proxy
CHUTES_API_KEY=cpk_... tests/e2e_real.sh            # MODEL=... to pick another TEE model
```

## TLS

| Mode | How | Notes |
|---|---|---|
| Self-signed (default) | nothing to set | SAN includes `TLS_DOMAIN`, `localhost`, loopback IPs, `e2ee-local-proxy.chutes.dev`; set `TLS_STATE_DIR` to persist |
| Custom certificate | `TLS_CERT`, `TLS_KEY`, optional `TLS_CA` (PEM paths) | recommended for anything beyond a local loopback deployment |

`TLS_DOMAIN` sets `server_name` and the self-signed CN (default `localhost`).
The upstream "embedded certificate" mode is gone: no private key ships inside
the image, so there is nothing for Certificate Transparency monitors to
revoke and no key shared between all users.

## Routing modes

`/e2e/instances/{chute_id}` returns several GPU instances, each with a batch of
single-use nonces valid for about 55 s. Upstream always used the first
instance with nonces left, so requests spaced more than 55 s apart hopped
between instances and lost the prefix KV cache (measured on a 20k-token
prefix: hit rate 43%, effective input price $1.999/M; sticky: 100%, $0.330/M).

| Mode | Strategy | Use for |
|---|---|---|
| `agent` | one sticky instance per model | a single interactive coding agent |
| `balanced` (default) | sticky set of `BALANCED_N` (3) instances, round-robin | several agents in parallel; every member stays warm |
| `performance` | power-of-two-choices on a decaying EWMA of time-to-first-token | batch jobs that do not benefit from cache |
| `default` | upstream behaviour | control group / comparison |

- `ROUTE_MODE` sets the global default; the request header `X-Route-Mode:
  agent|balanced|performance|default` overrides it per request (unknown
  values fall back to the default with a warning).
- Every response carries `X-E2EE-Instance-Id` and `X-E2EE-Route-Mode`.
- Failover is automatic: a nonce rejection (403) is retried once on another
  instance; an instance that returns 5xx, fails to connect or fails
  attestation is dropped from stickiness and avoided for `ROUTE_BAN_S` (60 s).
- `PIN_INSTANCE_ID=<id>` pins one instance for experiments. It falls back to
  the mode logic when that instance is absent, with a warning; there is no
  other recovery, do not use it in production.

Hedged requests (racing two instances) are intentionally not implemented:
they double billing.

## Attestation

Upstream encrypted to whatever public key the discovery endpoint returned.
Nothing checked that the key was generated inside a genuine TD, so a
compromised discovery service could substitute its own key and read every
prompt while all client-side checks still passed.

This fork fetches a TDX quote for each instance key and verifies:

1. `report_data[0:32] == SHA256(nonce ‖ e2e_pubkey)` with a fresh 32-byte
   client nonce (defeats key substitution and quote replay by itself),
2. the TD debug bit is clear,
3. `MRTD` / `RTMR0-3` match `E2EE_ATTEST_MRTD` / `E2EE_ATTEST_RTMR*` when set,
4. the quote header is a well-formed TDX quote (v4/v5, ECDSA-P256, tee 0x81).

**Not verified: the quote's ECDSA signature and the PCK certificate chain.**
That needs Intel DCAP QVL, which is not in the image. Consequence: an attacker
who controls the API *and* can forge quotes still wins; one who can only swap
the public key does not. Pinning measurements obtained from an out-of-band
DCAP verification closes most of the remaining gap.

The exact endpoint path and `report_data` preimage of the Chutes attestation
API have not been confirmed against a live response yet, so:

- `E2EE_ATTEST=observe` (shipped default) runs every check, logs
  `attestation OK …` or `ATTESTATION FAILED (observe mode, request allowed)`
  with the response shape, and never rejects. Failures are cached for
  `E2EE_ATTEST_FAIL_TTL` (300 s) so they do not add round trips to every
  request.
- Once the logs show `attestation OK`, set `E2EE_ATTEST=enforce`. Instances
  that fail are rejected (up to three are tried) and the request returns
  `502 TEE attestation failed`.
- If the observe logs show a different endpoint or field layout, set
  `E2EE_ATTEST_URLS` (comma-separated templates with `{api}`, `{chute_id}`,
  `{instance_id}`, `{nonce_hex}`). The quote is located structurally inside
  the JSON, so field names do not matter, and six nonce/pubkey encodings are
  tried for the binding; a match proves the quote was made for this nonce and
  key, so trying several does not weaken the check.
- `E2EE_ATTEST=off` disables it.

Also note that `confidential_compute` in `/v1/models` is self-reported by the
API; attestation is what actually ties the key to a TD.

## Plaintext HTTP, CORS and what is (not) encrypted

- Port 80 redirects to HTTPS by default. `ALLOW_PLAINTEXT=true` makes it serve
  the API without TLS, for local tools that cannot trust a self-signed
  certificate. API keys then cross that hop in cleartext, so publish it on
  loopback only: `docker run -p 127.0.0.1:8080:80 …`. (Inside a container the
  listener must bind all interfaces for `-p` to work; `PLAINTEXT_BIND_ADDR`
  overrides that for `--network host` deployments.)
- CORS is an allowlist. Default: `null`, `http(s)://localhost[:port]`,
  `http(s)://127.0.0.1[:port]`, `http(s)://[::1][:port]`,
  `https://e2ee-local-proxy.chutes.dev[:port]`. Override with
  `CORS_ALLOWED_ORIGINS=https://app.example.com,https://*.example.org`
  (`*` alone restores allow-any).
- `GET /v1/models` is a TLS passthrough to `llm.chutes.ai`; it is **not**
  end-to-end encrypted (the model list is public metadata, the Authorization
  header is forwarded).
- Routing metadata is visible to api.chutes.ai in cleartext headers:
  chute id, instance id, nonce, stream flag, path, and your API key. Only the
  request/response bodies are end-to-end encrypted.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `TLS_CERT`, `TLS_KEY`, `TLS_CA` | – | PEM paths for a custom certificate (CA appended to the chain) |
| `TLS_DOMAIN` | `localhost` | server_name and self-signed CN/SAN |
| `TLS_STATE_DIR` | – | directory to persist the self-signed certificate |
| `ROUTE_MODE` | `balanced` | `agent`, `balanced`, `performance`, `default` |
| `BALANCED_N` | `3` | size of the sticky set in balanced mode |
| `ROUTE_BAN_S` | `60` | seconds an instance is avoided after a failure |
| `PIN_INSTANCE_ID` | – | diagnostics: force one instance |
| `PERF_EWMA_ALPHA`, `PERF_HALF_LIFE_S`, `PERF_COLD_START_S` | `0.3`, `300`, `0.5` | performance-mode scoring |
| `E2EE_ATTEST` | `observe` | `enforce`, `observe`, `off` |
| `E2EE_ATTEST_MRTD`, `E2EE_ATTEST_RTMR0..3` | – | hex allowlist (empty = accept any) |
| `E2EE_ATTEST_TTL` / `E2EE_ATTEST_FAIL_TTL` | `600` / `300` | cache of successful / observed-failed verifications (s) |
| `E2EE_ATTEST_URLS` | built-in candidates | endpoint templates |
| `E2EE_ATTEST_ALLOW_DEBUG_TD` | `false` | accept debug-mode TDs (do not) |
| `ALLOW_NON_CONFIDENTIAL` | `false` | allow models without `confidential_compute` |
| `ALLOW_PLAINTEXT` | `false` | serve the API on port 80 without TLS |
| `PLAINTEXT_BIND_ADDR` | `0.0.0.0` | bind address of the plaintext listener |
| `CORS_ALLOWED_ORIGINS` | local origins | comma-separated allowlist, `*` wildcards |
| `MAX_BODY_SIZE` | `64m` | `client_max_body_size`; larger bodies get a JSON 413 |
| `UPSTREAM_READ_TIMEOUT_MS` | `900000` | read timeout towards api.chutes.ai (long generations) |
| `UPSTREAM_CONNECT_TIMEOUT_MS`, `UPSTREAM_SEND_TIMEOUT_MS` | `5000`, `30000` | |
| `DISCOVERY_TIMEOUT_MS`, `MODELS_TIMEOUT_MS`, `MODEL_MAP_TTL_S` | `30000`, `10000`, `300` | |
| `LOG_LEVEL` | `notice` | nginx error log level; `debug` adds per-request traces (nonce prefixes only) |
| `METRICS_ENABLED` | `true` | expose `/metrics` |
| `API_BASE`, `MODELS_BASE` | `https://api.chutes.ai`, `https://llm.chutes.ai` | upstream endpoints (integration tests point them at a mock) |

## Observability

- `GET /health` → status, route mode, attestation mode, native build info
  (ML-KEM backend, OpenSSL version).
- `GET /metrics` (Prometheus text): request counts by path/mode/outcome,
  upstream error classes (`nonce_403`, `5xx`, `timeout`, `connect`, `decrypt`,
  `attest`), TTFT histogram by mode, seal/open durations, prompt and cached
  token totals from upstream `usage` (cache hit rate = cached / prompt),
  instance picks by reason, affinity hits/misses by mode, per-instance TTFT
  EWMA, nonce refreshes and `/e2e/instances` round-trip time, attestation
  results, keepalive reuse.
- `X-Request-Id`: taken from the client header when present (sanitised),
  otherwise generated; echoed on the response and prefixed on every log line
  and the access log.
- Logs never contain API keys or full nonces. `LOG_LEVEL=debug` adds instance
  choices and 8-character nonce prefixes.

## API endpoints

| Endpoint | Behaviour |
|---|---|
| `GET /health` | proxy status |
| `GET /metrics` | Prometheus metrics |
| `GET /v1/models` | passthrough to `llm.chutes.ai` (TLS only, no E2EE) |
| `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/*` | E2EE |
| `POST /v1/messages` | E2EE, Claude Messages API translated to chat completions |
| `POST /v1/responses` | E2EE, OpenAI Responses API translated to chat completions |
| `OPTIONS *` | CORS preflight (204) |

## E2EE protocol

For each request the proxy:

1. resolves the model to a chute id via `/v1/models` (cached 5 min),
2. takes an instance + single-use nonce from `/e2e/instances/{chute_id}`
   (instance chosen by the routing mode),
3. verifies the instance key's TDX attestation (cached 10 min per key),
4. generates an ephemeral ML-KEM-768 keypair for the response,
5. encapsulates to the instance key and derives the request key with
   HKDF-SHA256 (salt = first 16 bytes of the ML-KEM ciphertext, info
   `e2e-req-v1`),
6. injects the response public key into the JSON, gzips it, seals it with
   ChaCha20-Poly1305 (12-byte random nonce, 16-byte tag, no AAD),
7. POSTs `mlkem_ct ‖ nonce ‖ ciphertext ‖ tag` to `/e2e/invoke` over a
   keep-alive TLS connection,
8. decrypts the response blob (info `e2e-resp-v1`) or, for streaming, derives
   the stream key from the `e2e_init` event (info `e2e-stream-v1`) and
   decrypts each `base64(nonce ‖ ciphertext ‖ tag)` chunk.

Every request uses a fresh ephemeral keypair (forward secrecy).

## Development

```
native/           C library: e2ee_proxy_api.c (OpenSSL HKDF/AEAD, zlib gzip,
                  getrandom), mlkem/ (vendored PQClean FIPS 203 ML-KEM-768),
                  selftest.c + selftest_kat.h (NIST ACVP, RFC 5869, RFC 8439,
                  Wycheproof vectors), build.sh
lua/              OpenResty modules; lua/resty/ is vendored lua-resty-http 0.17.2
conf/             nginx.conf.template + locations.inc.template (rendered by entrypoint.sh)
tests/unit/       pure-Lua tests with an ngx mock (run: tests/unit/run.sh)
tests/integration mock_upstream.py (independent Python implementation of the
                  server side, kyber-py + cryptography) and pytest suite
```

Local checks without Docker:

```bash
cd native && ./build.sh --selftest         # needs a C compiler, OpenSSL headers, zlib
tests/unit/run.sh                          # needs luajit
```

Integration tests need the built image and a Python environment; the runner
starts the mock upstream and three proxy containers (observe / enforce /
1 MB body limit), runs pytest and scans the proxy logs for key material:

```bash
python3 -m venv .venv && .venv/bin/pip install -r tests/integration/requirements.txt
PYTHON=.venv/bin/python tests/integration/run_local.sh        # add --keep to leave containers up
```

CI (`.github/workflows/ci.yml`) runs LuaJIT syntax checks, luacheck, unit
tests, the native self-test, builds the amd64 image, runs the in-image cjson
round-trip test, and drives three proxy containers (observe, enforce, small
body limit) against the mock upstream, then asserts that no API key material
appears in the logs.

### Image notes

- The image targets `linux/amd64` by default (both Dockerfiles carry
  `ARG PLATFORM=linux/amd64`, so a bare `docker build .` is x86 too). On an
  Apple Silicon Mac the builder stage runs under Rosetta/QEMU and still
  produces an x86_64 `.so`; `./build.sh --platform linux/arm64` builds a
  native image for local testing.
- Default base is Alpine (musl); the native library is compiled in an
  `alpine:3.23` stage so libc and OpenSSL match the runtime. Inside nginx the
  loader reuses the `libcrypto.so.3` OpenResty bundles, so no version pin is
  needed beyond the OpenSSL 3 soname.
- `Dockerfile.debian` is the same layout on `debian:bookworm-slim` +
  `openresty/openresty:1.31.1.1-bookworm` for environments that prefer glibc.
- Runs as an unprivileged user; port binding uses `cap_net_bind_service` on
  the nginx binary.
- `worker_processes 1` is deliberate: nonce batches, routing state, metrics
  and attestation caches live in module-level Lua tables. Moving to several
  workers needs those in `lua_shared_dict` with atomic operations (nonces are
  single-use).
- Switching the ML-KEM backend: `MLKEM_BACKEND=kyber-r3` build arg, see
  [`native/mlkem/README.md`](native/mlkem/README.md).

## Known limitations / follow-ups

- Attestation signature and PCK chain are not verified (DCAP QVL sidecar or
  an in-`.so` verifier would close this).
- Attestation endpoint/schema are unconfirmed; ships in observe mode.
- Nonce batches are fetched synchronously when they expire (about one extra
  round trip when requests are more than ~55 s apart); background prefetch
  is a possible follow-up.
- Single worker by design (see above).
- OpenResty publishes no Debian 13 (trixie) image; the Debian variant uses
  bookworm. `alpine-slim` (22 MB) exists but has not been validated with the
  self-signed certificate flow, so the default is the plain `alpine` tag.

## License

MIT (see `LICENSE`). Vendored components: PQClean (public domain / CC0),
lua-resty-http (BSD-2-Clause, `lua/resty/LICENSE-lua-resty-http`).
