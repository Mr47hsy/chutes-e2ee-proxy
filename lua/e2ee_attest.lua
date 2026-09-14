--
-- e2ee_attest.lua - TEE attestation of instance public keys.
--
-- WHY THIS EXISTS
-- ---------------
-- The proxy encrypts every prompt to the `e2e_pubkey` that
-- GET /e2e/instances/{chute_id} hands out. Nothing upstream verified that the
-- key was generated inside a genuine TD. A compromised discovery endpoint
-- could return a key it controls and read every prompt while every
-- client-side check (ML-KEM decapsulation, Poly1305 tags) still passes.
--
-- WHAT IS VERIFIED
--   1. report_data[0:32] == SHA256(nonce || e2e_pubkey), nonce = our fresh
--      32 random bytes. Defeats key substitution and quote replay on its own.
--   2. TD debug bit is clear (td_attributes bit 0).
--   3. MRTD / RTMR0-3 match the operator allowlist when one is configured.
--   4. Quote header is a well-formed TDX quote (v4/v5, ECDSA-P256, tee 0x81).
--
-- WHAT IS NOT VERIFIED -- read this
--   The quote's ECDSA signature and the PCK certificate chain up to Intel's
--   root are NOT checked (needs Intel DCAP QVL; not in the base image). An
--   attacker who controls the API *and* can mint forged quotes still wins.
--   One who can only swap the public key does not. Pin MRTD/RTMRs obtained
--   from an out-of-band DCAP verification to close most of the remaining gap.
--
-- UNKNOWNS
--   The endpoint path and the exact report_data preimage have not been
--   confirmed against a live response. The module therefore
--     - probes several candidate URLs (E2EE_ATTEST_URLS to override),
--     - locates the quote structurally (base64/hex string with a valid TDX
--       header) instead of guessing field names,
--     - tries six nonce/pubkey encodings for the binding; a match proves the
--       quote was produced for this nonce and key, so trying several does
--       not weaken the check.
--   In E2EE_ATTEST=observe mode (the shipped default) the response structure
--   is logged so the schema can be confirmed, then switch to enforce.
--
-- CONFIG: see e2ee_config.lua (E2EE_ATTEST*).
--

local bit = require("bit")
local config = require("e2ee_config")
local log = require("e2ee_log")
local metrics = require("metrics")
local cjson = require("cjson.safe")

local _M = {}

local MODE = config.ATTEST_MODE

-- Dependencies are resolved lazily so the module loads (and is unit-testable)
-- outside OpenResty; tests inject replacements via _M._deps.
local deps = {}
_M._deps = deps

local function sha256_bin(s)
    if deps.sha256 then
        return deps.sha256(s)
    end
    local sha256 = require("resty.sha256")
    local h = sha256:new()
    h:update(s)
    return h:final()
end

local function random_bytes(n)
    if deps.random_bytes then
        return deps.random_bytes(n)
    end
    local rnd = require("resty.random")
    return rnd.bytes(n, true) or rnd.bytes(n, false)
end

local function to_hex(s)
    return (s:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function b64decode(s)
    if deps.b64decode then
        return deps.b64decode(s)
    end
    return ngx.decode_base64(s)
end

local function http_get_json(url, api_key)
    if deps.fetch then
        return deps.fetch(url, api_key)
    end
    local http = require("resty.http")
    local httpc = http.new()
    httpc:set_timeout(config.ATTEST_TIMEOUT_MS)
    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = {
            ["Authorization"] = "Bearer " .. api_key,
            ["Cache-Control"] = "no-cache, no-store",
        },
        ssl_verify = true,
    })
    if not res then
        return nil, nil, err or "request failed"
    end
    return res.status, res.body, nil
end

-- ---------------------------------------------------------------------------
-- Endpoint candidates
-- ---------------------------------------------------------------------------
local DEFAULT_URLS = {
    "{api}/instances/{instance_id}/attestation?nonce={nonce_hex}",
    "{api}/e2e/instances/{instance_id}/attestation?nonce={nonce_hex}",
    "{api}/chutes/{chute_id}/evidence?nonce={nonce_hex}",
    "{api}/instances/{instance_id}/evidence?nonce={nonce_hex}",
}

local URL_TEMPLATES = DEFAULT_URLS
if config.ATTEST_URLS and config.ATTEST_URLS ~= "" then
    URL_TEMPLATES = {}
    for u in config.ATTEST_URLS:gmatch("[^,]+") do
        u = u:gsub("^%s+", ""):gsub("%s+$", "")
        if u ~= "" then
            URL_TEMPLATES[#URL_TEMPLATES + 1] = u
        end
    end
end

-- Endpoint that worked last time, tried first afterwards.
local good_url_template = nil

-- verified[instance_id] = { pubkey_fp = hex, expires_at = ts }
local verified = {}
-- failed[instance_id]   = { pubkey_fp = hex, expires_at = ts, err = string }  (observe mode only)
local failed = {}

function _M.mode()
    return MODE
end

-- ---------------------------------------------------------------------------
-- TDX quote layout (Intel TDX DCAP quote v4/v5, TDReport10 body)
--
--   header 48 bytes
--     +0   version        u16 LE (4 or 5)
--     +2   att_key_type   u16 LE (2 = ECDSA-P256)
--     +4   tee_type       u32 LE (0x81 = TDX)
--   body 584 bytes, starts at 48
--     +0   tee_tcb_svn        16
--     +16  mr_seam            48
--     +64  mr_signer_seam     48
--     +112 seam_attributes     8
--     +120 td_attributes       8   bit 0 = DEBUG
--     +128 xfam                8
--     +136 mr_td              48
--     +184 mr_config_id       48
--     +232 mr_owner           48
--     +280 mr_owner_config    48
--     +328 rtmr0              48
--     +376 rtmr1              48
--     +424 rtmr2              48
--     +472 rtmr3              48
--     +520 report_data        64
--   total 632 bytes before the signature section
-- ---------------------------------------------------------------------------
local HDR = 48
local BODY_LEN = 584
local MIN_QUOTE = HDR + BODY_LEN
_M.MIN_QUOTE_LEN = MIN_QUOTE

local function le_u16(s, off)
    return s:byte(off + 1) + s:byte(off + 2) * 256
end

local function le_u32(s, off)
    return s:byte(off + 1) + s:byte(off + 2) * 256 + s:byte(off + 3) * 65536 + s:byte(off + 4) * 16777216
end

local function looks_like_tdx_quote(b)
    if type(b) ~= "string" or #b < MIN_QUOTE then
        return false
    end
    local version = le_u16(b, 0)
    if version ~= 4 and version ~= 5 then
        return false
    end
    if le_u16(b, 2) ~= 2 then
        return false
    end
    if le_u32(b, 4) ~= 0x81 then
        return false
    end
    return true
end

local function parse_quote(b)
    local function field(off, len)
        return b:sub(HDR + off + 1, HDR + off + len)
    end
    return {
        version = le_u16(b, 0),
        td_attributes = field(120, 8),
        xfam = field(128, 8),
        mr_td = field(136, 48),
        rtmr0 = field(328, 48),
        rtmr1 = field(376, 48),
        rtmr2 = field(424, 48),
        rtmr3 = field(472, 48),
        report_data = field(520, 64),
    }
end
_M._parse_quote = parse_quote
_M._looks_like_tdx_quote = looks_like_tdx_quote

-- ---------------------------------------------------------------------------
-- Locate the quote inside an arbitrary JSON document.
-- ---------------------------------------------------------------------------
local function hex_decode(s)
    if #s < MIN_QUOTE * 2 or #s % 2 ~= 0 or s:find("[^%x]") then
        return nil
    end
    return (s:gsub("%x%x", function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function find_quote(node, path, depth)
    depth = depth or 0
    if depth > 8 then
        return nil
    end
    local t = type(node)
    if t == "string" then
        if #node >= MIN_QUOTE then
            local raw = b64decode(node)
            if not raw then
                local std = node:gsub("-", "+"):gsub("_", "/")
                raw = b64decode(std)
            end
            if raw and looks_like_tdx_quote(raw) then
                return raw, path
            end
            local hx = hex_decode(node)
            if hx and looks_like_tdx_quote(hx) then
                return hx, path
            end
        end
        return nil
    elseif t == "table" then
        for k, v in pairs(node) do
            local q, p = find_quote(v, (path or "") .. "." .. tostring(k), depth + 1)
            if q then
                return q, p
            end
        end
    end
    return nil
end

-- Describe a JSON document's shape (keys, types, string lengths) for the
-- observe-mode log without dumping large blobs.
local function describe(node, depth)
    depth = depth or 0
    local t = type(node)
    if t == "table" then
        if depth > 3 then
            return "{...}"
        end
        local parts = {}
        local n = 0
        for k, v in pairs(node) do
            n = n + 1
            if n > 25 then
                parts[#parts + 1] = "..."
                break
            end
            parts[#parts + 1] = tostring(k) .. ":" .. describe(v, depth + 1)
        end
        return "{" .. table.concat(parts, ",") .. "}"
    elseif t == "string" then
        if #node <= 40 then
            return '"' .. node .. '"'
        end
        return "str[" .. #node .. "]"
    end
    return tostring(node)
end

-- ---------------------------------------------------------------------------
-- report_data binding candidates
-- ---------------------------------------------------------------------------
local function binding_candidates(nonce_raw, nonce_hex, pk_b64, pk_raw)
    return {
        { name = "sha256(nonce_raw||pk_raw)", digest = sha256_bin(nonce_raw .. (pk_raw or "")) },
        { name = "sha256(nonce_raw||pk_b64)", digest = sha256_bin(nonce_raw .. pk_b64) },
        { name = "sha256(nonce_hex||pk_b64)", digest = sha256_bin(nonce_hex .. pk_b64) },
        { name = "sha256(nonce_hex||pk_raw)", digest = sha256_bin(nonce_hex .. (pk_raw or "")) },
        { name = "sha256(pk_raw||nonce_raw)", digest = sha256_bin((pk_raw or "") .. nonce_raw) },
        { name = "sha256(pk_b64||nonce_hex)", digest = sha256_bin(pk_b64 .. nonce_hex) },
    }
end

-- ---------------------------------------------------------------------------

local function fetch_evidence(chute_id, instance_id, nonce_hex, api_key)
    local templates = {}
    if good_url_template then
        templates[1] = good_url_template
    end
    for _, t in ipairs(URL_TEMPLATES) do
        if t ~= good_url_template then
            templates[#templates + 1] = t
        end
    end

    local last_err = "no endpoint tried"
    for _, tmpl in ipairs(templates) do
        local url = tmpl:gsub("{api}", config.API_BASE)
                        :gsub("{chute_id}", chute_id)
                        :gsub("{instance_id}", instance_id)
                        :gsub("{nonce_hex}", nonce_hex)
        local t0 = ngx.now()
        local status, body, err = http_get_json(url, api_key)
        metrics.observe("e2ee_attestation_seconds", nil, ngx.now() - t0)
        if status == 200 then
            local data = cjson.decode(body)
            if data then
                good_url_template = tmpl
                return data, url
            end
            last_err = "non-JSON attestation body from " .. url
        elseif status then
            last_err = "HTTP " .. status .. " from " .. url
        else
            last_err = (err or "request failed") .. " for " .. url
        end
    end
    return nil, nil, last_err
end

local function check_measurements(q)
    local got = {
        mrtd = to_hex(q.mr_td),
        rtmr0 = to_hex(q.rtmr0),
        rtmr1 = to_hex(q.rtmr1),
        rtmr2 = to_hex(q.rtmr2),
        rtmr3 = to_hex(q.rtmr3),
    }
    local want = {
        mrtd = config.ATTEST_MRTD, rtmr0 = config.ATTEST_RTMR0, rtmr1 = config.ATTEST_RTMR1,
        rtmr2 = config.ATTEST_RTMR2, rtmr3 = config.ATTEST_RTMR3,
    }
    for _, name in ipairs({ "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3" }) do
        if want[name] ~= "" and want[name] ~= got[name] then
            return nil, string.format("%s mismatch: expected %s, got %s", name:upper(), want[name], got[name]), got
        end
    end
    return true, nil, got
end

--- Verify a parsed quote against our nonce/pubkey and the policy.
-- Exposed for tests. Returns ok, err, details.
function _M.check_quote(quote_bin, nonce_raw, e2e_pubkey_b64)
    if not looks_like_tdx_quote(quote_bin) then
        return nil, "not a TDX quote"
    end
    local q = parse_quote(quote_bin)
    local nonce_hex = to_hex(nonce_raw)
    local pk_raw = b64decode(e2e_pubkey_b64) or ""

    local matched
    for _, cand in ipairs(binding_candidates(nonce_raw, nonce_hex, e2e_pubkey_b64, pk_raw)) do
        if q.report_data:sub(1, 32) == cand.digest then
            matched = cand.name
            break
        end
    end
    if not matched then
        return nil, "report_data does not bind our nonce to this instance's e2e_pubkey "
            .. "(key not generated in the TD, or replayed quote); report_data="
            .. to_hex(q.report_data:sub(1, 32))
    end

    local debug_bit = bit.band(q.td_attributes:byte(1), 0x01) == 1
    if debug_bit and not config.ATTEST_ALLOW_DEBUG_TD then
        return nil, "TD is running in debug mode (td_attributes bit 0 set); memory is host-readable"
    end

    local ok, merr, got = check_measurements(q)
    if not ok then
        return nil, "measurement check failed: " .. merr
    end

    return true, nil, { version = q.version, binding = matched, measurements = got, debug = debug_bit }
end

--- Verify one instance's e2e_pubkey came from a genuine TD.
-- @return true, or nil plus an error string.
function _M.verify(chute_id, instance_id, e2e_pubkey_b64, api_key)
    if MODE == "off" then
        return true
    end

    local fp = to_hex(sha256_bin(e2e_pubkey_b64))
    local now = ngx.now()

    -- Cache keyed on the pubkey fingerprint too: a swapped key re-verifies.
    local cached = verified[instance_id]
    if cached and cached.pubkey_fp == fp and now < cached.expires_at then
        metrics.inc("e2ee_attestation_total", { result = "cached" })
        return true
    end

    local nonce_raw = random_bytes(32)
    if not nonce_raw or #nonce_raw ~= 32 then
        return nil, "failed to generate attestation nonce"
    end
    local nonce_hex = to_hex(nonce_raw)

    local data, url, ferr = fetch_evidence(chute_id, instance_id, nonce_hex, api_key)
    if not data then
        return nil, "attestation fetch failed: " .. (ferr or "unknown")
    end

    local quote_bin, where = find_quote(data, "", 0)
    if not quote_bin then
        return nil, "no TDX quote found in attestation response from " .. url
            .. "; response shape: " .. describe(data)
            .. " (point E2EE_ATTEST_URLS at the right endpoint if needed)"
    end

    local ok, err, details = _M.check_quote(quote_bin, nonce_raw, e2e_pubkey_b64)
    if not ok then
        return nil, err .. " [quote at " .. where .. " from " .. url .. "]"
    end

    verified[instance_id] = { pubkey_fp = fp, expires_at = now + config.ATTEST_TTL_S }
    failed[instance_id] = nil

    log.notice("attestation OK instance=", instance_id,
               " quote_v", details.version, " binding=", details.binding,
               " at=", where, " url=", url,
               " mrtd=", details.measurements.mrtd:sub(1, 16), "...",
               " (quote signature and PCK chain are NOT verified)")
    return true
end

--- Decide whether the handler may use this instance.
-- enforce: reject on failure. observe: log and allow. off: allow.
-- @return true to continue, or nil plus error
function _M.guard(chute_id, instance_id, e2e_pubkey_b64, api_key)
    if MODE == "off" then
        metrics.inc("e2ee_attestation_total", { result = "skipped" })
        return true
    end

    if MODE == "observe" then
        local fp = to_hex(sha256_bin(e2e_pubkey_b64))
        local f = failed[instance_id]
        if f and f.pubkey_fp == fp and ngx.now() < f.expires_at then
            -- Already logged recently; do not pay the round trips again.
            metrics.inc("e2ee_attestation_total", { result = "observed_failure_cached" })
            return true
        end
    end

    local ok, err = _M.verify(chute_id, instance_id, e2e_pubkey_b64, api_key)
    if ok then
        metrics.inc("e2ee_attestation_total", { result = "ok" })
        return true
    end

    if MODE == "observe" then
        metrics.inc("e2ee_attestation_total", { result = "observed_failure" })
        failed[instance_id] = {
            pubkey_fp = to_hex(sha256_bin(e2e_pubkey_b64)),
            expires_at = ngx.now() + config.ATTEST_FAIL_TTL_S,
            err = err,
        }
        log.warn("ATTESTATION FAILED (observe mode, request allowed): ", err, " instance=", instance_id)
        return true
    end

    metrics.inc("e2ee_attestation_total", { result = "failed" })
    log.err("ATTESTATION FAILED, rejecting instance: ", err, " instance=", instance_id)
    return nil, err
end

--- Drop cached verification state for an instance.
function _M.invalidate(instance_id)
    verified[instance_id] = nil
    failed[instance_id] = nil
end

--- Tests only.
function _M._reset()
    verified = {}
    failed = {}
    good_url_template = nil
end

function _M._set_mode(m)
    MODE = m
end

return _M
