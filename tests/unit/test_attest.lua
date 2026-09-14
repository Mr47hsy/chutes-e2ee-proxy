local T = require("ngx_mock")
local sha256 = require("sha256_pure")
local config = require("e2ee_config")
local attest = require("e2ee_attest")

-- Inject test dependencies (production uses resty.sha256 / resty.random / resty.http)
attest._deps.sha256 = sha256
attest._deps.b64decode = ngx.decode_base64

local NONCE = string.rep("\x11", 32)
attest._deps.random_bytes = function(n)
    return NONCE:sub(1, n)
end

local function to_hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function from_hex(h)
    return (h:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
end

local PK_RAW = string.rep("\xAB", 1184)
local PK_B64 = ngx.encode_base64(PK_RAW)

-- Build a synthetic 632-byte TDX quote (header 48 + TDReport10 body 584).
-- Field offsets follow Intel's TDReport10 layout, including the 8-byte xfam.
local function build_quote(opts)
    opts = opts or {}
    local function le16(v) return string.char(v % 256, math.floor(v / 256) % 256) end
    local function le32(v)
        return string.char(v % 256, math.floor(v / 256) % 256, math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256)
    end
    local header = le16(opts.version or 4) .. le16(opts.att_key_type or 2) .. le32(opts.tee_type or 0x81)
        .. le16(0) .. le16(0) .. string.rep("\0", 16) .. string.rep("\0", 20)
    assert(#header == 48)

    local report_data = opts.report_data or (sha256(NONCE .. PK_RAW) .. string.rep("\0", 32))
    assert(#report_data == 64)
    local td_attributes = opts.td_attributes or string.rep("\0", 8)
    local body = string.rep("\1", 16)          -- tee_tcb_svn      +0
        .. string.rep("\2", 48)                 -- mr_seam          +16
        .. string.rep("\3", 48)                 -- mr_signer_seam   +64
        .. string.rep("\4", 8)                  -- seam_attributes  +112
        .. td_attributes                        -- td_attributes    +120
        .. string.rep("\5", 8)                  -- xfam             +128
        .. (opts.mr_td or string.rep("\6", 48)) -- mr_td            +136
        .. string.rep("\7", 48)                 -- mr_config_id     +184
        .. string.rep("\8", 48)                 -- mr_owner         +232
        .. string.rep("\9", 48)                 -- mr_owner_config  +280
        .. (opts.rtmr0 or string.rep("\10", 48))-- rtmr0            +328
        .. string.rep("\11", 48)                -- rtmr1            +376
        .. string.rep("\12", 48)                -- rtmr2            +424
        .. string.rep("\13", 48)                -- rtmr3            +472
        .. report_data                          -- report_data      +520
    assert(#body == 584, "body must be 584 bytes, got " .. #body)
    return header .. body .. (opts.trailer or string.rep("\0", 100)) -- signature section, ignored
end

T.test("quote layout: 48 + 584 = 632 and field offsets", function()
    local q = build_quote()
    T.truthy(#q >= attest.MIN_QUOTE_LEN)
    T.eq(attest.MIN_QUOTE_LEN, 632)
    local p = attest._parse_quote(q)
    T.eq(p.version, 4)
    T.eq(p.xfam, string.rep("\5", 8))
    T.eq(p.mr_td, string.rep("\6", 48))
    T.eq(p.rtmr0, string.rep("\10", 48))
    T.eq(p.rtmr3, string.rep("\13", 48))
    T.eq(p.report_data:sub(1, 32), sha256(NONCE .. PK_RAW))
end)

T.test("looks_like_tdx_quote rejects wrong header fields", function()
    T.truthy(attest._looks_like_tdx_quote(build_quote()))
    T.truthy(attest._looks_like_tdx_quote(build_quote({ version = 5 })))
    T.falsy(attest._looks_like_tdx_quote(build_quote({ version = 3 })))
    T.falsy(attest._looks_like_tdx_quote(build_quote({ att_key_type = 3 })))
    T.falsy(attest._looks_like_tdx_quote(build_quote({ tee_type = 0 })), "SGX tee_type rejected")
    T.falsy(attest._looks_like_tdx_quote(build_quote():sub(1, 600)), "too short")
end)

T.test("check_quote: binding sha256(nonce_raw||pk_raw) accepted", function()
    local ok, err, details = attest.check_quote(build_quote(), NONCE, PK_B64)
    T.truthy(ok, err)
    T.eq(details.binding, "sha256(nonce_raw||pk_raw)")
    T.eq(details.measurements.mrtd, to_hex(string.rep("\6", 48)))
end)

T.test("check_quote: alternative encodings are also recognised", function()
    local nonce_hex = to_hex(NONCE)
    local q = build_quote({ report_data = sha256(nonce_hex .. PK_B64) .. string.rep("\0", 32) })
    local ok, _, details = attest.check_quote(q, NONCE, PK_B64)
    T.truthy(ok)
    T.eq(details.binding, "sha256(nonce_hex||pk_b64)")
end)

T.test("check_quote: wrong nonce (replay) rejected", function()
    local q = build_quote({ report_data = sha256(string.rep("\x22", 32) .. PK_RAW) .. string.rep("\0", 32) })
    local ok, err = attest.check_quote(q, NONCE, PK_B64)
    T.falsy(ok)
    T.truthy(err:find("does not bind", 1, true), err)
end)

T.test("check_quote: swapped public key rejected", function()
    local other_pk = ngx.encode_base64(string.rep("\xCD", 1184))
    local ok, err = attest.check_quote(build_quote(), NONCE, other_pk)
    T.falsy(ok)
    T.truthy(err:find("does not bind", 1, true), err)
end)

T.test("check_quote: debug TD rejected unless allowed", function()
    local q = build_quote({ td_attributes = "\1" .. string.rep("\0", 7) })
    local ok, err = attest.check_quote(q, NONCE, PK_B64)
    T.falsy(ok)
    T.truthy(err:find("debug mode", 1, true), err)
    config.ATTEST_ALLOW_DEBUG_TD = true
    ok = attest.check_quote(q, NONCE, PK_B64)
    T.truthy(ok)
    config.ATTEST_ALLOW_DEBUG_TD = false
end)

T.test("check_quote: MRTD / RTMR allowlist", function()
    config.ATTEST_MRTD = to_hex(string.rep("\6", 48))
    T.truthy(attest.check_quote(build_quote(), NONCE, PK_B64))
    config.ATTEST_MRTD = to_hex(string.rep("\x66", 48))
    local ok, err = attest.check_quote(build_quote(), NONCE, PK_B64)
    T.falsy(ok)
    T.truthy(err:find("MRTD mismatch", 1, true), err)
    config.ATTEST_MRTD = ""
    config.ATTEST_RTMR0 = to_hex(string.rep("\10", 48))
    T.truthy(attest.check_quote(build_quote(), NONCE, PK_B64))
    config.ATTEST_RTMR0 = "00"
    ok, err = attest.check_quote(build_quote(), NONCE, PK_B64)
    T.falsy(ok)
    T.truthy(err:find("RTMR0 mismatch", 1, true), err)
    config.ATTEST_RTMR0 = ""
end)

-- ---------------------------------------------------------------------------
-- verify / guard with a fake attestation endpoint
-- ---------------------------------------------------------------------------
local function fake_endpoint(shape)
    -- Returns a fetch function that produces a quote bound to the nonce in the URL.
    local calls = 0
    local fn = function(url, api_key)
        calls = calls + 1
        T.eq(api_key, "cpk_test")
        local nonce_hex = url:match("nonce=(%x+)")
        if not nonce_hex then
            return 400, "no nonce", nil
        end
        local nonce_raw = from_hex(nonce_hex)
        local q = build_quote({ report_data = sha256(nonce_raw .. PK_RAW) .. string.rep("\0", 32) })
        local body = shape(ngx.encode_base64(q), to_hex(q))
        return 200, body, nil
    end
    return fn, function() return calls end
end

T.test("verify: finds a base64 quote in a nested field", function()
    attest._reset()
    attest._set_mode("enforce")
    local fetch = fake_endpoint(function(b64)
        return T.json.encode({ evidence = { tdx = { quote = b64 }, note = "x" } })
    end)
    attest._deps.fetch = fetch
    local ok, err = attest.verify("chute1", "inst-1", PK_B64, "cpk_test")
    T.truthy(ok, err)
    T.truthy(T.log_contains("attestation OK instance=inst-1"))
end)

T.test("verify: evidence array with several instances' quotes, ours not first", function()
    attest._reset()
    attest._set_mode("enforce")
    attest._deps.fetch = function(url)
        local nonce_raw = from_hex(url:match("nonce=(%x+)"))
        local other = build_quote({ report_data = sha256(nonce_raw .. string.rep("\xCD", 1184)) .. string.rep("\0", 32) })
        local ours = build_quote({ report_data = sha256(to_hex(nonce_raw) .. PK_B64) .. string.rep("\0", 32) })
        local arr = setmetatable({
            { instance_id = "other", quote = ngx.encode_base64(other) },
            { instance_id = "inst-11", quote = ngx.encode_base64(ours) },
        }, { __jsontype = "array" })
        return 200, T.json.encode({ evidence = arr }), nil
    end
    local ok, err = attest.verify("chute1", "inst-11", PK_B64, "cpk_test")
    T.truthy(ok, err)
    T.truthy(T.log_contains("binding=sha256(nonce_hex||pk_b64)"), "live binding formula recognised")
    T.truthy(T.log_contains("at=.evidence.2.quote"), "second array element matched")
    -- and a response where no quote binds our key is rejected, naming the count
    attest._reset()
    attest._deps.fetch = function(url)
        local nonce_raw = from_hex(url:match("nonce=(%x+)"))
        local other = build_quote({ report_data = sha256(nonce_raw .. string.rep("\xCD", 1184)) .. string.rep("\0", 32) })
        return 200, T.json.encode({ evidence = setmetatable({ { quote = ngx.encode_base64(other) },
                                                              { quote = ngx.encode_base64(other) } }, { __jsontype = "array" }) }), nil
    end
    ok, err = attest.verify("chute1", "inst-12", PK_B64, "cpk_test")
    T.falsy(ok)
    T.truthy(err:find("none of 2 quote", 1, true), err)
end)

T.test("verify: finds a hex quote", function()
    attest._reset()
    attest._deps.fetch = fake_endpoint(function(_, hex)
        return T.json.encode({ quote = hex })
    end)
    T.truthy(attest.verify("chute1", "inst-2", PK_B64, "cpk_test"))
end)

T.test("verify: response without a quote fails with a shape description", function()
    attest._reset()
    attest._deps.fetch = function()
        return 200, T.json.encode({ status = "ok", data = { foo = "bar" } }), nil
    end
    local ok, err = attest.verify("chute1", "inst-3", PK_B64, "cpk_test")
    T.falsy(ok)
    T.truthy(err:find("no TDX quote found", 1, true), err)
    T.truthy(err:find("response shape", 1, true), err)
end)

T.test("verify: all endpoints 404 -> fetch failed", function()
    attest._reset()
    attest._deps.fetch = function()
        return 404, "nope", nil
    end
    local ok, err = attest.verify("chute1", "inst-4", PK_B64, "cpk_test")
    T.falsy(ok)
    T.truthy(err:find("attestation fetch failed", 1, true), err)
    T.truthy(err:find("HTTP 404", 1, true), err)
end)

T.test("verify: result cached per instance+pubkey, re-verified when key changes", function()
    attest._reset()
    local fetch, calls = fake_endpoint(function(b64) return T.json.encode({ quote = b64 }) end)
    attest._deps.fetch = fetch
    T.truthy(attest.verify("chute1", "inst-5", PK_B64, "cpk_test"))
    T.truthy(attest.verify("chute1", "inst-5", PK_B64, "cpk_test"))
    T.eq(calls(), 1, "second call served from cache")
    local other = ngx.encode_base64(string.rep("\xCD", 1184))
    local ok = attest.verify("chute1", "inst-5", other, "cpk_test")
    T.falsy(ok, "swapped key must not pass (quote binds the original key)")
    T.eq(calls(), 2)
    T.advance(config.ATTEST_TTL_S + 1)
    T.truthy(attest.verify("chute1", "inst-5", PK_B64, "cpk_test"))
    T.eq(calls(), 3, "expired cache re-fetches")
end)

T.test("verify: remembers the endpoint that worked", function()
    attest._reset()
    local urls = {}
    attest._deps.fetch = function(url)
        urls[#urls + 1] = url
        if url:find("/instances/", 1, true) and url:find("/evidence", 1, true) then
            local nonce_raw = from_hex(url:match("nonce=(%x+)"))
            local q = build_quote({ report_data = sha256(nonce_raw .. PK_RAW) .. string.rep("\0", 32) })
            return 200, T.json.encode({ quote = ngx.encode_base64(q) }), nil
        end
        return 404, "", nil
    end
    T.truthy(attest.verify("chute1", "inst-6", PK_B64, "cpk_test"))
    local n_first = #urls
    T.truthy(n_first >= 2, "probed several candidates")
    T.truthy(attest.verify("chute1", "inst-7", PK_B64, "cpk_test"))
    T.eq(#urls, n_first + 1, "second instance hit the known-good endpoint first")
    T.truthy(urls[#urls]:find("/instances/", 1, true) and urls[#urls]:find("/evidence", 1, true))
end)

T.test("guard: enforce rejects, observe allows and logs, off skips", function()
    attest._reset()
    attest._deps.fetch = function() return 404, "", nil end

    attest._set_mode("enforce")
    local ok, err = attest.guard("chute1", "inst-8", PK_B64, "cpk_test")
    T.falsy(ok)
    T.truthy(err)
    T.truthy(T.log_contains("rejecting instance"))

    T.reset()
    attest._set_mode("observe")
    ok = attest.guard("chute1", "inst-8", PK_B64, "cpk_test")
    T.truthy(ok)
    T.truthy(T.log_contains("observe mode, request allowed"))

    T.reset()
    attest._set_mode("off")
    T.truthy(attest.guard("chute1", "inst-8", PK_B64, "cpk_test"))
    T.eq(#T.logs, 0, "off mode is silent")
end)

T.test("guard(observe): failures are negatively cached to avoid re-probing every request", function()
    attest._reset()
    attest._set_mode("observe")
    local calls = 0
    attest._deps.fetch = function()
        calls = calls + 1
        return 404, "", nil
    end
    T.truthy(attest.guard("chute1", "inst-9", PK_B64, "cpk_test"))
    local after_first = calls
    T.truthy(attest.guard("chute1", "inst-9", PK_B64, "cpk_test"))
    T.eq(calls, after_first, "no new probes while failure is cached")
    T.advance(config.ATTEST_FAIL_TTL_S + 1)
    T.truthy(attest.guard("chute1", "inst-9", PK_B64, "cpk_test"))
    T.truthy(calls > after_first, "re-probed after fail TTL")
end)

T.test("guard metrics: first verification is ok, repeat is cached", function()
    attest._reset()
    attest._set_mode("enforce")
    local metrics = require("metrics")
    metrics.reset()
    attest._deps.fetch = fake_endpoint(function(b64) return T.json.encode({ quote = b64 }) end)
    T.truthy(attest.guard("chute1", "inst-13", PK_B64, "cpk_test"))
    T.truthy(attest.guard("chute1", "inst-13", PK_B64, "cpk_test"))
    local text = metrics.render()
    T.truthy(text:find('e2ee_attestation_total{result="ok"} 1', 1, true), text)
    T.truthy(text:find('e2ee_attestation_total{result="cached"} 1', 1, true), text)
end)

T.test("invalidate drops cached state", function()
    attest._reset()
    attest._set_mode("enforce")
    local fetch, calls = fake_endpoint(function(b64) return T.json.encode({ quote = b64 }) end)
    attest._deps.fetch = fetch
    T.truthy(attest.verify("chute1", "inst-10", PK_B64, "cpk_test"))
    attest.invalidate("inst-10")
    T.truthy(attest.verify("chute1", "inst-10", PK_B64, "cpk_test"))
    T.eq(calls(), 2)
end)

T.finish("e2ee_attest")
