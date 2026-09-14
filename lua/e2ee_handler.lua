--
-- e2ee_handler.lua - main request handler and the shared E2EE round trip.
--
-- Transparently intercepts OpenAI-compatible requests, encrypts them with
-- the E2EE protocol, sends them to api.chutes.ai, and decrypts responses
-- (JSON or SSE). claude_handler / responses_handler reuse e2ee_round_trip().
--
-- Per request:
--   1. resolve model -> chute_id
--   2. pick instance + nonce (instance_selector via discovery, honouring
--      X-Route-Mode / ROUTE_MODE), attest its public key
--   3. encrypt, POST /e2e/invoke over a keep-alive TLS connection
--   4. on a nonce 403: invalidate that instance (failover) and retry once
--   5. decrypt; record TTFT for the selector; export usage to metrics
--
-- Logging rule: never log API keys or full nonces.
--

local crypto = require("e2ee_crypto")
local discovery = require("e2ee_discovery")
local attest = require("e2ee_attest")
local selector = require("instance_selector")
local config = require("e2ee_config")
local log = require("e2ee_log")
local metrics = require("metrics")
local cjson = require("cjson.safe")
local http = require("resty.http")

local _M = {}

--- Extract the API key from Authorization or x-api-key
function _M.get_api_key()
    local headers = ngx.req.get_headers()

    -- Anthropic SDK
    local key = headers["x-api-key"]
    if type(key) == "table" then
        key = key[1]
    end
    if key and key ~= "" then
        return key
    end

    -- OpenAI SDK
    local auth = headers["Authorization"]
    if type(auth) == "table" then
        auth = auth[1]
    end
    if not auth or auth == "" then
        return nil, "missing Authorization header"
    end
    key = auth:match("^[Bb]earer%s+(.+)$") or auth
    return key
end

--- Route mode for this request (header overrides env)
function _M.get_route_mode()
    local headers = ngx.req.get_headers()
    local mode = selector.resolve_mode(headers["x-route-mode"])
    return mode
end

--- Send a JSON error response
function _M.send_error(status, message)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        error = {
            message = message,
            type = "proxy_error",
        }
    }))
    return ngx.exit(status)
end

--- Write a round-trip error (raw upstream passthrough or proxy error)
function _M.send_round_err(round_err)
    if round_err.raw then
        ngx.status = round_err.status
        ngx.header.content_type = round_err.content_type or "application/json"
        ngx.print(round_err.message)
        return
    end
    return _M.send_error(round_err.status, round_err.message)
end

--- Read the request body (memory or temp file)
function _M.read_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "rb")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end
    return body
end

-- ---------------------------------------------------------------------------
-- usage / cache accounting
-- ---------------------------------------------------------------------------

local function cached_tokens_from_usage(usage)
    if type(usage) ~= "table" then
        return nil, nil
    end
    local prompt = tonumber(usage.prompt_tokens) or tonumber(usage.input_tokens)
    local cached
    local d = usage.prompt_tokens_details
    if type(d) == "table" then
        cached = tonumber(d.cached_tokens)
    end
    cached = cached or tonumber(usage.cached_tokens) or tonumber(usage.prompt_cache_hit_tokens)
        or tonumber(usage.cache_read_input_tokens)
    return prompt, cached
end

local function account_usage(model, obj)
    if type(obj) ~= "table" or type(obj.usage) ~= "table" then
        return
    end
    local prompt, cached = cached_tokens_from_usage(obj.usage)
    if prompt then
        metrics.inc("e2ee_prompt_tokens_total", { model = model }, prompt)
    end
    if cached then
        metrics.inc("e2ee_cached_tokens_total", { model = model }, cached)
    end
    if prompt or cached then
        metrics.inc("e2ee_cache_events_total", { model = model, result = (cached and cached > 0) and "hit" or "miss" })
        log.info("usage model=", model, " prompt_tokens=", prompt or "-", " cached_tokens=", cached or "-")
    end
end

local function account_usage_json(model, json_str)
    if type(json_str) ~= "string" or not json_str:find('"usage"', 1, true) then
        return
    end
    local obj = cjson.decode(json_str)
    if obj then
        account_usage(model, obj)
    end
end

local function account_usage_sse_line(model, line)
    if type(line) ~= "string" or not line:find('"usage"', 1, true) then
        return
    end
    local raw = line:match("^data:%s*(.-)%s*$")
    if raw then
        account_usage_json(model, raw)
    end
end

-- ---------------------------------------------------------------------------
-- SSE
-- ---------------------------------------------------------------------------

--- Process one SSE line. Returns event_type, data, err.
local function process_sse_line(line, stream_key, response_sk)
    line = line:gsub("\r$", "")

    if not line:match("^data: ") then
        return nil, nil, nil
    end

    local raw = line:sub(7):match("^%s*(.-)%s*$")
    if raw == "[DONE]" then
        return "done", nil, nil
    end
    if not raw or raw == "" then
        return nil, nil, nil
    end

    local event = cjson.decode(raw)
    if not event then
        return nil, nil, nil
    end

    if event.e2e_init then
        local key, err = crypto.decrypt_stream_init(response_sk, event.e2e_init)
        if not key then
            return "error", nil, "stream init failed: " .. (err or "unknown")
        end
        return "init", key, nil

    elseif event.e2e then
        if not stream_key then
            return "error", nil, "received e2e chunk before e2e_init"
        end
        local t0 = ngx.now()
        local decrypted, err = crypto.decrypt_stream_chunk(event.e2e, stream_key)
        metrics.observe("e2ee_crypto_seconds", { op = "stream_open" }, ngx.now() - t0)
        if not decrypted then
            return "error", nil, "chunk decryption failed: " .. (err or "unknown")
        end
        return "chunk", decrypted, nil

    elseif event.usage then
        return "passthrough", line, nil

    elseif event.e2e_error then
        return "chunk", "data: " .. cjson.encode({ error = event.e2e_error }), nil
    end

    return nil, nil, nil
end

-- ---------------------------------------------------------------------------
-- upstream connection
-- ---------------------------------------------------------------------------

local function connect_upstream()
    local httpc = http.new()
    httpc:set_timeouts(config.UPSTREAM_CONNECT_TIMEOUT_MS,
                       config.UPSTREAM_SEND_TIMEOUT_MS,
                       config.UPSTREAM_READ_TIMEOUT_MS)

    local parsed, perr = httpc:parse_uri(config.API_BASE .. "/e2e/invoke", false)
    if not parsed then
        return nil, nil, nil, "bad API_BASE: " .. tostring(perr)
    end
    local scheme, host, port, path = parsed[1], parsed[2], parsed[3], parsed[4]

    -- Table-form connect: lua-resty-http keys the keepalive pool on
    -- scheme/host/port/SNI/verify, and skips the TLS handshake on a reused
    -- connection. The old connect()+ssl_handshake() pair did neither.
    local ok, err = httpc:connect({
        scheme = scheme,
        host = host,
        port = port,
        ssl_verify = (scheme == "https"),
        ssl_server_name = host,
    })
    if not ok then
        return nil, nil, nil, "upstream connect failed: " .. (err or "unknown")
    end

    local reused = (httpc:get_reused_times() or 0) > 0
    metrics.inc("e2ee_upstream_connections_total", { reused = tostring(reused) })
    log.debug("upstream connection reused=", tostring(reused))
    return httpc, host, path, nil
end

local function classify_error(status)
    if status >= 500 then
        return "5xx"
    elseif status == 403 then
        return "other_403"
    else
        return "4xx"
    end
end

-- ---------------------------------------------------------------------------
-- round trip
-- ---------------------------------------------------------------------------

--- E2EE round trip: encrypt request, send, decrypt response.
-- Non-streaming: returns decrypted_json or (nil, {status=, message=, raw=?})
-- Streaming: calls on_chunk(line) per decrypted SSE data line, on_chunk(nil) at end
-- @param opts  optional { mode = route mode, model_label = string }
function _M.e2ee_round_trip(api_key, model, body_json, is_streaming, e2e_path, on_chunk, opts)
    opts = opts or {}
    local mode = opts.mode or _M.get_route_mode()
    local path_label = e2e_path or "/v1/unknown"
    local err

    local function fail(status, message, class, raw, content_type)
        metrics.inc("e2ee_requests_total", { path = path_label, mode = mode, outcome = "error" })
        if class then
            metrics.inc("e2ee_upstream_errors_total", { class = class })
        end
        return nil, { status = status, message = message, raw = raw, content_type = content_type }
    end

    -- Resolve model -> chute_id
    local chute_id
    chute_id, err = discovery.resolve_chute_id(model, api_key)
    if not chute_id then
        return fail(404, err)
    end

    local res, httpc, response_sk, instance, nonce
    for attempt = 1, 2 do
        -- Pick an instance whose key passes attestation. A rejected instance is
        -- dropped from affinity and a fresh discovery round is forced.
        local att_err
        for pick = 1, 3 do
            local reason
            instance, nonce, reason = discovery.get_nonce(chute_id, api_key, mode)
            if not instance then
                return fail(503, reason) -- get_nonce returns nil, nil, err
            end
            local att_ok
            att_ok, att_err = attest.guard(chute_id, instance.instance_id, instance.e2e_pubkey, api_key)
            if att_ok then
                att_err = nil
                log.debug("attempt ", attempt, ": instance=", instance.instance_id,
                          " mode=", mode, " reason=", reason, " chute=", chute_id)
                break
            end
            log.warn("attestation rejected instance ", instance.instance_id, " (pick ", pick, "/3): ", att_err)
            attest.invalidate(instance.instance_id)
            discovery.invalidate_nonces(chute_id, instance.instance_id)
            instance = nil
        end
        if not instance then
            return fail(502, "TEE attestation failed: " .. (att_err or "unknown"), "attest")
        end

        -- Encrypt
        local t_seal = ngx.now()
        local blob
        blob, response_sk, err = crypto.build_e2ee_request(instance.e2e_pubkey, body_json)
        metrics.observe("e2ee_crypto_seconds", { op = "seal" }, ngx.now() - t_seal)
        if not blob then
            return fail(500, "encryption failed: " .. (err or "unknown"))
        end

        -- Connect + send
        local host, path, cerr
        httpc, host, path, cerr = connect_upstream()
        if not httpc then
            selector.invalidate(chute_id, instance.instance_id)
            return fail(502, cerr, "connect")
        end

        local t_send = ngx.now()
        res, err = httpc:request({
            method = "POST",
            path = path,
            body = blob,
            headers = {
                ["Host"] = host,
                ["Authorization"] = "Bearer " .. api_key,
                ["X-Chute-Id"] = chute_id,
                ["X-Instance-Id"] = instance.instance_id,
                ["X-E2E-Nonce"] = nonce,
                ["X-E2E-Stream"] = tostring(is_streaming),
                ["X-E2E-Path"] = e2e_path,
                ["Content-Type"] = "application/octet-stream",
                ["Content-Length"] = tostring(#blob),
            },
        })

        if not res then
            httpc:close()
            selector.record(chute_id, instance.instance_id, nil, false)
            selector.invalidate(chute_id, instance.instance_id)
            local class = (err and err:find("timeout", 1, true)) and "timeout" or "connect"
            return fail(502, "upstream request failed: " .. (err or "unknown"), class)
        end
        instance.ttfb = ngx.now() - t_send

        -- Retry once on a nonce 403; failover happens through invalidate.
        if res.status == 403 and attempt < 2 then
            local err_body = res:read_body() or ""
            log.warn("403 on attempt ", attempt, ": instance=", instance.instance_id,
                     " nonce_prefix=", nonce:sub(1, 8), " chute=", chute_id,
                     " body=", err_body:sub(1, 200))
            if err_body:find("nonce") then
                metrics.inc("e2ee_upstream_errors_total", { class = "nonce_403" })
                log.warn("nonce rejected, retrying on another instance")
                httpc:close()
                discovery.invalidate_nonces(chute_id, instance.instance_id)
            else
                httpc:set_keepalive()
                return fail(403, err_body, "other_403", true)
            end
        else
            break
        end
    end

    ngx.header["X-E2EE-Instance-Id"] = instance.instance_id
    ngx.header["X-E2EE-Route-Mode"] = mode

    -- Non-200: pass the upstream error through
    if res.status ~= 200 then
        local err_body = res:read_body() or ""
        httpc:set_keepalive()
        selector.record(chute_id, instance.instance_id, nil, false)
        if res.status >= 500 then
            selector.invalidate(chute_id, instance.instance_id)
        end
        return fail(res.status, err_body, classify_error(res.status), true, res.headers["Content-Type"])
    end

    if not is_streaming then
        local response_blob = res:read_body()
        if not response_blob or #response_blob == 0 then
            httpc:set_keepalive()
            selector.record(chute_id, instance.instance_id, nil, false)
            return fail(502, "empty response from upstream", "empty")
        end

        local t_open = ngx.now()
        local decrypted
        decrypted, err = crypto.decrypt_response(response_blob, response_sk)
        metrics.observe("e2ee_crypto_seconds", { op = "open" }, ngx.now() - t_open)
        httpc:set_keepalive()
        if not decrypted then
            selector.record(chute_id, instance.instance_id, nil, false)
            return fail(502, "failed to decrypt response: " .. (err or "unknown"), "decrypt")
        end

        selector.record(chute_id, instance.instance_id, instance.ttfb, true)
        metrics.observe("e2ee_ttft_seconds", { mode = mode }, instance.ttfb)
        metrics.inc("e2ee_requests_total", { path = path_label, mode = mode, outcome = "ok" })
        account_usage_json(model, decrypted)
        return decrypted, nil
    end

    -- Streaming: parse SSE, decrypt chunks, call on_chunk for each
    local reader = res.body_reader
    if not reader then
        httpc:set_keepalive()
        return fail(502, "no body reader")
    end

    local buffer = ""
    local stream_key = nil
    local done_sent = false
    local first_chunk_at = nil
    local t_stream0 = ngx.now()
    local had_error = false

    local function deliver(line)
        if not first_chunk_at then
            first_chunk_at = ngx.now()
            local ttft = first_chunk_at - t_stream0 + (instance.ttfb or 0)
            selector.record(chute_id, instance.instance_id, ttft, true)
            metrics.observe("e2ee_ttft_seconds", { mode = mode }, ttft)
        end
        metrics.inc("e2ee_stream_chunks_total", nil, 1)
        account_usage_sse_line(model, line)
        on_chunk(line)
    end

    local function handle(event_type, data, event_err)
        if event_type == "init" then
            stream_key = data
        elseif event_type == "chunk" or event_type == "passthrough" then
            deliver(data)
        elseif event_type == "done" then
            on_chunk(nil)
            done_sent = true
        elseif event_type == "error" then
            had_error = true
            log.err("stream error: ", event_err)
            metrics.inc("e2ee_upstream_errors_total", { class = "decrypt" })
            on_chunk("data: " .. cjson.encode({ error = { message = event_err, type = "proxy_error" } }))
            on_chunk(nil)
            done_sent = true
        end
    end

    while not done_sent do
        local chunk
        chunk, err = reader(8192)
        if err then
            log.err("stream read error: ", err)
            metrics.inc("e2ee_upstream_errors_total", { class = err:find("timeout", 1, true) and "timeout" or "5xx" })
            had_error = true
            break
        end
        if not chunk then
            break
        end

        buffer = buffer .. chunk
        while not done_sent do
            local pos = buffer:find("\n", 1, true)
            if not pos then
                break
            end
            local line = buffer:sub(1, pos - 1)
            buffer = buffer:sub(pos + 1)
            if line ~= "" then
                handle(process_sse_line(line, stream_key, response_sk))
            end
        end
    end

    -- Trailing partial line
    if buffer ~= "" and not done_sent then
        local event_type, data = process_sse_line(buffer, stream_key, response_sk)
        if event_type == "chunk" or event_type == "passthrough" then
            deliver(data)
        elseif event_type == "done" then
            on_chunk(nil)
            done_sent = true
        end
    end

    if not done_sent then
        on_chunk(nil)
    end

    if had_error then
        httpc:close()
        selector.record(chute_id, instance.instance_id, nil, false)
        metrics.inc("e2ee_requests_total", { path = path_label, mode = mode, outcome = "stream_error" })
    else
        httpc:set_keepalive()
        if not first_chunk_at then
            selector.record(chute_id, instance.instance_id, instance.ttfb, true)
        end
        metrics.inc("e2ee_requests_total", { path = path_label, mode = mode, outcome = "ok" })
    end
    return true, nil
end

-- ---------------------------------------------------------------------------
-- content handler for /v1/* (OpenAI-compatible passthrough)
-- ---------------------------------------------------------------------------

function _M.handle()
    local body = _M.read_body()
    if not body then
        return _M.send_error(400, "missing request body")
    end

    local payload = cjson.decode(body)
    if not payload then
        return _M.send_error(400, "invalid JSON body")
    end

    local model = payload.model
    if not model then
        return _M.send_error(400, "missing 'model' field")
    end

    local is_streaming = (payload.stream == true)
    local original_path = ngx.var.uri

    local api_key, err = _M.get_api_key()
    if not api_key then
        return _M.send_error(401, err)
    end

    if not is_streaming then
        local decrypted, round_err = _M.e2ee_round_trip(api_key, model, body, false, original_path)
        if not decrypted then
            return _M.send_round_err(round_err)
        end
        ngx.header.content_type = "application/json"
        ngx.print(decrypted)
        return
    end

    ngx.header.content_type = "text/event-stream"
    ngx.header.cache_control = "no-cache"
    ngx.header["X-Accel-Buffering"] = "no"

    local _, round_err = _M.e2ee_round_trip(api_key, model, body, true, original_path,
        function(line)
            if line == nil then
                ngx.print("data: [DONE]\n\n")
                ngx.flush(true)
            else
                local trimmed = line:gsub("%s+$", "")
                if trimmed ~= "" then
                    ngx.print(trimmed .. "\n\n")
                    ngx.flush(true)
                end
            end
        end)

    if round_err then
        _M.send_round_err(round_err)
    end
end

return _M
