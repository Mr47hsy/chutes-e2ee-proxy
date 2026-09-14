--
-- e2ee_discovery.lua - model resolution and nonce management.
--
--   resolve_chute_id(model, api_key)     -> chute_id
--   get_nonce(chute_id, api_key, mode)   -> instance_info, nonce, pick_reason
--   invalidate_nonces(chute_id, instance_id)
--
-- Instance choice is delegated to instance_selector; this module only owns
-- the nonce batches and the HTTP calls.
--
-- State is module-level (single worker, see nginx.conf.template).
--

local http = require("resty.http")
local cjson = require("cjson.safe")
local config = require("e2ee_config")
local log = require("e2ee_log")
local metrics = require("metrics")
local selector = require("instance_selector")

local _M = {}

-- model_map[model_id] = { chute_id = ..., confidential = bool }
local model_map = nil
local model_map_expires = 0

-- nonce_cache[chute_id] = { instances = [...], expires_at = ts }
local nonce_cache = {}

--- Check if a string looks like a UUID
local function is_uuid(s)
    if not s or #s ~= 36 then
        return false
    end
    return s:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil
end

--- Fetch the model list from the API
local function fetch_model_map(api_key)
    local httpc = http.new()
    httpc:set_timeout(config.MODELS_TIMEOUT_MS)

    local res, err = httpc:request_uri(config.MODELS_BASE .. "/v1/models", {
        method = "GET",
        headers = {
            ["Authorization"] = "Bearer " .. api_key,
        },
        ssl_verify = true,
    })

    if not res then
        return nil, "model list request failed: " .. (err or "unknown")
    end
    if res.status ~= 200 then
        return nil, "model list returned " .. res.status
    end

    local data = cjson.decode(res.body)
    if not data or not data.data then
        return nil, "invalid model list response"
    end

    local map = {}
    for _, model in ipairs(data.data) do
        if model.id and model.chute_id then
            map[model.id] = {
                chute_id = model.chute_id,
                confidential = model.confidential_compute == true,
            }
        end
    end
    return map
end

local function check_confidential(model, entry)
    if not entry then
        return nil, "model '" .. model .. "' not found"
    end
    if not entry.confidential and not config.ALLOW_NON_CONFIDENTIAL then
        return nil, "model '" .. model .. "' is not running in confidential compute (TEE). "
            .. "E2EE requires confidential compute to guarantee privacy. "
            .. "Set ALLOW_NON_CONFIDENTIAL=true to override."
    end
    return entry.chute_id
end

--- Resolve a model name (or UUID) to a chute_id
function _M.resolve_chute_id(model, api_key)
    if is_uuid(model) then
        return model
    end

    local now = ngx.now()
    if model_map and now < model_map_expires then
        local entry = model_map[model]
        if entry then
            return check_confidential(model, entry)
        end
    end

    local map, err = fetch_model_map(api_key)
    if not map then
        if model_map and model_map[model] then
            log.warn("model list refresh failed (", err, "), using stale cache")
            return check_confidential(model, model_map[model])
        end
        return nil, "failed to resolve model '" .. model .. "': " .. (err or "unknown")
    end

    model_map = map
    model_map_expires = now + config.MODEL_MAP_TTL_S
    return check_confidential(model, map[model])
end

--- Fetch instances and nonces for a chute
local function fetch_instances(chute_id, api_key)
    local httpc = http.new()
    httpc:set_timeout(config.DISCOVERY_TIMEOUT_MS)

    local url = config.API_BASE .. "/e2e/instances/" .. chute_id
    local t0 = ngx.now()
    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = {
            ["Authorization"] = "Bearer " .. api_key,
            ["Cache-Control"] = "no-cache, no-store",
        },
        ssl_verify = true,
    })
    local rtt = ngx.now() - t0
    metrics.observe("e2ee_discovery_seconds", nil, rtt)

    if not res then
        metrics.inc("e2ee_nonce_refresh_total", { result = "error" })
        return nil, "instance discovery failed: " .. (err or "unknown")
    end
    if res.status ~= 200 then
        metrics.inc("e2ee_nonce_refresh_total", { result = "http_" .. res.status })
        return nil, "instance discovery returned " .. res.status .. ": " .. (res.body or ""):sub(1, 300)
    end

    local data = cjson.decode(res.body)
    if not data or type(data.instances) ~= "table" then
        metrics.inc("e2ee_nonce_refresh_total", { result = "invalid" })
        return nil, "invalid instance discovery response: " .. (res.body or ""):sub(1, 200)
    end

    local nonce_ttl = tonumber(data.nonce_expires_in) or 55
    local expires_at = ngx.now() + nonce_ttl

    local total_nonces = 0
    for _, inst in ipairs(data.instances) do
        if inst.nonces then
            total_nonces = total_nonces + #inst.nonces
            log.debug("  instance=", inst.instance_id,
                      " nonces=", #inst.nonces,
                      " pubkey_len=", inst.e2e_pubkey and #inst.e2e_pubkey or 0)
        end
    end
    log.info("fetched ", #data.instances, " instances with ", total_nonces,
             " nonces (TTL=", nonce_ttl, "s, rtt=", string.format("%.3f", rtt), "s) for chute ", chute_id)
    metrics.inc("e2ee_nonce_refresh_total", { result = "ok" })

    return {
        instances = data.instances,
        expires_at = expires_at,
    }
end

--- Take one nonce from the cache for a chute_id, choosing the instance via the selector.
local function take_nonce(chute_id, mode)
    local cached = nonce_cache[chute_id]
    if not cached then
        return nil
    end
    if ngx.now() >= cached.expires_at then
        nonce_cache[chute_id] = nil
        return nil
    end

    local inst, reason = selector.pick(cached.instances, chute_id, mode)
    if not inst then
        -- All nonces consumed
        nonce_cache[chute_id] = nil
        return nil
    end

    local nonce = table.remove(inst.nonces, 1)
    log.debug("take_nonce: instance=", inst.instance_id, " mode=", mode, " reason=", reason,
              " nonce_prefix=", nonce:sub(1, 8), " remaining=", #inst.nonces)
    return {
        instance_id = inst.instance_id,
        e2e_pubkey = inst.e2e_pubkey,
    }, nonce, reason
end

--- Invalidate cached nonces for a chute; also drops the selector's affinity
--- for the given instance (or the whole chute when instance_id is nil).
function _M.invalidate_nonces(chute_id, instance_id)
    nonce_cache[chute_id] = nil
    selector.invalidate(chute_id, instance_id)
end

--- Get an instance and nonce for a chute
-- @return instance_info {instance_id, e2e_pubkey}, nonce, pick_reason  (or nil, nil, err)
function _M.get_nonce(chute_id, api_key, mode)
    local inst, nonce, reason = take_nonce(chute_id, mode)
    if inst then
        return inst, nonce, reason
    end

    local cached, err = fetch_instances(chute_id, api_key)
    if not cached then
        return nil, nil, err
    end
    nonce_cache[chute_id] = cached

    inst, nonce, reason = take_nonce(chute_id, mode)
    if not inst then
        return nil, nil, "no nonces available for chute " .. chute_id
    end
    return inst, nonce, reason
end

--- Tests only.
function _M._reset()
    model_map = nil
    model_map_expires = 0
    nonce_cache = {}
end

return _M
