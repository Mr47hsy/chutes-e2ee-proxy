--
-- e2ee_config.lua - single place where environment variables are read.
--
-- Every variable listed here must also appear as an `env NAME;` directive in
-- conf/nginx.conf.template, otherwise os.getenv() returns nil inside nginx.
--
-- Values are parsed once at module load (worker start). Nothing here is
-- secret; _M.summary() is logged at startup.
--

local _M = {}

local warnings = {}

local function warn(msg)
    warnings[#warnings + 1] = msg
end

local function env(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    return v
end

local function env_bool(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    v = v:lower()
    if v == "true" or v == "1" or v == "yes" or v == "on" then
        return true
    end
    if v == "false" or v == "0" or v == "no" or v == "off" then
        return false
    end
    warn(name .. "=" .. v .. " is not a boolean, using " .. tostring(default))
    return default
end

local function env_num(name, default, min, max)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    local n = tonumber(v)
    if not n then
        warn(name .. "=" .. v .. " is not a number, using " .. tostring(default))
        return default
    end
    if min and n < min then
        warn(name .. "=" .. v .. " below minimum " .. min .. ", clamping")
        n = min
    end
    if max and n > max then
        warn(name .. "=" .. v .. " above maximum " .. max .. ", clamping")
        n = max
    end
    return n
end

local function env_enum(name, default, allowed)
    local v = env(name, default)
    v = tostring(v):lower()
    for _, a in ipairs(allowed) do
        if v == a then
            return v
        end
    end
    warn(name .. "=" .. v .. " is not one of " .. table.concat(allowed, "|") .. ", using " .. default)
    return default
end

local function strip_trailing_slash(s)
    return (s:gsub("/+$", ""))
end

-- ---------------------------------------------------------------------------
-- Upstream endpoints
-- ---------------------------------------------------------------------------
_M.API_BASE = strip_trailing_slash(env("API_BASE", "https://api.chutes.ai"))
_M.MODELS_BASE = strip_trailing_slash(env("MODELS_BASE", "https://llm.chutes.ai"))

-- ---------------------------------------------------------------------------
-- Routing
-- ---------------------------------------------------------------------------
_M.ROUTE_MODES = { "agent", "balanced", "performance", "default" }
_M.ROUTE_MODE = env_enum("ROUTE_MODE", "balanced", _M.ROUTE_MODES)
_M.BALANCED_N = env_num("BALANCED_N", 3, 1, 64)
_M.PIN_INSTANCE_ID = env("PIN_INSTANCE_ID", nil)
_M.PERF_EWMA_ALPHA = env_num("PERF_EWMA_ALPHA", 0.3, 0.01, 1)
_M.PERF_HALF_LIFE_S = env_num("PERF_HALF_LIFE_S", 300, 5, 86400)
_M.PERF_COLD_START_S = env_num("PERF_COLD_START_S", 0.5, 0.01, 60)
-- After a 403/5xx from an instance it is avoided for this long (all modes).
_M.ROUTE_BAN_S = env_num("ROUTE_BAN_S", 60, 0, 3600)

-- ---------------------------------------------------------------------------
-- Upstream HTTP behaviour
-- ---------------------------------------------------------------------------
_M.UPSTREAM_CONNECT_TIMEOUT_MS = env_num("UPSTREAM_CONNECT_TIMEOUT_MS", 5000, 100, 600000)
_M.UPSTREAM_SEND_TIMEOUT_MS = env_num("UPSTREAM_SEND_TIMEOUT_MS", 30000, 100, 600000)
_M.UPSTREAM_READ_TIMEOUT_MS = env_num("UPSTREAM_READ_TIMEOUT_MS", 900000, 1000, 3600000)
_M.DISCOVERY_TIMEOUT_MS = env_num("DISCOVERY_TIMEOUT_MS", 30000, 1000, 600000)
_M.MODELS_TIMEOUT_MS = env_num("MODELS_TIMEOUT_MS", 10000, 1000, 600000)
_M.MODEL_MAP_TTL_S = env_num("MODEL_MAP_TTL_S", 300, 5, 86400)
_M.ALLOW_NON_CONFIDENTIAL = env_bool("ALLOW_NON_CONFIDENTIAL", false)

-- ---------------------------------------------------------------------------
-- Attestation
-- ---------------------------------------------------------------------------
-- Endpoint and report_data preimage were confirmed against api.chutes.ai on
-- 2026-09-14 (see e2ee_attest.lua), so the default is "enforce". Use
-- "observe" to log without rejecting when investigating a schema change.
_M.ATTEST_MODE = env_enum("E2EE_ATTEST", "enforce", { "enforce", "observe", "off" })
_M.ATTEST_TTL_S = env_num("E2EE_ATTEST_TTL", 600, 1, 86400)
_M.ATTEST_FAIL_TTL_S = env_num("E2EE_ATTEST_FAIL_TTL", 300, 0, 86400)
_M.ATTEST_TIMEOUT_MS = env_num("E2EE_ATTEST_TIMEOUT_MS", 10000, 500, 120000)
_M.ATTEST_ALLOW_DEBUG_TD = env_bool("E2EE_ATTEST_ALLOW_DEBUG_TD", false)
_M.ATTEST_MRTD = (env("E2EE_ATTEST_MRTD", "")):lower()
_M.ATTEST_RTMR0 = (env("E2EE_ATTEST_RTMR0", "")):lower()
_M.ATTEST_RTMR1 = (env("E2EE_ATTEST_RTMR1", "")):lower()
_M.ATTEST_RTMR2 = (env("E2EE_ATTEST_RTMR2", "")):lower()
_M.ATTEST_RTMR3 = (env("E2EE_ATTEST_RTMR3", "")):lower()
_M.ATTEST_URLS = env("E2EE_ATTEST_URLS", nil)

-- ---------------------------------------------------------------------------
-- HTTP surface
-- ---------------------------------------------------------------------------
_M.CORS_ALLOWED_ORIGINS = env("CORS_ALLOWED_ORIGINS", nil)
_M.METRICS_ENABLED = env_bool("METRICS_ENABLED", true)
_M.ALLOW_PLAINTEXT = env_bool("ALLOW_PLAINTEXT", false)

-- ---------------------------------------------------------------------------
-- Native library
-- ---------------------------------------------------------------------------
_M.E2EE_LIB_PATH = env("E2EE_LIB_PATH", "/usr/local/openresty/lib/libe2ee_proxy.so")

-- ---------------------------------------------------------------------------

function _M.warnings()
    return warnings
end

--- One-line summary for the startup log. Contains no secrets.
function _M.summary()
    return table.concat({
        "api_base=" .. _M.API_BASE,
        "models_base=" .. _M.MODELS_BASE,
        "route_mode=" .. _M.ROUTE_MODE,
        "balanced_n=" .. _M.BALANCED_N,
        "pin_instance=" .. (_M.PIN_INSTANCE_ID or "-"),
        "attest=" .. _M.ATTEST_MODE,
        "read_timeout_ms=" .. _M.UPSTREAM_READ_TIMEOUT_MS,
        "allow_non_confidential=" .. tostring(_M.ALLOW_NON_CONFIDENTIAL),
        "allow_plaintext=" .. tostring(_M.ALLOW_PLAINTEXT),
        "metrics=" .. tostring(_M.METRICS_ENABLED),
    }, " ")
end

return _M
