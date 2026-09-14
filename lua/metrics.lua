--
-- metrics.lua - minimal Prometheus text-format registry.
--
-- Module-level tables are per worker; conf/nginx.conf.template pins
-- worker_processes to 1, so this is process-global. If workers are ever
-- increased, move the series into lua_shared_dict with atomic incr().
--
-- API:
--   metrics.inc(name, labels, delta)
--   metrics.set(name, labels, value)
--   metrics.observe(name, labels, value)     -- histograms
--   metrics.render() -> string                -- exposition format
--   metrics.handler()                         -- nginx content handler
--   metrics.reset()                           -- tests only
--

local _M = {}

local registry = {}
local order = {}

local function define(name, kind, help, buckets)
    registry[name] = { kind = kind, help = help, buckets = buckets, series = {}, series_order = {} }
    order[#order + 1] = name
end

-- ---------------------------------------------------------------------------
-- Metric definitions
-- ---------------------------------------------------------------------------
local TTFT_BUCKETS = { 0.25, 0.5, 1, 2, 3, 5, 8, 13, 21, 34, 60, 120 }
local CRYPTO_BUCKETS = { 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5 }
local RTT_BUCKETS = { 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 30 }

define("e2ee_build_info", "gauge", "Build information (value is always 1).")
define("e2ee_requests_total", "counter", "Proxied requests by path, route mode and outcome.")
define("e2ee_upstream_errors_total", "counter",
    "Upstream failures by class (nonce_403, other_403, 4xx, 5xx, timeout, connect, decrypt, attest, empty).")
define("e2ee_ttft_seconds", "histogram", "Time from sending the encrypted request to the first byte/chunk, by route mode.", TTFT_BUCKETS)
define("e2ee_crypto_seconds", "histogram", "Time spent in E2EE seal/open operations.", CRYPTO_BUCKETS)
define("e2ee_prompt_tokens_total", "counter", "Prompt tokens reported by upstream usage, by model.")
define("e2ee_cached_tokens_total", "counter", "Cached prompt tokens reported by upstream usage, by model.")
define("e2ee_cache_events_total", "counter", "Requests with usage data, by model and whether any cached tokens were reported.")
define("e2ee_instance_picks_total", "counter", "Instance selections by chute, mode, instance and reason.")
define("e2ee_affinity_total", "counter", "Whether the picked instance was already sticky (hit) or newly chosen (miss), by mode.")
define("e2ee_instance_ttft_ewma_seconds", "gauge", "Decayed EWMA of TTFT per instance (performance mode input).")
define("e2ee_nonce_refresh_total", "counter", "Calls to /e2e/instances by result.")
define("e2ee_discovery_seconds", "histogram", "Round-trip time of /e2e/instances.", RTT_BUCKETS)
define("e2ee_attestation_total", "counter", "Attestation verifications by result (ok, cached, failed, skipped, observed_failure).")
define("e2ee_attestation_seconds", "histogram", "Round-trip time of attestation fetches.", RTT_BUCKETS)
define("e2ee_upstream_connections_total", "counter", "Upstream connections by whether they were reused from the keepalive pool.")
define("e2ee_stream_chunks_total", "counter", "Decrypted streaming chunks delivered to clients.")

-- ---------------------------------------------------------------------------
-- Internals
-- ---------------------------------------------------------------------------
local function escape(v)
    return (tostring(v):gsub("\\", "\\\\"):gsub("\n", "\\n"):gsub('"', '\\"'))
end

local function label_key(labels)
    if not labels then
        return ""
    end
    local keys = {}
    for k in pairs(labels) do
        keys[#keys + 1] = k
    end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do
        parts[#parts + 1] = k .. '="' .. escape(labels[k]) .. '"'
    end
    return table.concat(parts, ",")
end

local function series(name, labels)
    local m = registry[name]
    if not m then
        return nil
    end
    local key = label_key(labels)
    local s = m.series[key]
    if not s then
        s = { key = key }
        if m.kind == "histogram" then
            s.counts = {}
            for i = 1, #m.buckets do
                s.counts[i] = 0
            end
            s.sum = 0
            s.count = 0
        else
            s.value = 0
        end
        m.series[key] = s
        m.series_order[#m.series_order + 1] = key
    end
    return s, m
end

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------
local function kind_of(name)
    local m = registry[name]
    return m and m.kind or nil
end

function _M.inc(name, labels, delta)
    local kind = kind_of(name)
    if kind ~= "counter" and kind ~= "gauge" then
        return
    end
    local s = series(name, labels)
    s.value = s.value + (delta or 1)
end

function _M.set(name, labels, value)
    local kind = kind_of(name)
    if kind ~= "counter" and kind ~= "gauge" then
        return
    end
    local s = series(name, labels)
    s.value = value
end

function _M.observe(name, labels, value)
    if kind_of(name) ~= "histogram" or type(value) ~= "number" then
        return
    end
    local s, m = series(name, labels)
    for i, b in ipairs(m.buckets) do
        if value <= b then
            s.counts[i] = s.counts[i] + 1
        end
    end
    s.sum = s.sum + value
    s.count = s.count + 1
end

--- Register a callback that refreshes gauges right before rendering.
local collectors = {}
function _M.add_collector(fn)
    collectors[#collectors + 1] = fn
end

local function fmt_num(v)
    if v == math.huge then
        return "+Inf"
    end
    if v == math.floor(v) and math.abs(v) < 1e15 then
        return string.format("%d", v)
    end
    return string.format("%.6g", v)
end

function _M.render()
    for _, fn in ipairs(collectors) do
        pcall(fn)
    end

    local out = {}
    for _, name in ipairs(order) do
        local m = registry[name]
        if #m.series_order > 0 then
            out[#out + 1] = "# HELP " .. name .. " " .. m.help
            out[#out + 1] = "# TYPE " .. name .. " " .. m.kind
            for _, key in ipairs(m.series_order) do
                local s = m.series[key]
                if m.kind == "histogram" then
                    local sep = key ~= "" and "," or ""
                    for i, b in ipairs(m.buckets) do
                        out[#out + 1] = string.format('%s_bucket{%s%sle="%s"} %s',
                            name, key, sep, fmt_num(b), fmt_num(s.counts[i]))
                    end
                    out[#out + 1] = string.format('%s_bucket{%s%sle="+Inf"} %s', name, key, sep, fmt_num(s.count))
                    out[#out + 1] = string.format("%s_sum%s %s", name, key ~= "" and "{" .. key .. "}" or "", fmt_num(s.sum))
                    out[#out + 1] = string.format("%s_count%s %s", name, key ~= "" and "{" .. key .. "}" or "", fmt_num(s.count))
                else
                    out[#out + 1] = string.format("%s%s %s", name, key ~= "" and "{" .. key .. "}" or "", fmt_num(s.value))
                end
            end
        end
    end
    out[#out + 1] = ""
    return table.concat(out, "\n")
end

--- nginx content handler for GET /metrics
function _M.handler()
    local config = require("e2ee_config")
    if not config.METRICS_ENABLED then
        ngx.status = 404
        ngx.header.content_type = "application/json"
        ngx.say('{"error":{"message":"metrics disabled (METRICS_ENABLED=false)","type":"proxy_error"}}')
        return ngx.exit(404)
    end
    ngx.header.content_type = "text/plain; version=0.0.4; charset=utf-8"
    ngx.print(_M.render())
end

function _M.reset()
    for _, name in ipairs(order) do
        registry[name].series = {}
        registry[name].series_order = {}
    end
end

-- Exposed for tests / introspection
function _M._registry()
    return registry
end

return _M
