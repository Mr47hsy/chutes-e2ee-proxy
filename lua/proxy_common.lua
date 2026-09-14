--
-- proxy_common.lua - phase handlers shared by every server block.
--
--   access()         request id + CORS preflight
--   header_filter()  CORS headers + X-Request-Id on every response
--   health()         GET /health
--   init_worker()    library init + startup banner
--

local cors = require("cors")
local config = require("e2ee_config")
local log = require("e2ee_log")

local _M = {}

local MAX_RID_LEN = 128

local function sanitize_rid(v)
    if type(v) == "table" then
        v = v[1]
    end
    if type(v) ~= "string" or v == "" or #v > MAX_RID_LEN then
        return nil
    end
    if v:find("[^%w%-_%.:]") then
        return nil
    end
    return v
end

--- access phase: assign request id, answer CORS preflight.
function _M.access()
    local headers = ngx.req.get_headers()
    local rid = sanitize_rid(headers["x-request-id"]) or ngx.var.request_id
    ngx.ctx.request_id = rid
    -- expose to the access log format
    ngx.var.e2ee_request_id = rid

    if ngx.req.get_method() == "OPTIONS" then
        cors.apply(headers["origin"], true, headers["access-control-request-headers"])
        ngx.header["Content-Length"] = "0"
        return ngx.exit(204)
    end
end

--- header_filter phase: CORS + request id echo.
function _M.header_filter()
    local origin = ngx.var.http_origin
    cors.apply(origin, false)
    if ngx.ctx.request_id then
        ngx.header["X-Request-Id"] = ngx.ctx.request_id
    end
end

--- GET /health
function _M.health()
    local crypto = require("e2ee_crypto")
    local cjson = require("cjson.safe")
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        status = "ok",
        route_mode = config.ROUTE_MODE,
        attestation = config.ATTEST_MODE,
        native = crypto.build_info(),
    }))
end

--- init_worker phase
function _M.init_worker()
    local crypto = require("e2ee_crypto")
    local ok, err = crypto.init()
    if not ok then
        log.err("FATAL: e2ee_init failed: ", err)
        return
    end
    log.notice("e2ee proxy started: ", crypto.build_info())
    log.notice("config: ", config.summary())
    for _, w in ipairs(config.warnings()) do
        log.warn("config: ", w)
    end
    if config.ATTEST_MODE == "observe" then
        log.warn("E2EE_ATTEST=observe: attestation failures are logged but NOT enforced. ",
                 "Set E2EE_ATTEST=enforce once 'attestation OK' appears in the logs.")
    elseif config.ATTEST_MODE == "off" then
        log.warn("E2EE_ATTEST=off: instance public keys are trusted without attestation.")
    end
    if config.ALLOW_PLAINTEXT then
        log.warn("ALLOW_PLAINTEXT=true: port 80 serves the API without TLS; API keys travel in cleartext. ",
                 "Publish it on loopback only (docker run -p 127.0.0.1:8080:80).")
    end
    if config.ALLOW_NON_CONFIDENTIAL then
        log.warn("ALLOW_NON_CONFIDENTIAL=true: requests to non-TEE models are allowed.")
    end

    local metrics = require("metrics")
    metrics.set("e2ee_build_info", {
        native = crypto.build_info(),
        route_mode = config.ROUTE_MODE,
        attestation = config.ATTEST_MODE,
    }, 1)
end

return _M
