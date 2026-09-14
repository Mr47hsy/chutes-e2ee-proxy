--
-- e2ee_log.lua - ngx.log wrapper that prefixes the per-request id.
--
-- The request id is set by proxy_common.access() into ngx.ctx.request_id.
-- Outside of a request (init_worker, timers) there is no ctx; that is
-- handled by pcall so the helper is safe everywhere.
--
-- Rule enforced by convention, not code: never log API keys, full nonces,
-- or request bodies. Nonce prefixes (8 chars) are allowed at DEBUG only.
--

local ngx = ngx

local _M = {}

local function prefix()
    local ok, ctx = pcall(function()
        return ngx.ctx
    end)
    if ok and ctx and ctx.request_id then
        return "[rid=" .. ctx.request_id .. "] "
    end
    return ""
end

local function make(level)
    return function(...)
        return ngx.log(level, prefix(), ...)
    end
end

_M.debug = make(ngx.DEBUG)
_M.info = make(ngx.INFO)
_M.notice = make(ngx.NOTICE)
_M.warn = make(ngx.WARN)
_M.err = make(ngx.ERR)

return _M
