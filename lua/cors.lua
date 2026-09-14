--
-- cors.lua - origin allowlist instead of "Access-Control-Allow-Origin: *".
--
-- A wide-open CORS policy lets any web page a user visits call the local
-- proxy with the user's API key. Default allowlist covers local development
-- only. Override with CORS_ALLOWED_ORIGINS (comma separated). Entries are
-- matched case-insensitively; "*" inside an entry is a wildcard, e.g.
--   https://*.example.com
--   http://localhost:*
-- The literal entry "*" restores the upstream behaviour (any origin).
--

local config = require("e2ee_config")

local _M = {}

local DEFAULT_ORIGINS = {
    "null",
    "http://localhost", "http://localhost:*",
    "https://localhost", "https://localhost:*",
    "http://127.0.0.1", "http://127.0.0.1:*",
    "https://127.0.0.1", "https://127.0.0.1:*",
    "http://[::1]", "http://[::1]:*",
    "https://[::1]", "https://[::1]:*",
    "https://e2ee-local-proxy.chutes.dev", "https://e2ee-local-proxy.chutes.dev:*",
}

local ALLOW_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
-- Fallback when the preflight carries no Access-Control-Request-Headers;
-- otherwise the requested list is echoed back (SDKs send many X-Stainless-*).
local ALLOW_HEADERS = "Authorization, Content-Type, X-Api-Key, X-Route-Mode, X-Request-Id, "
    .. "Anthropic-Version, Anthropic-Beta, OpenAI-Beta, OpenAI-Organization, OpenAI-Project"
local EXPOSE_HEADERS = "X-Request-Id, X-E2EE-Instance-Id, X-E2EE-Route-Mode, Content-Type"

local rules = nil
local allow_any = false

local function to_pattern(entry)
    -- Escape Lua magic chars, then translate wildcards:
    --   trailing ":*"  -> any port          (digits only)
    --   other "*"      -> any host segment  (no "/" or ":" so "*.example.org"
    --                                        cannot match "evil.example.org:80/…")
    local e = entry:lower()
    local port_wild = false
    if e:sub(-2) == ":*" then
        port_wild = true
        e = e:sub(1, -3)
    end
    local p = e:gsub("([%^%$%(%)%%%.%[%]%+%-%?])", "%%%1"):gsub("%*", "[^/:]*")
    if port_wild then
        p = p .. ":%d+"
    end
    return "^" .. p .. "$"
end

local function compile(list_str)
    local out = {}
    allow_any = false
    local src = list_str
    if not src or src == "" then
        out = DEFAULT_ORIGINS
    else
        src = src:gsub("%s+", "")
        out = {}
        for entry in src:gmatch("[^,]+") do
            if entry == "*" then
                allow_any = true
            else
                out[#out + 1] = entry
            end
        end
    end
    rules = {}
    for _, e in ipairs(out) do
        rules[#rules + 1] = { exact = e:lower(), pattern = e:find("*", 1, true) and to_pattern(e) or nil }
    end
end

--- Return the origin string to echo back, or nil if not allowed.
function _M.match(origin)
    if not rules then
        compile(config.CORS_ALLOWED_ORIGINS)
    end
    if not origin or origin == "" then
        return nil
    end
    if type(origin) == "table" then
        origin = origin[1]
    end
    if allow_any then
        return origin
    end
    local o = origin:lower()
    for _, r in ipairs(rules) do
        if r.pattern then
            if o:match(r.pattern) then
                return origin
            end
        elseif o == r.exact then
            return origin
        end
    end
    return nil
end

--- Set response CORS headers for an allowed origin (or clear them).
-- @param requested  value of Access-Control-Request-Headers (preflight only)
function _M.apply(origin, preflight, requested)
    local allowed = _M.match(origin)
    -- Always own these headers: never let an upstream "*" leak through.
    if allowed then
        ngx.header["Access-Control-Allow-Origin"] = allowed
        ngx.header["Vary"] = "Origin"
        ngx.header["Access-Control-Allow-Methods"] = ALLOW_METHODS
        if type(requested) == "table" then
            requested = requested[1]
        end
        if type(requested) == "string" and requested ~= "" and #requested <= 2048
            and not requested:find("[^%w%-_, ]") then
            ngx.header["Access-Control-Allow-Headers"] = requested
        else
            ngx.header["Access-Control-Allow-Headers"] = ALLOW_HEADERS
        end
        ngx.header["Access-Control-Expose-Headers"] = EXPOSE_HEADERS
        if preflight then
            ngx.header["Access-Control-Max-Age"] = "86400"
        end
    else
        ngx.header["Access-Control-Allow-Origin"] = nil
        ngx.header["Access-Control-Allow-Methods"] = nil
        ngx.header["Access-Control-Allow-Headers"] = nil
        ngx.header["Access-Control-Expose-Headers"] = nil
    end
    return allowed ~= nil
end

--- Tests only: recompile with an explicit list.
function _M._configure(list_str)
    compile(list_str)
end

return _M
