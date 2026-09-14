--
-- ngx_mock.lua - just enough of the OpenResty API to unit-test the pure-Lua
-- modules (instance_selector, e2ee_attest, cors, metrics, e2ee_config) with
-- plain LuaJIT. Also provides a pure-Lua "cjson"/"cjson.safe".
--
local M = {}

M.clock = 1000000
M.logs = {}
M.exit_code = nil

-- ---------------------------------------------------------------------------
-- base64
-- ---------------------------------------------------------------------------
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function encode_base64(data)
    return ((data:gsub(".", function(x)
        local r, b = "", x:byte()
        for i = 8, 1, -1 do
            r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0")
        end
        return r
    end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
        if #x < 6 then
            return ""
        end
        local c = 0
        for i = 1, 6 do
            c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0)
        end
        return b64chars:sub(c + 1, c + 1)
    end) .. ({ "", "==", "=" })[#data % 3 + 1])
end

local function decode_base64(data)
    if type(data) ~= "string" then
        return nil
    end
    data = data:gsub("[^" .. b64chars .. "=]", "")
    if #data % 4 ~= 0 then
        return nil
    end
    return (data:gsub(".", function(x)
        if x == "=" then
            return ""
        end
        local r, f = "", (b64chars:find(x, 1, true) - 1)
        for i = 6, 1, -1 do
            r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0")
        end
        return r
    end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
        if #x ~= 8 then
            return ""
        end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0)
        end
        return string.char(c)
    end))
end

-- ---------------------------------------------------------------------------
-- minimal JSON codec (enough for test payloads)
-- ---------------------------------------------------------------------------
local json = {}
json.null = setmetatable({}, { __tostring = function() return "null" end })

local function skip_ws(s, i)
    return s:find("%S", i) or #s + 1
end

local decode_value

local function decode_string(s, i)
    -- i points at opening quote
    local out = {}
    i = i + 1
    while i <= #s do
        local c = s:sub(i, i)
        if c == '"' then
            return table.concat(out), i + 1
        elseif c == "\\" then
            local n = s:sub(i + 1, i + 1)
            local map = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
            if n == "u" then
                local hex = s:sub(i + 2, i + 5)
                local cp = tonumber(hex, 16)
                if cp < 128 then
                    out[#out + 1] = string.char(cp)
                else
                    out[#out + 1] = "?"
                end
                i = i + 6
            else
                out[#out + 1] = map[n] or n
                i = i + 2
            end
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    error("unterminated string")
end

decode_value = function(s, i)
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == "{" then
        local obj = {}
        i = skip_ws(s, i + 1)
        if s:sub(i, i) == "}" then
            return obj, i + 1
        end
        while true do
            i = skip_ws(s, i)
            if s:sub(i, i) ~= '"' then
                error("expected key at " .. i)
            end
            local k
            k, i = decode_string(s, i)
            i = skip_ws(s, i)
            if s:sub(i, i) ~= ":" then
                error("expected : at " .. i)
            end
            local v
            v, i = decode_value(s, i + 1)
            obj[k] = v
            i = skip_ws(s, i)
            local d = s:sub(i, i)
            if d == "," then
                i = i + 1
            elseif d == "}" then
                return obj, i + 1
            else
                error("expected , or } at " .. i)
            end
        end
    elseif c == "[" then
        local arr = setmetatable({}, { __jsontype = "array" })
        i = skip_ws(s, i + 1)
        if s:sub(i, i) == "]" then
            return arr, i + 1
        end
        while true do
            local v
            v, i = decode_value(s, i)
            arr[#arr + 1] = v
            i = skip_ws(s, i)
            local d = s:sub(i, i)
            if d == "," then
                i = i + 1
            elseif d == "]" then
                return arr, i + 1
            else
                error("expected , or ] at " .. i)
            end
        end
    elseif c == '"' then
        return decode_string(s, i)
    elseif s:sub(i, i + 3) == "true" then
        return true, i + 4
    elseif s:sub(i, i + 4) == "false" then
        return false, i + 5
    elseif s:sub(i, i + 3) == "null" then
        return json.null, i + 4
    else
        local num = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", i)
        if not num or num == "" then
            error("unexpected char at " .. i .. ": " .. c)
        end
        return tonumber(num), i + #num
    end
end

function json.decode(s)
    local ok, v = pcall(function()
        local val, i = decode_value(s, 1)
        i = skip_ws(s, i)
        if i <= #s then
            error("trailing garbage")
        end
        return val
    end)
    if ok then
        return v
    end
    return nil, v
end

local function encode_string(s)
    return '"' .. s:gsub('[%c"\\]', function(c)
        local map = { ["\n"] = "\\n", ["\t"] = "\\t", ["\r"] = "\\r", ['"'] = '\\"', ["\\"] = "\\\\" }
        return map[c] or string.format("\\u%04x", c:byte())
    end) .. '"'
end

local function is_array(t)
    local mt = getmetatable(t)
    if mt and mt.__jsontype == "array" then
        return true
    end
    local n = 0
    for k in pairs(t) do
        if type(k) ~= "number" then
            return false
        end
        n = n + 1
    end
    return n == #t and n > 0
end

function json.encode(v)
    local t = type(v)
    if v == json.null or v == nil then
        return "null"
    elseif t == "boolean" then
        return tostring(v)
    elseif t == "number" then
        if v == math.floor(v) and math.abs(v) < 1e15 then
            return string.format("%d", v)
        end
        return string.format("%.14g", v)
    elseif t == "string" then
        return encode_string(v)
    elseif t == "table" then
        if is_array(v) then
            local parts = {}
            for i = 1, #v do
                parts[i] = json.encode(v[i])
            end
            return "[" .. table.concat(parts, ",") .. "]"
        end
        local keys = {}
        for k in pairs(v) do
            keys[#keys + 1] = tostring(k)
        end
        table.sort(keys)
        local parts = {}
        for _, k in ipairs(keys) do
            parts[#parts + 1] = encode_string(k) .. ":" .. json.encode(v[k])
        end
        return "{" .. table.concat(parts, ",") .. "}"
    end
    error("cannot encode " .. t)
end

function json.new()
    return json
end

function json.decode_array_with_array_mt() end

package.preload["cjson"] = function() return json end
package.preload["cjson.safe"] = function() return json end
M.json = json

-- ---------------------------------------------------------------------------
-- ngx
-- ---------------------------------------------------------------------------
local ngx = {
    DEBUG = 8, INFO = 7, NOTICE = 6, WARN = 5, ERR = 4, CRIT = 3,
    ctx = {},
    header = {},
    var = {},
    status = 0,
    encode_base64 = encode_base64,
    decode_base64 = decode_base64,
    now = function()
        return M.clock
    end,
    log = function(level, ...)
        local parts = {}
        for i = 1, select("#", ...) do
            parts[#parts + 1] = tostring((select(i, ...)))
        end
        local line = table.concat(parts)
        M.logs[#M.logs + 1] = { level = level, line = line }
        if os.getenv("TEST_VERBOSE") then
            print(string.format("[ngx.log %d] %s", level, line))
        end
    end,
    get_phase = function()
        return "content"
    end,
    exit = function(code)
        M.exit_code = code
        error({ ngx_exit = code }, 0)
    end,
    print = function(s)
        M.out = (M.out or "") .. tostring(s)
    end,
    say = function(s)
        M.out = (M.out or "") .. tostring(s) .. "\n"
    end,
    flush = function() end,
    req = {
        get_headers = function()
            return M.headers or {}
        end,
        get_method = function()
            return M.method or "GET"
        end,
    },
    sleep = function() end,
}
_G.ngx = ngx
M.ngx = ngx

function M.advance(seconds)
    M.clock = M.clock + seconds
end

function M.reset()
    M.logs = {}
    M.out = nil
    M.exit_code = nil
    ngx.ctx = {}
    ngx.header = {}
    ngx.var = {}
    ngx.status = 0
end

function M.log_contains(pat)
    for _, l in ipairs(M.logs) do
        if l.line:find(pat, 1, true) then
            return true
        end
    end
    return false
end

-- ---------------------------------------------------------------------------
-- tiny test runner
-- ---------------------------------------------------------------------------
local passed, failed = 0, 0
function M.test(name, fn)
    M.reset()
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        io.write("  ok   ", name, "\n")
    else
        failed = failed + 1
        local msg = err
        if type(err) == "table" then
            msg = err.ngx_exit and ("ngx.exit(" .. err.ngx_exit .. ")") or "table"
        end
        io.write("  FAIL ", name, ": ", tostring(msg), "\n")
    end
end

function M.finish(suite)
    io.write(string.format("%s: %d passed, %d failed\n", suite, passed, failed))
    if failed > 0 then
        os.exit(1)
    end
end

function M.eq(a, b, msg)
    if a ~= b then
        error((msg or "assertion") .. ": expected " .. tostring(b) .. ", got " .. tostring(a), 2)
    end
end

function M.truthy(v, msg)
    if not v then
        error((msg or "assertion") .. ": expected truthy, got " .. tostring(v), 2)
    end
end

function M.falsy(v, msg)
    if v then
        error((msg or "assertion") .. ": expected falsy, got " .. tostring(v), 2)
    end
end

return M
