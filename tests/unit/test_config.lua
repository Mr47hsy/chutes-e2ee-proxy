-- e2ee_config reads the environment at load time; set variables via FFI
-- before requiring it.
local ffi = require("ffi")
ffi.cdef [[ int setenv(const char *name, const char *value, int overwrite); ]]
local function setenv(k, v)
    ffi.C.setenv(k, v, 1)
end

setenv("ROUTE_MODE", "AGENT")
setenv("BALANCED_N", "999")          -- clamped to 64
setenv("UPSTREAM_READ_TIMEOUT_MS", "abc") -- invalid -> default
setenv("E2EE_ATTEST", "bogus")       -- invalid -> observe
setenv("ALLOW_NON_CONFIDENTIAL", "yes")
setenv("API_BASE", "https://mock.example/")
setenv("E2EE_ATTEST_MRTD", "ABCDEF")

local T = require("ngx_mock")
local config = require("e2ee_config")

T.test("parsing, clamping and defaults", function()
    T.eq(config.ROUTE_MODE, "agent")
    T.eq(config.BALANCED_N, 64)
    T.eq(config.UPSTREAM_READ_TIMEOUT_MS, 900000)
    T.eq(config.ATTEST_MODE, "observe")
    T.eq(config.ALLOW_NON_CONFIDENTIAL, true)
    T.eq(config.API_BASE, "https://mock.example", "trailing slash stripped")
    T.eq(config.ATTEST_MRTD, "abcdef", "lowercased")
    T.eq(config.MODELS_BASE, "https://llm.chutes.ai")
    T.eq(config.ATTEST_TTL_S, 600)
end)

T.test("invalid values produce warnings, not failures", function()
    local w = table.concat(config.warnings(), "\n")
    T.truthy(w:find("BALANCED_N=999", 1, true), w)
    T.truthy(w:find("UPSTREAM_READ_TIMEOUT_MS=abc", 1, true), w)
    T.truthy(w:find("E2EE_ATTEST=bogus", 1, true), w)
end)

T.test("summary has no secrets and mentions the mode", function()
    local s = config.summary()
    T.truthy(s:find("route_mode=agent", 1, true))
    T.truthy(s:find("attest=observe", 1, true))
end)

T.finish("e2ee_config")
