std = "luajit"
max_line_length = 140
codes = true

-- OpenResty globals
globals = { "ngx", "ndk" }

exclude_files = {
    "lua/resty/**",      -- vendored lua-resty-http
    "private/**",
}

files["tests/**"] = {
    globals = { "ngx" },
    ignore = { "631" }, -- long lines in test vectors
}

files["lua/claude_format.lua"] = { ignore = { "631", "211", "212", "213", "311", "312", "542" } }
files["lua/responses_format.lua"] = { ignore = { "631", "211", "212", "213", "311", "312", "542" } }
