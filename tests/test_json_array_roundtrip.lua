package.path = "./lua/?.lua;/workspace/lua/?.lua;" .. package.path

local function serializer_for(func)
    for index = 1, 20 do
        local name, value = debug.getupvalue(func, index)
        if not name then
            break
        end
        if name == "cjson" then
            return value
        end
    end
    error("production serializer not found")
end

local function assert_schema_types(encoded, path)
    assert(encoded:find('"required":[]', 1, true), path .. ": empty array became an object")
    assert(encoded:find('"properties":{}', 1, true), path .. ": empty object became an array")
end

local function assert_safe_decode(cjson, path)
    local value, err = cjson.decode("{")
    assert(value == nil and err, path .. ": invalid JSON raised instead of returning an error")
end

local chat_json = [[
{
    "tools": [{
        "type": "function",
        "function": {
            "name": "list_files",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }]
}
]]

local crypto = require("e2ee_crypto")
local crypto_json = serializer_for(crypto.build_e2ee_request)
local chat_payload = crypto_json.decode(chat_json)
chat_payload.e2e_response_pk = "test-key"
assert_schema_types(crypto_json.encode(chat_payload), "chat completions")

local claude_handler = require("claude_handler")
local claude_format = require("claude_format")
local claude_json = serializer_for(claude_handler.handle)
assert_safe_decode(claude_json, "Claude Messages")
local claude_payload = claude_json.decode([[
{
    "model": "test-model",
    "max_tokens": 1,
    "messages": [{"role": "user", "content": "test"}],
    "tools": [{
        "name": "list_files",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }]
}
]])
assert_schema_types(
    claude_json.encode(claude_format.request_to_openai(claude_payload)),
    "Claude Messages"
)

local responses_handler = require("responses_handler")
local responses_format = require("responses_format")
local responses_json = serializer_for(responses_handler.handle)
assert_safe_decode(responses_json, "Responses API")
local responses_payload = responses_json.decode([[
{
    "model": "test-model",
    "input": "test",
    "tools": [{
        "type": "function",
        "name": "list_files",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }]
}
]])
assert_schema_types(
    responses_json.encode(responses_format.request_to_openai(responses_payload)),
    "Responses API"
)

print("JSON array round-trip tests passed")
