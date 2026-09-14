--
-- claude_handler.lua - Handler for Claude Messages API (/v1/messages)
--
-- Translates Claude Messages API requests to OpenAI chat completions,
-- sends through the E2EE pipeline, and translates responses back.
--

local cjson = require("cjson.safe").new()
cjson.decode_array_with_array_mt(true)
local e2ee = require("e2ee_handler")
local claude_fmt = require("claude_format")

local _M = {}

function _M.handle()
    local body = e2ee.read_body()
    if not body then
        return e2ee.send_error(400, "missing request body")
    end

    local claude_body = cjson.decode(body)
    if not claude_body then
        return e2ee.send_error(400, "invalid JSON body")
    end

    local model = claude_body.model
    if not model then
        return e2ee.send_error(400, "missing 'model' field")
    end

    local api_key, err = e2ee.get_api_key()
    if not api_key then
        return e2ee.send_error(401, err)
    end

    local is_streaming = (claude_body.stream == true)

    -- Translate Claude request to OpenAI format
    local oai_request = claude_fmt.request_to_openai(claude_body)
    local oai_body = cjson.encode(oai_request)

    if not is_streaming then
        local decrypted, round_err = e2ee.e2ee_round_trip(
            api_key, model, oai_body, false, "/v1/chat/completions"
        )
        if not decrypted then
            return e2ee.send_round_err(round_err)
        end

        local claude_resp = claude_fmt.response_from_openai(decrypted, model)
        if not claude_resp then
            return e2ee.send_error(502, "failed to translate response")
        end

        ngx.header.content_type = "application/json"
        ngx.print(claude_fmt.encode(claude_resp))
        return
    end

    ngx.header.content_type = "text/event-stream"
    ngx.header.cache_control = "no-cache"
    ngx.header["X-Accel-Buffering"] = "no"

    local stream_state = claude_fmt.new_stream_state(model)

    local _, round_err = e2ee.e2ee_round_trip(
        api_key, model, oai_body, true, "/v1/chat/completions",
        function(line)
            local events
            if line == nil then
                events = claude_fmt.stream_end(stream_state)
            else
                events = claude_fmt.stream_chunk_from_openai(stream_state, line)
            end
            for _, evt in ipairs(events) do
                ngx.print(evt)
                ngx.flush(true)
            end
        end)

    if round_err then
        e2ee.send_round_err(round_err)
    end
end

return _M
