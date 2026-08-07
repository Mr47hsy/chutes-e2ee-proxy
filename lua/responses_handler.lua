--
-- responses_handler.lua - Handler for OpenAI Responses API (/v1/responses)
--
-- Translates Responses API requests to OpenAI chat completions,
-- sends through the E2EE pipeline, and translates responses back.
--

local cjson = require("cjson.safe").new()
cjson.decode_array_with_array_mt(true)
local e2ee = require("e2ee_handler")
local resp_fmt = require("responses_format")

local _M = {}

function _M.handle()
    -- Read request body
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "rb")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end

    if not body then
        return e2ee.send_error(400, "missing request body")
    end

    local resp_body = cjson.decode(body)
    if not resp_body then
        return e2ee.send_error(400, "invalid JSON body")
    end

    local model = resp_body.model
    if not model then
        return e2ee.send_error(400, "missing 'model' field")
    end

    local api_key, err = e2ee.get_api_key()
    if not api_key then
        return e2ee.send_error(401, err)
    end

    local is_streaming = (resp_body.stream == true)

    -- Translate Responses request to OpenAI format
    local oai_request = resp_fmt.request_to_openai(resp_body)
    local oai_body = cjson.encode(oai_request)

    if not is_streaming then
        -- Non-streaming
        local decrypted, round_err = e2ee.e2ee_round_trip(
            api_key, model, oai_body, false, "/v1/chat/completions"
        )

        if not decrypted then
            if round_err.raw then
                ngx.status = round_err.status
                ngx.header.content_type = round_err.content_type or "application/json"
                ngx.print(round_err.message)
                return
            end
            return e2ee.send_error(round_err.status, round_err.message)
        end

        -- Translate response back to Responses format
        local response = resp_fmt.response_from_openai(decrypted, model, resp_body)
        if not response then
            return e2ee.send_error(502, "failed to translate response")
        end

        ngx.header.content_type = "application/json"
        ngx.print(resp_fmt.encode(response))
    else
        -- Streaming
        ngx.header.content_type = "text/event-stream"
        ngx.header.cache_control = "no-cache"
        ngx.header["X-Accel-Buffering"] = "no"

        local stream_state = resp_fmt.new_stream_state(model)

        local _, round_err = e2ee.e2ee_round_trip(
            api_key, model, oai_body, true, "/v1/chat/completions",
            function(line)
                if line == nil then
                    -- Stream ended, emit closing events
                    local end_events = resp_fmt.stream_end(stream_state)
                    for _, evt in ipairs(end_events) do
                        ngx.print(evt)
                        ngx.flush(true)
                    end
                else
                    -- Translate chunk
                    local events = resp_fmt.stream_chunk_from_openai(stream_state, line)
                    for _, evt in ipairs(events) do
                        ngx.print(evt)
                        ngx.flush(true)
                    end
                end
            end)

        if round_err then
            if round_err.raw then
                ngx.status = round_err.status
                ngx.header.content_type = round_err.content_type or "application/json"
                ngx.print(round_err.message)
            else
                e2ee.send_error(round_err.status, round_err.message)
            end
        end
    end
end

return _M
