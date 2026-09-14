--
-- instance_selector.lua - chooses which GPU instance serves a request.
--
-- WHY
-- ---
-- /e2e/instances returns a list of instances, each with a batch of single-use
-- nonces valid for ~55s. Upstream always took the first instance with nonces
-- left, so any request arriving after the TTL could land on a different
-- instance and miss that instance's prefix KV cache. Measured on a 20k-token
-- fixed prefix with 90s gaps: hit rate 43% -> 100%, effective input price
-- $1.999/M -> $0.330/M once the choice is made sticky.
--
-- MODES
-- -----
--   agent        one sticky instance per chute (max cache hits, single agent)
--   balanced     sticky set of N instances, round-robin (default; several
--                agents in parallel, every member stays warm)
--   performance  power-of-two-choices on a decayed EWMA of TTFT
--   default      upstream behaviour: first instance with nonces (control)
--
-- PIN_INSTANCE_ID overrides every mode when that instance is available
-- (diagnostics only; falls back to the mode logic when it is not).
--
-- STATE
-- -----
-- Module-level tables (single worker, see nginx.conf.template). All state is
-- per chute_id. selector.invalidate() is what turns a rejected request into a
-- failover: the handler calls it before retrying, so the failing instance is
-- dropped from stickiness and its stats are penalised.
--

local config = require("e2ee_config")
local log = require("e2ee_log")
local metrics = require("metrics")

local _M = {}

local VALID = {}
for _, m in ipairs(config.ROUTE_MODES) do
    VALID[m] = true
end

-- state[chute_id] = {
--   sticky   = instance_id             (agent)
--   ring     = { instance_id, ... }    (balanced)
--   ring_pos = n
--   stats    = { [instance_id] = { ewma = s, n = count, last = ts, fails = n } }
-- }
local state = {}

local now = function()
    return ngx.now()
end

local function chute_state(chute_id)
    local s = state[chute_id]
    if not s then
        s = { ring = {}, ring_pos = 0, stats = {}, banned = {} }
        state[chute_id] = s
    end
    return s
end

-- Drop candidates that were invalidated recently (403/5xx), unless that would
-- leave nothing to pick from.
local function without_banned(cs, cands)
    local t = now()
    local out = {}
    for _, inst in ipairs(cands) do
        local until_ts = cs.banned[inst.instance_id]
        if until_ts and until_ts > t then
            -- still banned
        else
            cs.banned[inst.instance_id] = nil
            out[#out + 1] = inst
        end
    end
    if #out == 0 then
        return cands
    end
    return out
end

local function has_nonces(inst)
    return inst and inst.nonces and #inst.nonces > 0
end

local function eligible(instances)
    local out = {}
    for _, inst in ipairs(instances or {}) do
        if has_nonces(inst) and inst.instance_id then
            out[#out + 1] = inst
        end
    end
    return out
end

local function find(list, instance_id)
    for _, inst in ipairs(list) do
        if inst.instance_id == instance_id then
            return inst
        end
    end
    return nil
end

local function present(instances, instance_id)
    for _, inst in ipairs(instances or {}) do
        if inst.instance_id == instance_id then
            return true
        end
    end
    return false
end

-- ---------------------------------------------------------------------------
-- Mode resolution
-- ---------------------------------------------------------------------------

--- Resolve the effective mode from an optional per-request header value.
-- Unknown values fall back to the global default with a warning.
function _M.resolve_mode(header_value)
    if header_value == nil or header_value == "" then
        return config.ROUTE_MODE, false
    end
    if type(header_value) == "table" then
        header_value = header_value[1]
    end
    local v = tostring(header_value):lower()
    if VALID[v] then
        return v, true
    end
    log.warn("unknown X-Route-Mode '", v, "', using ROUTE_MODE=", config.ROUTE_MODE)
    return config.ROUTE_MODE, false
end

-- ---------------------------------------------------------------------------
-- Performance-mode scoring
-- ---------------------------------------------------------------------------

local function score(cs, instance_id)
    local st = cs.stats[instance_id]
    local base = config.PERF_COLD_START_S
    if not st or st.n == 0 then
        -- Optimistic cold start so every instance gets probed at least once.
        return base
    end
    -- Decay old samples towards the optimistic baseline so one slow episode
    -- does not blacklist an instance forever.
    local age = now() - (st.last or 0)
    local factor = 0.5 ^ (age / config.PERF_HALF_LIFE_S)
    return base + (st.ewma - base) * factor
end

local function pick_performance(cs, cands)
    if #cands == 1 then
        return cands[1], "single"
    end
    -- Power of two choices: sample two distinct candidates, take the faster.
    local i = math.random(#cands)
    local j = math.random(#cands - 1)
    if j >= i then
        j = j + 1
    end
    local a, b = cands[i], cands[j]
    if score(cs, a.instance_id) <= score(cs, b.instance_id) then
        return a, "p2c"
    end
    return b, "p2c"
end

-- ---------------------------------------------------------------------------
-- Balanced-mode ring
-- ---------------------------------------------------------------------------

local function prune_ring(cs, instances)
    local kept = {}
    for _, id in ipairs(cs.ring) do
        if present(instances, id) then
            kept[#kept + 1] = id
        end
    end
    cs.ring = kept
end

local function ring_has(ring, id)
    for _, v in ipairs(ring) do
        if v == id then
            return true
        end
    end
    return false
end

local function fill_ring(cs, cands)
    local n = config.BALANCED_N
    for _, inst in ipairs(cands) do
        if #cs.ring >= n then
            break
        end
        if not ring_has(cs.ring, inst.instance_id) then
            cs.ring[#cs.ring + 1] = inst.instance_id
        end
    end
end

-- Returns inst, reason, affinity ("hit" = existing member, "miss" = a new
-- member joined a non-empty ring, "cold" = ring was empty).
local function pick_balanced(cs, instances, cands)
    prune_ring(cs, instances)
    local had_members = #cs.ring > 0
    local was_member = {}
    for _, id in ipairs(cs.ring) do
        was_member[id] = true
    end
    fill_ring(cs, cands)
    if #cs.ring == 0 then
        return nil
    end
    -- Round-robin from the last position, skipping members that have no
    -- nonces left in this batch (they stay in the ring; nonces refresh).
    for step = 1, #cs.ring do
        local idx = ((cs.ring_pos + step - 1) % #cs.ring) + 1
        local inst = find(cands, cs.ring[idx])
        if inst then
            cs.ring_pos = idx
            if was_member[inst.instance_id] then
                return inst, "ring", "hit"
            end
            return inst, "ring_new", had_members and "miss" or "cold"
        end
    end
    return nil
end

-- ---------------------------------------------------------------------------
-- pick
-- ---------------------------------------------------------------------------

--- Choose an instance.
-- @param instances  list from /e2e/instances (entries with .instance_id, .nonces)
-- @param chute_id   chute UUID
-- @param mode       one of config.ROUTE_MODES
-- @return instance table (still holding its nonces) or nil, reason string
function _M.pick(instances, chute_id, mode)
    mode = VALID[mode] and mode or config.ROUTE_MODE
    local cands = eligible(instances)
    if #cands == 0 then
        return nil, "none"
    end
    local cs = chute_state(chute_id)
    cands = without_banned(cs, cands)
    local chosen, reason

    -- Hard pin (diagnostics)
    if config.PIN_INSTANCE_ID then
        chosen = find(cands, config.PIN_INSTANCE_ID)
        if chosen then
            reason = "pin"
        else
            log.warn("PIN_INSTANCE_ID=", config.PIN_INSTANCE_ID,
                     " has no nonces / is absent for chute ", chute_id, "; falling back to mode=", mode)
        end
    end

    local affinity
    if not chosen then
        if mode == "default" then
            chosen, reason = cands[1], "first"
        elseif mode == "agent" then
            if cs.sticky then
                chosen = find(cands, cs.sticky)
                if chosen then
                    reason, affinity = "sticky", "hit"
                end
            end
            if not chosen then
                -- Sticky instance gone (or first request): choose the lowest
                -- recent TTFT if we have data, else the first available.
                chosen, reason = cands[1], "new"
                affinity = cs.sticky and "miss" or "cold"
                local best = score(cs, chosen.instance_id)
                for _, c in ipairs(cands) do
                    local sc = score(cs, c.instance_id)
                    if sc < best then
                        best, chosen = sc, c
                    end
                end
            end
            cs.sticky = chosen.instance_id
        elseif mode == "balanced" then
            chosen, reason, affinity = pick_balanced(cs, instances, cands)
        elseif mode == "performance" then
            chosen, reason = pick_performance(cs, cands)
        end
    end

    if not chosen then
        return nil, "none"
    end

    metrics.inc("e2ee_instance_picks_total",
        { chute = chute_id, mode = mode, instance = chosen.instance_id, reason = reason })
    if affinity then
        metrics.inc("e2ee_affinity_total", { mode = mode, result = affinity })
    end
    return chosen, reason
end

-- ---------------------------------------------------------------------------
-- feedback
-- ---------------------------------------------------------------------------

--- Record the outcome of a request served by an instance.
-- @param ttft_seconds  number or nil (unknown)
-- @param ok            boolean
function _M.record(chute_id, instance_id, ttft_seconds, ok)
    if not chute_id or not instance_id then
        return
    end
    local cs = chute_state(chute_id)
    local st = cs.stats[instance_id]
    if not st then
        st = { ewma = 0, n = 0, last = 0, fails = 0 }
        cs.stats[instance_id] = st
    end
    local sample
    if ok then
        sample = ttft_seconds
    else
        st.fails = st.fails + 1
        -- A failure is treated as a very slow sample so P2C avoids it for a while.
        sample = math.max((st.n > 0 and st.ewma or config.PERF_COLD_START_S) * 4, 10)
    end
    if type(sample) ~= "number" or sample < 0 then
        return
    end
    if st.n == 0 then
        st.ewma = sample
    else
        st.ewma = config.PERF_EWMA_ALPHA * sample + (1 - config.PERF_EWMA_ALPHA) * st.ewma
    end
    st.n = st.n + 1
    st.last = now()
end

--- Drop stickiness (and stats) for a chute, or for one instance of it.
-- Called before retrying a rejected request so the retry lands elsewhere.
function _M.invalidate(chute_id, instance_id)
    local cs = state[chute_id]
    if not cs then
        return
    end
    if not instance_id then
        state[chute_id] = nil
        return
    end
    if cs.sticky == instance_id then
        cs.sticky = nil
    end
    cs.banned[instance_id] = now() + config.ROUTE_BAN_S
    local kept = {}
    for _, id in ipairs(cs.ring) do
        if id ~= instance_id then
            kept[#kept + 1] = id
        end
    end
    cs.ring = kept
    if cs.ring_pos > #cs.ring then
        cs.ring_pos = 0
    end
    _M.record(chute_id, instance_id, nil, false)
end

--- Snapshot for /metrics and debugging.
function _M.stats(chute_id)
    local cs = state[chute_id]
    if not cs then
        return nil
    end
    local out = { sticky = cs.sticky, ring = { unpack(cs.ring) }, instances = {}, banned = {} }
    for id, until_ts in pairs(cs.banned) do
        if until_ts > now() then
            out.banned[id] = until_ts - now()
        end
    end
    for id, st in pairs(cs.stats) do
        out.instances[id] = {
            ewma = st.ewma, samples = st.n, fails = st.fails, score = score(cs, id),
        }
    end
    return out
end

function _M.all_stats()
    local out = {}
    for chute_id in pairs(state) do
        out[chute_id] = _M.stats(chute_id)
    end
    return out
end

--- Tests only.
function _M.reset()
    state = {}
end

function _M._set_clock(fn)
    now = fn
end

-- Refresh the EWMA gauges when /metrics is scraped.
metrics.add_collector(function()
    for chute_id, cs in pairs(state) do
        for id in pairs(cs.stats) do
            metrics.set("e2ee_instance_ttft_ewma_seconds", { chute = chute_id, instance = id }, score(cs, id))
        end
    end
end)

return _M
