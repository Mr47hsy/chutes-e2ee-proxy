local T = require("ngx_mock")
local config = require("e2ee_config")
local selector = require("instance_selector")
local metrics = require("metrics")

local function insts(spec)
    -- spec: { {id, n_nonces}, ... }
    local out = {}
    for _, s in ipairs(spec) do
        local nonces = {}
        for i = 1, s[2] do
            nonces[i] = s[1] .. "-nonce-" .. i
        end
        out[#out + 1] = { instance_id = s[1], e2e_pubkey = "pk-" .. s[1], nonces = nonces }
    end
    return out
end

local function pick_ids(instances, chute, mode, n)
    local ids = {}
    for i = 1, n do
        local inst, reason = selector.pick(instances, chute, mode)
        ids[i] = inst and inst.instance_id or "nil"
        ids["reason" .. i] = reason
    end
    return ids
end

selector._set_clock(function() return T.clock end)

T.test("resolve_mode: header overrides env, unknown falls back", function()
    T.eq(selector.resolve_mode(nil), config.ROUTE_MODE)
    T.eq(selector.resolve_mode("agent"), "agent")
    T.eq(selector.resolve_mode("AGENT"), "agent")
    T.eq(selector.resolve_mode({ "performance", "agent" }), "performance")
    T.eq(selector.resolve_mode("bogus"), config.ROUTE_MODE)
    T.truthy(T.log_contains("unknown X-Route-Mode"), "warns on unknown mode")
end)

T.test("default mode: first instance with nonces (upstream behaviour)", function()
    selector.reset()
    local list = insts({ { "a", 0 }, { "b", 2 }, { "c", 5 } })
    local inst, reason = selector.pick(list, "chute1", "default")
    T.eq(inst.instance_id, "b")
    T.eq(reason, "first")
    -- consumes nothing itself; discovery removes nonces. Simulate exhaustion:
    list[2].nonces = {}
    inst = selector.pick(list, "chute1", "default")
    T.eq(inst.instance_id, "c")
end)

T.test("no eligible instances -> nil", function()
    selector.reset()
    local inst, reason = selector.pick(insts({ { "a", 0 } }), "chute1", "agent")
    T.eq(inst, nil)
    T.eq(reason, "none")
    T.eq(selector.pick({}, "chute1", "agent"), nil)
    T.eq(selector.pick(nil, "chute1", "agent"), nil)
end)

T.test("agent mode: sticks to one instance across refreshes", function()
    selector.reset()
    metrics.reset()
    local list = insts({ { "a", 3 }, { "b", 3 }, { "c", 3 } })
    local first = selector.pick(list, "chute1", "agent").instance_id
    -- a "refresh" returns instances in a different order
    local list2 = insts({ { "c", 3 }, { "b", 3 }, { "a", 3 } })
    for _ = 1, 5 do
        local inst, reason = selector.pick(list2, "chute1", "agent")
        T.eq(inst.instance_id, first, "sticky instance kept")
        T.eq(reason, "sticky")
    end
    local reg = metrics._registry()["e2ee_affinity_total"].series
    T.truthy(reg['mode="agent",result="hit"'] and reg['mode="agent",result="hit"'].value == 5, "affinity hits counted")
end)

T.test("agent mode: falls back when sticky instance disappears, then re-sticks", function()
    selector.reset()
    local first = selector.pick(insts({ { "a", 3 }, { "b", 3 } }), "chute1", "agent").instance_id
    local other = first == "a" and "b" or "a"
    local inst, reason = selector.pick(insts({ { other, 3 } }), "chute1", "agent")
    T.eq(inst.instance_id, other)
    T.eq(reason, "new")
    -- now sticks to the new one even when the old one returns
    inst = selector.pick(insts({ { "a", 3 }, { "b", 3 } }), "chute1", "agent")
    T.eq(inst.instance_id, other)
end)

T.test("agent mode: sticky member with exhausted nonces is not chosen", function()
    selector.reset()
    local list = insts({ { "a", 1 }, { "b", 3 } })
    T.eq(selector.pick(list, "chute1", "agent").instance_id, "a")
    list[1].nonces = {}
    T.eq(selector.pick(list, "chute1", "agent").instance_id, "b")
end)

T.test("invalidate(chute, instance) drops stickiness for that instance only", function()
    selector.reset()
    local list = insts({ { "a", 3 }, { "b", 3 } })
    local first = selector.pick(list, "chute1", "agent").instance_id
    selector.invalidate("chute1", first)
    local inst, reason = selector.pick(list, "chute1", "agent")
    T.truthy(inst.instance_id ~= first, "moved off the invalidated instance")
    T.eq(reason, "new")
    local st = selector.stats("chute1")
    T.eq(st.instances[first].fails, 1)
end)

T.test("invalidate(chute) wipes everything for the chute", function()
    selector.reset()
    selector.pick(insts({ { "a", 3 } }), "chute1", "agent")
    selector.record("chute1", "a", 1.5, true)
    selector.invalidate("chute1")
    T.eq(selector.stats("chute1"), nil)
end)

T.test("balanced mode: round-robins over a sticky set of N", function()
    selector.reset()
    config.BALANCED_N = 3
    local list = insts({ { "a", 9 }, { "b", 9 }, { "c", 9 }, { "d", 9 }, { "e", 9 } })
    local ids = pick_ids(list, "chute1", "balanced", 6)
    T.eq(ids[1] .. ids[2] .. ids[3], "abc", "first three fill the ring in list order")
    T.eq(ids[4] .. ids[5] .. ids[6], "abc", "then rotates")
    T.eq(ids.reason1, "ring_new")
    T.eq(ids.reason4, "ring")
    -- order of the refreshed list does not change membership
    local list2 = insts({ { "e", 9 }, { "d", 9 }, { "c", 9 }, { "b", 9 }, { "a", 9 } })
    local ids2 = pick_ids(list2, "chute1", "balanced", 3)
    local seen = {}
    for i = 1, 3 do
        seen[ids2[i]] = true
    end
    T.truthy(seen.a and seen.b and seen.c, "same members after refresh")
    T.falsy(seen.d or seen.e, "no new members while ring is full")
end)

T.test("balanced mode: member without nonces is skipped, not evicted", function()
    selector.reset()
    config.BALANCED_N = 2
    local list = insts({ { "a", 9 }, { "b", 9 }, { "c", 9 } })
    pick_ids(list, "chute1", "balanced", 2) -- ring = a, b
    list[2].nonces = {} -- b exhausted this batch
    local ids = pick_ids(list, "chute1", "balanced", 3)
    T.eq(ids[1] .. ids[2] .. ids[3], "aaa")
    T.eq(#selector.stats("chute1").ring, 2, "b still a member")
    list[2].nonces = { "x" }
    T.eq(selector.pick(list, "chute1", "balanced").instance_id, "b")
end)

T.test("balanced mode: vanished member is pruned and replaced", function()
    selector.reset()
    config.BALANCED_N = 2
    pick_ids(insts({ { "a", 9 }, { "b", 9 }, { "c", 9 } }), "chute1", "balanced", 2) -- ring a,b
    local list = insts({ { "a", 9 }, { "c", 9 } })
    local ids = pick_ids(list, "chute1", "balanced", 4)
    local ring = selector.stats("chute1").ring
    T.eq(#ring, 2)
    T.truthy((ring[1] == "a" and ring[2] == "c") or (ring[1] == "c" and ring[2] == "a"), "ring is now a,c")
    for i = 1, 4 do
        T.truthy(ids[i] ~= "b", "b never picked")
    end
end)

T.test("balanced mode: invalidated instance leaves the ring", function()
    selector.reset()
    config.BALANCED_N = 3
    local list = insts({ { "a", 9 }, { "b", 9 }, { "c", 9 }, { "d", 9 } })
    pick_ids(list, "chute1", "balanced", 3)
    selector.invalidate("chute1", "b")
    local ids = pick_ids(list, "chute1", "balanced", 6)
    for i = 1, 6 do
        T.truthy(ids[i] ~= "b", "b not picked after invalidate")
    end
    local ring = selector.stats("chute1").ring
    T.eq(#ring, 3, "ring refilled to N")
    T.truthy(selector.stats("chute1").banned.b, "b is banned")
    -- after the ban window b may come back
    T.advance(config.ROUTE_BAN_S + 1)
    selector.invalidate("chute1", "a")
    selector.invalidate("chute1", "c")
    local inst = selector.pick(list, "chute1", "balanced")
    T.truthy(inst.instance_id == "b" or inst.instance_id == "d", "b eligible again after ban expiry")
end)

T.test("ban is ignored when it would leave no candidates", function()
    selector.reset()
    local list = insts({ { "a", 9 } })
    selector.pick(list, "chute1", "agent")
    selector.invalidate("chute1", "a")
    local inst = selector.pick(list, "chute1", "agent")
    T.eq(inst.instance_id, "a", "only candidate is still used")
end)

T.test("performance mode: prefers the lower EWMA TTFT", function()
    selector.reset()
    local list = insts({ { "fast", 9 }, { "slow", 9 } })
    selector.record("chute1", "fast", 0.8, true)
    selector.record("chute1", "slow", 4.0, true)
    for _ = 1, 20 do
        T.eq(selector.pick(list, "chute1", "performance").instance_id, "fast")
    end
end)

T.test("performance mode: cold instances get an optimistic score so they are probed", function()
    selector.reset()
    local list = insts({ { "known", 9 }, { "cold", 9 } })
    selector.record("chute1", "known", 2.0, true)
    local seen_cold = false
    for _ = 1, 30 do
        if selector.pick(list, "chute1", "performance").instance_id == "cold" then
            seen_cold = true
        end
    end
    T.truthy(seen_cold, "cold instance was probed")
end)

T.test("performance mode: failures penalise, and decay with half-life", function()
    selector.reset()
    local list = insts({ { "a", 9 }, { "b", 9 } })
    selector.record("chute1", "a", 1.0, true)
    selector.record("chute1", "b", 1.0, true)
    selector.record("chute1", "b", nil, false)
    local st = selector.stats("chute1")
    T.truthy(st.instances.b.score > st.instances.a.score, "failed instance scores worse")
    T.eq(st.instances.b.fails, 1)
    for _ = 1, 20 do
        T.eq(selector.pick(list, "chute1", "performance").instance_id, "a")
    end
    -- After many half-lives the penalty decays towards the baseline.
    T.advance(config.PERF_HALF_LIFE_S * 20)
    st = selector.stats("chute1")
    T.truthy(math.abs(st.instances.b.score - config.PERF_COLD_START_S) < 0.01, "score decayed to baseline")
end)

T.test("performance mode: single candidate short-circuits", function()
    selector.reset()
    local inst, reason = selector.pick(insts({ { "only", 1 } }), "chute1", "performance")
    T.eq(inst.instance_id, "only")
    T.eq(reason, "single")
end)

T.test("PIN_INSTANCE_ID overrides every mode when available, else falls back", function()
    selector.reset()
    config.PIN_INSTANCE_ID = "c"
    local list = insts({ { "a", 9 }, { "b", 9 }, { "c", 9 } })
    for _, mode in ipairs({ "agent", "balanced", "performance", "default" }) do
        local inst, reason = selector.pick(list, "chute-" .. mode, mode)
        T.eq(inst.instance_id, "c", mode)
        T.eq(reason, "pin")
    end
    local inst = selector.pick(insts({ { "a", 9 } }), "chute-x", "agent")
    T.eq(inst.instance_id, "a", "falls back when pinned instance absent")
    T.truthy(T.log_contains("PIN_INSTANCE_ID=c"), "warns about missing pin")
    config.PIN_INSTANCE_ID = nil
end)

T.test("record: EWMA uses alpha", function()
    selector.reset()
    selector.record("chute1", "a", 1.0, true)
    selector.record("chute1", "a", 3.0, true)
    local st = selector.stats("chute1").instances.a
    local expect = config.PERF_EWMA_ALPHA * 3.0 + (1 - config.PERF_EWMA_ALPHA) * 1.0
    T.truthy(math.abs(st.ewma - expect) < 1e-9, "ewma")
    T.eq(st.samples, 2)
    selector.record("chute1", "a", "garbage", true) -- ignored
    T.eq(selector.stats("chute1").instances.a.samples, 2)
    selector.record(nil, "a", 1, true) -- ignored
end)

T.test("state is per chute", function()
    selector.reset()
    local list = insts({ { "a", 9 }, { "b", 9 } })
    selector.pick(list, "chute1", "agent")
    T.eq(selector.stats("chute2"), nil)
end)

T.test("metrics: picks and EWMA gauges are exported", function()
    selector.reset()
    metrics.reset()
    local list = insts({ { "a", 9 } })
    selector.pick(list, "chute1", "agent")
    selector.record("chute1", "a", 1.25, true)
    local text = metrics.render()
    T.truthy(text:find('e2ee_instance_picks_total{chute="chute1",instance="a",mode="agent",reason="new"} 1', 1, true), "picks series")
    T.truthy(text:find('e2ee_instance_ttft_ewma_seconds{chute="chute1",instance="a"}', 1, true), "ewma gauge")
end)

T.finish("instance_selector")
