-- Replays extracted production helpers without loading runtime configuration.
local source = rawget(_G, 'WAF_RUNTIME_SOURCE')
if not source then
    local file = assert(io.open(arg[1] or 'init.lua', 'r'))
    source = file:read('*a')
    file:close()
end

local function fixture(disabled)
    local env = setmetatable({
        ngx = {unescape_uri = function(value) return value end},
        ngx_match = function(value, pattern)
            assert(pattern ~= '', 'disabled placeholders must not reach the matcher')
            return string.find(value, pattern, 1, true)
        end,
        server_name = 'fixture',
        site_config = {fixture = {disable_rule = disabled or {post = {1}}}},
    }, {__index = _G})
    for _, name in ipairs({'read_file', 'select_rule', 'continue_key', 'is_ngx_match'}) do
        local body = assert(source:match('function ' .. name .. '%b()%s*.-\nend'), 'missing function: ' .. name)
        local compiled = assert(loadstring(body))
        setfenv(compiled, env)
        compiled()
    end
    return env
end

local tests = {}
function tests.original_zero_based_exception_is_effective()
    local env = fixture()
    local rules = env.select_rule({{0, 'inactive'}, {1, 'needle'}, {1, 'other'}})
    assert(env.is_ngx_match(rules, {value = 'needle'}, 'post') == false, 'original index 1 must disable needle')
end

function tests.unrelated_rule_remains_active()
    local env = fixture()
    local rules = env.select_rule({{0, 'inactive'}, {1, 'needle'}, {1, 'other'}})
    assert(env.is_ngx_match(rules, {value = 'other'}, 'post') == true, 'original index 2 must stay enabled')
end

function tests.inactive_slots_preserve_array_length()
    local env = fixture()
    local rules = env.select_rule({{0, 'first'}, {1, 'second'}, {0, 'third'}, {1, 'fourth'}, {0, 'last'}})
    assert(#rules == 5, 'inactive rows must preserve their original offsets')
    assert(rules[1] == '' and rules[2] == 'second' and rules[3] == '' and rules[4] == 'fourth' and rules[5] == '')
    assert(env.is_ngx_match(rules, {value = 'first third last'}, false) == false)
end

function tests.every_site_rule_family_uses_original_offsets()
    for _, name in ipairs({'post', 'header', 'cookie', 'args', 'url', 'user_agent'}) do
        local env = fixture({[name] = {1, 3}})
        local rules = env.select_rule({{0, 'inactive'}, {1, 'needle'}, {1, 'other'}, {1, 'last'}})
        assert(env.is_ngx_match(rules, 'needle last', name) == false, 'exception shifted in ' .. name)
        assert(env.is_ngx_match(rules, 'other', name) == true, 'unrelated rule disabled in ' .. name)
    end
end

function tests.global_matching_without_site_exceptions_still_works()
    local env = fixture()
    local rules = env.select_rule({{0, 'inactive'}, {1, 'needle'}})
    assert(env.is_ngx_match(rules, 'needle', false) == true)
    assert(env.is_ngx_match(rules, 'inactive', false) == false)
    env.site_config = {}
    assert(env.is_ngx_match(rules, 'needle', 'post') == true)
end

function tests.selection_does_not_mutate_input_or_prior_results()
    local env = fixture()
    local input = {{0, 'inactive', 'remark'}, {1, 'needle', 'original'}}
    local first = env.select_rule(input)
    local second = env.select_rule({{1, 'other'}})
    assert(input[1][1] == 0 and input[1][2] == 'inactive' and input[2][3] == 'original')
    assert(first ~= second and first[2] == 'needle', 'subsequent selection changed previous result')
    assert(env.new_rules == nil, 'selection must not leak shared scratch state')
end

function tests.read_file_keeps_raw_rule_rows_for_other_consumers()
    local env = fixture()
    local rows = {{0, 'inactive'}, {1, 'needle'}}
    env.jpath = 'fixture/'
    env.read_file_body = function(path) assert(path == 'fixture/post.json'); return 'fixture-json' end
    env.json = {decode = function(value) assert(value == 'fixture-json'); return rows end}
    local loaded = env.read_file('post')
    assert(loaded == rows and loaded[1][1] == 0 and loaded[2][1] == 1, 'read_file must retain raw rule shape')
    local selected = env.select_rule(loaded)
    assert(#selected == 2 and selected[1] == '' and selected[2] == 'needle')
    assert(loaded[1][2] == 'inactive', 'selection rewrote raw disk data')
end

function tests.nil_and_empty_rules_are_safe()
    local env = fixture()
    assert(#env.select_rule(nil) == 0 and #env.select_rule({}) == 0)
    assert(env.is_ngx_match(env.select_rule({{0, 'inactive'}}), 'anything', false) == false)
    assert(env.is_ngx_match('needle', 'needle', false) == true)
end

local failed, total = 0, 0
local names = {}
for name in pairs(tests) do names[#names + 1] = name end
table.sort(names)
for _, name in ipairs(names) do
    total = total + 1
    local ok, message = pcall(tests[name])
    if not ok then failed = failed + 1 end
    print((ok and 'PASS ' or 'FAIL ') .. name .. (ok and '' or ': ' .. tostring(message)))
end
print('rule_identity: ' .. (total - failed) .. '/' .. total .. ' passed; isolated_fixture=true')
assert(failed == 0, tostring(failed) .. ' rule identity regressions')
