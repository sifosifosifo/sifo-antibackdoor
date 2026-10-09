-- Regression tests for event-to-dynamic-code execution detection.
-- Run from the repository root with: lua tests/threat_scanner_test.lua
SIFO = {
    Findings = {},
    lower = function(value) return string.lower(tostring(value or "")) end,
    trim = function(value) return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "") end,
    contains = function(value, needle)
        return string.find(string.lower(tostring(value or "")), string.lower(tostring(needle or "")), 1, true) ~= nil
    end,
    addFinding = function(data) table.insert(SIFO.Findings, data) end
}

dofile("server/threat_scanner.lua")

local malicious = [[
RegisterNetEvent("helpEmptyCode")
AddEventHandler("helpEmptyCode", function(id)
    local ok, funcOrErr = pcall(load, id)
    if ok and type(funcOrErr) == "function" then
        pcall(funcOrErr)
    end
end)
]]

SIFO.scanTxAdminEventRCE("screenshare", "server/main.lua", malicious)
assert(#SIFO.Findings == 1, "Expected pcall(load, eventArgument) result execution to be detected")
assert(SIFO.Findings[1].severity == "CRITICAL", "Expected a CRITICAL finding")
assert(SIFO.Findings[1].resource == "screenshare", "Detection must not depend on the resource being txAdmin")
assert(SIFO.Findings[1].line == 2, "Finding line numbers must include physical blank lines correctly")

SIFO.Findings = {}
local notExecuted = [[
RegisterNetEvent("sampleEvent")
AddEventHandler("sampleEvent", function(id)
    local ok, funcOrErr = pcall(load, id)
    print(ok, funcOrErr)
end)
]]
SIFO.scanTxAdminEventRCE("ordinary-resource", "server/main.lua", notExecuted)
assert(#SIFO.Findings == 0, "A loader result that is never executed should not be reported as confirmed event-to-code execution")

print("SIFO Sentinel threat_scanner regression tests passed.")
