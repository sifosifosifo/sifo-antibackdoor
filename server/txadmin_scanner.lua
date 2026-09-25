-- SIFO Sentinel - txAdmin Tamper Detection
-- Defensive static analysis for known txAdmin/monitor tampering patterns.
-- This scanner does not execute discovered code.

local function txLine(content, position)
    local prefix = content:sub(1, math.max(0, (position or 1) - 1))
    local _, count = prefix:gsub("\n", "\n")
    return count + 1
end

local function txReport(resource, file, line, id, severity, score, category, indicator, reason, code)
    SIFO.addFinding({
        id = id,
        resource = resource,
        file = file,
        line = line or 0,
        indicator = indicator,
        category = category,
        severity = severity,
        score = score,
        reason = reason,
        code = code or indicator
    })
end

local function txIsMonitor(resource, file)
    local r = SIFO.lower(resource)
    local f = SIFO.lower(file):gsub("\\\\", "/")
    return r == "monitor" or f:find("monitor/", 1, true) ~= nil
end

local function txIsFile(file, suffix)
    local f = SIFO.lower(file):gsub("\\\\", "/")
    return f == suffix or f:sub(-#suffix - 1) == "/" .. suffix
end

local function txFindLine(content, pattern)
    local pos = content:find(pattern)
    if not pos then return 0 end
    return txLine(content, pos)
end

function SIFO.scanTxAdminTampering(resource, file, content)
    if not txIsMonitor(resource, file) then return end

    local normalized = SIFO.lower(file):gsub("\\\\", "/")
    local lower = SIFO.lower(content)

    -- 1) Network event -> argument -> load/loadstring -> execution.
    -- This is deliberately generic: malware can rename the event.
    if normalized:find("monitor/resource/", 1, true) then
        local handlerPattern =
            "[Aa][Dd][Dd][Ee][Vv][Ee][Nn][Tt][Hh][Aa][Nn][Dd][Ll][Ee][Rr]%s*%(%s*[\"']([^\"']+)[\"']%s*,%s*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn]%s*%(([^)]*)%)"

        local cursor = 1
        while true do
            local hs, he, eventName, params = content:find(handlerPattern, cursor)
            if not hs then break end

            local firstArg = SIFO.trim((params or ""):match("^%s*([%w_]+)") or "")
            if firstArg ~= "" then
                local arg = firstArg:gsub("([^%w_])", "%%%1")
                local bodyEnd = content:find("\n%s*end%s*%)", he + 1)
                    or math.min(#content, he + 16000)
                local body = content:sub(he + 1, bodyEnd)

                local sink = body:match("[Ll][Oo][Aa][Dd]%s*%(%s*" .. arg .. "%s*%)")
                    or body:match("[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. arg .. "%s*%)")

                if sink then
                    local fn = body:match("[Ll][Oo][Cc][Aa][Ll]%s+([%w_]+)%s*=%s*[Ll][Oo][Aa][Dd]%s*%(%s*" .. arg .. "%s*%)")
                        or body:match("[Ll][Oo][Cc][Aa][Ll]%s+([%w_]+)%s*=%s*[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. arg .. "%s*%)")
                    local executed = false
                    if fn then
                        local fp = fn:gsub("([^%w_])", "%%%1")
                        executed = body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*" .. fp .. "%s*%)") ~= nil
                            or body:match("[Xx][Pp][Cc][Aa][Ll][Ll]%s*%(%s*" .. fp .. "%s*[,)]") ~= nil
                            or body:match("[^%w_]" .. fp .. "%s*%(") ~= nil
                    end

                    local direct = body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd]%s*%(%s*" .. arg .. "%s*%)") ~= nil
                        or body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. arg .. "%s*%)") ~= nil

                    if executed or direct then
                        local prefix = content:sub(1, hs - 1)
                        local _, lc = prefix:gsub("\n", "\n")
                        txReport(resource, file, lc + 1, "TXADMIN_EVENT_TO_LUA_EXECUTION",
                            "CRITICAL", 100, "CODE_EXECUTION", eventName,
                            "txAdmin monitor network event argument reaches load/loadstring and the resulting code is executed",
                            "Event: " .. eventName .. " | Argument: " .. firstArg .. " | Sink: load/loadstring")
                    end
                end
            end
            cursor = he + 1
        end
    end

    -- 2) Known txAdmin malicious event handlers. The event name alone is not enough;
    -- require the executable data-flow before raising Critical.
    local knownEvents = {"helpEmptyCode", "onServerResourceFail"}
    for _, eventName in ipairs(knownEvents) do
        if SIFO.contains(content, eventName) then
            local ep = eventName:gsub("([^%w_])", "%%%1")
            local hs, he, params = content:find(
                "[Aa][Dd][Dd][Ee][Vv][Ee][Nn][Tt][Hh][Aa][Nn][Dd][Ll][Ee][Rr]%s*%(%s*[\"']"
                .. ep .. "[\"']%s*,%s*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn]%s*%(([^)]*)%)")
            if hs then
                local arg = SIFO.trim((params or ""):match("^%s*([%w_]+)") or "")
                if arg ~= "" then
                    local ap = arg:gsub("([^%w_])", "%%%1")
                    local bodyEnd = content:find("\n%s*end%s*%)", he + 1)
                        or math.min(#content, he + 16000)
                    local body = content:sub(he + 1, bodyEnd)
                    local directLoad = body:match("[Ll][Oo][Aa][Dd]%s*%(%s*" .. ap .. "%s*%)")
                        or body:match("[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. ap .. "%s*%)")
                    if directLoad then
                        txReport(resource, file, txLine(content, hs), "TXADMIN_KNOWN_EVENT_LOADER",
                            "CRITICAL", 100, "CODE_EXECUTION", eventName,
                            "Known txAdmin tampering event accepts network-controlled data and passes it to a dynamic Lua loader",
                            "Event: " .. eventName .. " | Argument: " .. arg .. " | Sink: load/loadstring")
                    end
                end
            end
        end
    end

    -- 3) Resource hiding / exclusion added to txAdmin resource reporting.
    if normalized:find("monitor/resource/sv_main.lua", 1, true) then
        local hasExclude = lower:find("resource_exclude", 1, true)
            or lower:find("excludedresource", 1, true)
            or lower:find("isexcludedresource", 1, true)
        local hasReporting = lower:find("txareportresources", 1, true)
            or (lower:find("getnumresources", 1, true) and lower:find("getresourcebyfindindex", 1, true))
        if hasExclude and hasReporting then
            local p = lower:find("resource_exclude", 1, true)
                or lower:find("isexcludedresource", 1, true)
                or 1
            txReport(resource, file, txLine(content, p), "TXADMIN_RESOURCE_REPORTING_TAMPER",
                "CRITICAL", 90, "DEFENSE_EVASION", "RESOURCE_EXCLUDE",
                "txAdmin resource reporting is modified with an exclusion mechanism that can conceal resources",
                "Resource exclusion logic near txAdmin resource reporting")
        end
    end

    -- 4) Massive obfuscated JavaScript appended to sv_reportHeap.js.
    if normalized:find("monitor/resource/sv_reportheap.js", 1, true) then
        local size = #content
        local hasDynamic = lower:find("eval(", 1, true) or lower:find("function(", 1, true)
            or lower:find("function (", 1, true)
        local hasBrowserStorage = lower:find("document.cookie", 1, true)
            or lower:find("localstorage", 1, true)
        local escapeCount = 0
        for _ in content:gmatch("\\x%x%x") do escapeCount = escapeCount + 1 end
        for _ in content:gmatch("\\u%x%x%x%x") do escapeCount = escapeCount + 1 end

        if size >= 10000 and hasDynamic and (hasBrowserStorage or escapeCount >= 40) then
            local marker = lower:find("eval(", 1, true)
                or lower:find("document.cookie", 1, true)
                or lower:find("localstorage", 1, true)
                or 1
            txReport(resource, file, txLine(content, marker), "TXADMIN_OBFUSCATED_JS_INJECTION",
                "CRITICAL", 100, "TAMPERING", "sv_reportHeap.js",
                "txAdmin heap reporter contains an abnormally large obfuscated JavaScript payload with dynamic execution or browser-storage access",
                "File size: " .. tostring(size) .. " bytes | Escapes: " .. tostring(escapeCount))
        end
    end

    -- 5) Explicit integrity anomaly for known tiny txAdmin heap reporter.
    -- A normal version may change, so this is a heuristic anomaly, not a hard hash verdict.
    if normalized:find("monitor/resource/sv_reportheap.js", 1, true) then
        if #content >= 10000 then
            txReport(resource, file, txLine(content, 1), "TXADMIN_HEAP_REPORTER_SIZE_ANOMALY",
                "HIGH", 70, "TAMPERING", "SIZE_ANOMALY",
                "txAdmin sv_reportHeap.js is unexpectedly large; compare against the exact installed official txAdmin release",
                "Observed bytes: " .. tostring(#content))
        end
    end
end
