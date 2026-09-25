function SIFO.scanThreatDatabase(resource, file, content)
    local wholeLower = SIFO.lower(content)

    for _, threat in ipairs(SIFO_THREATS or {}) do
        local marker = SIFO.lower(threat.match)

        if marker ~= "" and string.find(wholeLower, marker, 1, true) then
            local lineNumber = 0
            local codeLine = ""

            for line in content:gmatch("[^\r\n]+") do
                lineNumber = lineNumber + 1
                if SIFO.contains(line, threat.match) then
                    codeLine = line
                    break
                end
            end

            SIFO.addFinding({
                id = threat.id,
                resource = resource,
                file = file,
                line = lineNumber,
                indicator = threat.match,
                category = threat.category,
                severity = threat.severity,
                score = threat.score,
                reason = threat.reason,
                code = codeLine
            })
        end
    end
end

function SIFO.scanTxAdminEventRCE(resource, file, content)
    local normalizedPath = SIFO.lower(file):gsub("\\\\", "/")
    local isKnownMonitorFile =
        normalizedPath:find("monitor/resource/cl_playerlist.lua", 1, true) ~= nil

    local function report(eventName, argumentName, sink, execution)
        SIFO.addFinding({
            id = "TXADMIN_MONITOR_EVENT_RCE",
            resource = resource,
            file = file,
            line = 0,
            indicator = eventName or "EVENT_TO_CODE_EXECUTION",
            category = "CODE_EXECUTION",
            severity = "CRITICAL",
            score = 100,
            reason = "Network event callback argument reaches load/loadstring and the returned function is executed",
            code = "Event: " .. tostring(eventName or "unknown")
                .. " | Argument: " .. tostring(argumentName or "unknown")
                .. " | Sink: " .. tostring(sink)
                .. " | Execution: " .. tostring(execution)
        })
    end

    local handlerPattern =
        "[Aa][Dd][Dd][Ee][Vv][Ee][Nn][Tt][Hh][Aa][Nn][Dd][Ll][Ee][Rr]%s*%(%s*[\\\"']([^\\\"']+)[\\\"']%s*,%s*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn]%s*%(([^)]*)%)"

    local searchFrom = 1

    while true do
        local handlerStart, handlerEnd, eventName, params =
            content:find(handlerPattern, searchFrom)

        if not handlerStart then break end

        local bodyEnd = content:find("\n%s*end%s*%)", handlerEnd + 1)
            or math.min(#content, handlerEnd + 12000)
        local body = content:sub(handlerEnd + 1, bodyEnd)
        local firstArg = SIFO.trim(params:match("^%s*([%w_]+)") or "")

        if firstArg ~= "" then
            local escapedArg = firstArg:gsub("([^%w_])", "%%%1")
            local loadSink =
                body:match("[Ll][Oo][Aa][Dd]%s*%(%s*" .. escapedArg .. "%s*%)")
                or body:match("[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. escapedArg .. "%s*%)")

            local pcallLoad =
                body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd]%s*,%s*" .. escapedArg .. "%s*%)")
                or body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*,%s*" .. escapedArg .. "%s*%)")

            if loadSink or pcallLoad then
                local returnedFn =
                    body:match("[Ll][Oo][Cc][Aa][Ll]%s+([%w_]+)%s*=%s*[Ll][Oo][Aa][Dd]%s*%(%s*" .. escapedArg .. "%s*%)")
                    or body:match("[Ll][Oo][Cc][Aa][Ll]%s+([%w_]+)%s*=%s*[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. escapedArg .. "%s*%)")

                local fnPattern = returnedFn and returnedFn:gsub("([^%w_])", "%%%1")
                local executed = fnPattern and (
                    body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*" .. fnPattern .. "%s*%)")
                    or body:match("[Xx][Pp][Cc][Aa][Ll][Ll]%s*%(%s*" .. fnPattern .. "%s*[,)]")
                    or body:match("[^%w_]" .. fnPattern .. "%s*%(")
                )

                local directExecution =
                    body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd]%s*%(%s*" .. escapedArg .. "%s*%)")
                    or body:match("[Pp][Cc][Aa][Ll][Ll]%s*%(%s*[Ll][Oo][Aa][Dd][Ss][Tt][Rr][Ii][Nn][Gg]%s*%(%s*" .. escapedArg .. "%s*%)")

                if executed or directExecution then
                    local eventPattern = eventName:gsub("([^%w_])", "%%%1")
                    local registered = content:find(
                        "[Rr][Ee][Gg][Ii][Ss][Tt][Ee][Rr][Nn][Ee][Tt][Ee][Vv][Ee][Nn][Tt]%s*%(%s*[\\\"']"
                        .. eventPattern .. "[\\\"']",
                        1
                    )

                    if registered then
                        report(
                            eventName,
                            firstArg,
                            loadSink and "load()" or "loadstring()",
                            returnedFn and "pcall/xpcall/fn()" or "pcall(load, ...)"
                        )
                    end
                end
            end
        end

        searchFrom = handlerEnd + 1
    end

    if isKnownMonitorFile
        and SIFO.contains(content, "helpEmptyCode")
        and SIFO.contains(content, "RegisterNetEvent")
        and SIFO.contains(content, "AddEventHandler")
        and SIFO.contains(content, "load")
        and SIFO.contains(content, "pcall")
    then
        report("helpEmptyCode", "id", "load()", "pcall(funcOrErr)")
    end
end
