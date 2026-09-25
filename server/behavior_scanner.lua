function SIFO.scanBehavioralSecurity(resource, file, content)
    local whole = SIFO.lower(content)

    local function report(id, category, severity, score, reason, indicator)
        SIFO.addFinding({
            id = id,
            resource = resource,
            file = file,
            line = 0,
            indicator = indicator,
            category = category,
            severity = severity,
            score = score,
            reason = reason,
            code = "Behavioral rule matched"
        })
    end

    if SIFO.contains(whole, "performhttprequest")
        and (SIFO.contains(whole, "assert(load(")
            or SIFO.contains(whole, "loadstring")
            or SIFO.contains(whole, "load("))
    then
        report("BEHAVIOR_REMOTE_CODE_EXECUTION", "CODE_EXECUTION", "CRITICAL", 55,
            "Network request and dynamic Lua execution primitives occur in the same resource file",
            "PerformHttpRequest + load/loadstring")
    end

    if SIFO.contains(whole, "registernetevent")
        and SIFO.contains(whole, "addeventhandler")
        and (SIFO.contains(whole, "addmoney")
            or SIFO.contains(whole, "additem")
            or SIFO.contains(whole, "removemoney")
            or SIFO.contains(whole, "removeitem"))
    then
        report("BEHAVIOR_EVENT_TO_ECONOMY", "EXPLOIT", "HIGH", 45,
            "Network event handler reaches an economy/inventory mutation sink; validate all client-controlled arguments server-side",
            "RegisterNetEvent + AddEventHandler + economy sink")
    end

    if SIFO.contains(whole, "registernuicallback")
        and (SIFO.contains(whole, "addmoney")
            or SIFO.contains(whole, "additem")
            or SIFO.contains(whole, "removemoney")
            or SIFO.contains(whole, "removeitem"))
    then
        report("BEHAVIOR_NUI_TO_ECONOMY", "EXPLOIT", "HIGH", 40,
            "NUI callback reaches an economy/inventory mutation sink; validate every value and permission",
            "RegisterNUICallback + economy sink")
    end

    if SIFO.contains(whole, "registernetevent")
        and SIFO.contains(whole, "networkgetentityfromnetworkid")
    then
        report("BEHAVIOR_EVENT_ENTITY_SPOOF", "EXPLOIT", "MEDIUM", 30,
            "Network event accepts or resolves network entity identifiers; validate ownership and entity type",
            "RegisterNetEvent + NetworkGetEntityFromNetworkId")
    end

    if SIFO.contains(whole, "registernetevent")
        and SIFO.contains(whole, "addeventhandler")
        and (SIFO.contains(whole, "mysql.query")
            or SIFO.contains(whole, "mysql.async")
            or SIFO.contains(whole, "oxmysql"))
    then
        report("BEHAVIOR_EVENT_TO_DATABASE", "EXPLOIT", "MEDIUM", 25,
            "Network event reaches a database sink; inspect parameterization and authorization",
            "RegisterNetEvent + database sink")
    end

    local normalizedFile = SIFO.lower(file):gsub("\\\\", "/")
    if normalizedFile == "fxmanifest.lua" or normalizedFile == "__resource.lua" then
        if SIFO.contains(whole, "server_script")
            and (SIFO.contains(whole, "http://") or SIFO.contains(whole, "https://"))
        then
            report("BEHAVIOR_REMOTE_MANIFEST_DEPENDENCY", "SUPPLY_CHAIN", "HIGH", 35,
                "Resource manifest references a network URL near server-side script declarations",
                "Manifest + remote URL")
        end
    end

    if SIFO.contains(whole, "string.char")
        and (SIFO.contains(whole, "loadstring")
            or SIFO.contains(whole, "load(")
            or SIFO.contains(whole, "assert(load"))
    then
        report("BEHAVIOR_OBFUSCATED_EXECUTION", "OBFUSCATION", "CRITICAL", 60,
            "Character construction is combined with a Lua execution sink",
            "string.char + load/loadstring")
    end
end

function SIFO.scanObfuscation(resource, file, content)
    local maxLine = 0
    local longestLine = ""

    for line in content:gmatch("[^\r\n]+") do
        if #line > maxLine then
            maxLine = #line
            longestLine = line
        end

        if #line >= Config.Scanner.HugeStringLength
            and SIFO.contains(line, "string.char")
            and (SIFO.contains(line, "load(")
                or SIFO.contains(line, "loadstring")
                or SIFO.contains(line, "assert(load"))
        then
            SIFO.addFinding({
                id = "large_string_char_payload",
                resource = resource,
                file = file,
                line = 0,
                indicator = "string.char + execution sink",
                category = "OBFUSCATION",
                severity = "CRITICAL",
                score = 70,
                reason = "Large character-construction payload combined with dynamic code execution",
                code = line
            })
        end

        local hexCount = 0
        for _ in line:gmatch("\\x%x%x") do
            hexCount = hexCount + 1
        end

        if hexCount >= 12
            and (SIFO.contains(line, "load(")
                or SIFO.contains(line, "loadstring")
                or SIFO.contains(line, "assert(load"))
        then
            SIFO.addFinding({
                id = "hex_encoded_payload",
                resource = resource,
                file = file,
                line = 0,
                indicator = "\\xNN + execution sink",
                category = "OBFUSCATION",
                severity = "HIGH",
                score = 45,
                reason = "Encoded hexadecimal content is combined with a Lua execution sink",
                code = line
            })
        end
    end

    if maxLine >= Config.Scanner.LongLineLength then
        SIFO.addFinding({
            id = "very_long_line",
            resource = resource,
            file = file,
            line = 0,
            indicator = "VERY_LONG_LINE",
            category = "OBFUSCATION",
            severity = "MEDIUM",
            score = 25,
            reason = "Extremely long line can indicate generated or obfuscated code",
            code = longestLine
        })
    end

    if #content >= Config.Scanner.EntropyMinLength then
        local entropy = SIFO.estimateEntropy(content)
        if entropy >= Config.Scanner.EntropyThreshold then
            SIFO.addFinding({
                id = "high_entropy_file",
                resource = resource,
                file = file,
                line = 0,
                indicator = string.format("entropy %.2f", entropy),
                category = "OBFUSCATION",
                severity = "MEDIUM",
                score = 20,
                reason = "High byte entropy; inspect for packed or encoded content",
                code = "Entropy analysis"
            })
        end
    end
end
