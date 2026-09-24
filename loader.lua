local RESOURCE_NAME = GetCurrentResourceName()

local Config = {
    Discord = {
        Enabled = true,
        AllWebhook = "",
        CriticalWebhook = "",
        AllWebhookConvar = "sifo_antibackdoor_all_webhook",
        CriticalWebhookConvar = "sifo_antibackdoor_critical_webhook",
        SendCleanSummary = true,
        MaxFindingsPerMessage = 6,
        MinScoreForCritical = 80
    },

    Scanner = {
        ScanDelay = 5000,
        ScanOnResourceStart = true,
        IgnoreOwnResource = true,
        MaxCodePreview = 700,
        MaxFindingsStored = 5000,
        LongLineLength = 1800,
        HugeStringLength = 900,
        EntropyMinLength = 300,
        EntropyThreshold = 4.6
    },

    LocalReport = {
        Enabled = false,
        OutputFile = "sifo_forensic.log"
    },

    Allowlist = {
        Resources = {
            -- "qb-core",
            -- "ox_lib",
            -- "my-trusted-resource"
        },

        Indicators = {
            -- { resource = "my-resource", indicator = "PerformHttpRequest" }
        }
    },

    ScanExtensions = {
        lua = true,
        js = true,
        json = true,
        cfg = true,
        txt = true,
        sql = true,
        html = true,
        css = true
    },

    CombinationRules = {
        {
            id = "remote_loader_network",
            name = "Remote code loader + network",
            required = {"loadstring", "PerformHttpRequest"},
            score = 40,
            severity = "CRITICAL",
            category = "BACKDOOR"
        },
        {
            id = "remote_loader_file",
            name = "Remote code loader + resource file access",
            required = {"loadstring", "LoadResourceFile"},
            score = 35,
            severity = "CRITICAL",
            category = "BACKDOOR"
        },
        {
            id = "remote_loader_obfuscation",
            name = "Dynamic code + string obfuscation",
            required = {"loadstring", "string.char"},
            score = 35,
            severity = "CRITICAL",
            category = "OBFUSCATION"
        },
        {
            id = "remote_loader_base64",
            name = "Dynamic code + Base64 decoding",
            required = {"loadstring", "base64"},
            score = 35,
            severity = "CRITICAL",
            category = "OBFUSCATION"
        },
        {
            id = "command_network",
            name = "Command execution + network",
            required = {"ExecuteCommand", "PerformHttpRequest"},
            score = 30,
            severity = "CRITICAL",
            category = "BACKDOOR"
        },
        {
            id = "write_start",
            name = "Resource write + dynamic resource start",
            required = {"SaveResourceFile", "StartResource"},
            score = 30,
            severity = "HIGH",
            category = "RESOURCE_MANIPULATION"
        },
        {
            id = "webhook_command",
            name = "Webhook + command execution",
            required = {"discord.com/api/webhooks", "ExecuteCommand"},
            score = 25,
            severity = "HIGH",
            category = "EXFILTRATION"
        },
        {
            id = "debug_obfuscation",
            name = "Debug hook + dynamic globals",
            required = {"debug.sethook", "_G["},
            score = 25,
            severity = "HIGH",
            category = "ANTI_ANALYSIS"
        },
        {
            id = "nui_server_trust",
            name = "NUI callback + server event",
            required = {"RegisterNUICallback", "RegisterNetEvent"},
            score = 8,
            severity = "LOW",
            category = "EXPLOIT"
        }
    }
}

local findings = {}
local findingKeys = {}
local resourceScores = {}
local resourcesScanned = 0
local filesScanned = 0
local allowedResources = 0

local function lower(value)
    return string.lower(tostring(value or ""))
end

local function trim(value)
    return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function getWebhook(configValue, convarName)
    local convar = GetConvar(convarName, "")
    if convar and convar ~= "" then
        return convar
    end
    return configValue
end

local function isResourceAllowed(resource)
    for _, name in ipairs(Config.Allowlist.Resources) do
        if lower(name) == lower(resource) then
            return true
        end
    end
    return false
end

local function isIndicatorAllowed(resource, indicator)
    for _, item in ipairs(Config.Allowlist.Indicators) do
        if item.resource and item.indicator
            and lower(item.resource) == lower(resource)
            and lower(item.indicator) == lower(indicator)
        then
            return true
        end
    end
    return false
end

local function extensionOf(path)
    local ext = tostring(path or ""):match("%.([^%.]+)$")
    return ext and lower(ext) or nil
end

local function scoreLabel(score)
    if score >= 80 then return "CRITICAL" end
    if score >= 60 then return "HIGH" end
    if score >= 30 then return "MEDIUM" end
    if score > 0 then return "LOW" end
    return "CLEAN"
end

local function addScore(resource, score)
    resourceScores[resource] = math.min(
        100,
        (resourceScores[resource] or 0) + math.max(0, score or 0)
    )
end

local function addFinding(data)
    if not data or not data.resource or not data.file then
        return
    end

    if isIndicatorAllowed(
        data.resource,
        data.indicator or data.id or ""
    ) then
        return
    end

    local key = table.concat({
        tostring(data.resource),
        tostring(data.file),
        tostring(data.line or 0),
        tostring(data.id or data.indicator or ""),
        tostring(data.category or "")
    }, "|")

    if findingKeys[key] then
        return
    end

    if #findings >= Config.Scanner.MaxFindingsStored then
        return
    end

    findingKeys[key] = true

    data.severity = data.severity or "LOW"
    data.score = tonumber(data.score) or 0
    data.code = trim(data.code)
        :gsub("\r", " ")
        :gsub("\n", " ")

    if #data.code > Config.Scanner.MaxCodePreview then
        data.code =
            data.code:sub(1, Config.Scanner.MaxCodePreview)
            .. "..."
    end

    findings[#findings + 1] = data
    addScore(data.resource, data.score)
end

local function contains(text, needle)
    return string.find(
        lower(text),
        lower(needle),
        1,
        true
    ) ~= nil
end

local function estimateEntropy(text)
    local length = #text
    if length < 1 then
        return 0
    end

    local counts = {}

    for i = 1, length do
        local byte = text:byte(i)
        counts[byte] = (counts[byte] or 0) + 1
    end

    local entropy = 0

    for _, count in pairs(counts) do
        local p = count / length
        entropy =
            entropy
            - (p * (math.log(p) / math.log(2)))
    end

    return entropy
end

local function scanThreatDatabase(resource, file, content)
    local wholeLower = lower(content)

    for _, threat in ipairs(SIFO_THREATS or {}) do
        local marker = lower(threat.match)

        if marker ~= ""
            and string.find(
                wholeLower,
                marker,
                1,
                true
            )
        then
            local lineNumber = 0
            local codeLine = ""

            for line in content:gmatch("[^\r\n]+") do
                lineNumber = lineNumber + 1

                if contains(line, threat.match) then
                    codeLine = line
                    break
                end
            end

            addFinding({
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

local function scanCombinations(resource, file, content)
    local whole = lower(content)

    for _, rule in ipairs(Config.CombinationRules) do
        local matched = true

        for _, required in ipairs(rule.required) do
            if not string.find(
                whole,
                lower(required),
                1,
                true
            ) then
                matched = false
                break
            end
        end

        if matched then
            addFinding({
                id = rule.id,
                resource = resource,
                file = file,
                line = 0,
                indicator = table.concat(
                    rule.required,
                    " + "
                ),
                category = rule.category,
                severity = rule.severity,
                score = rule.score,
                reason = rule.name,
                code = "Combination rule matched"
            })
        end
    end
end

local function scanObfuscation(resource, file, content)
    local maxLine = 0
    local longestLine = ""

    for line in content:gmatch("[^\r\n]+") do
        if #line > maxLine then
            maxLine = #line
            longestLine = line
        end

        if #line >= Config.Scanner.HugeStringLength
            and contains(line, "string.char")
        then
            addFinding({
                id = "large_string_char_payload",
                resource = resource,
                file = file,
                line = 0,
                indicator = "string.char + very long line",
                category = "OBFUSCATION",
                severity = "CRITICAL",
                score = 70,
                reason = "Large character-construction payload",
                code = line
            })
        end

        local hexCount = 0

        for _ in line:gmatch("\\x%x%x") do
            hexCount = hexCount + 1
        end

        if hexCount >= 12 then
            addFinding({
                id = "hex_encoded_payload",
                resource = resource,
                file = file,
                line = 0,
                indicator = "\\xNN sequence",
                category = "OBFUSCATION",
                severity = "HIGH",
                score = 45,
                reason = "Many hexadecimal escape sequences suggest encoded content",
                code = line
            })
        end
    end

    if maxLine >= Config.Scanner.LongLineLength then
        addFinding({
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
        local entropy = estimateEntropy(content)

        if entropy >= Config.Scanner.EntropyThreshold then
            addFinding({
                id = "high_entropy_file",
                resource = resource,
                file = file,
                line = 0,
                indicator = string.format(
                    "entropy %.2f",
                    entropy
                ),
                category = "OBFUSCATION",
                severity = "MEDIUM",
                score = 20,
                reason = "High byte entropy; inspect for packed or encoded content",
                code = "Entropy analysis"
            })
        end
    end
end

local function scanFile(resource, file)
    local extension = extensionOf(file)

    if not extension
        or not Config.ScanExtensions[extension]
    then
        return
    end

    if string.find(file, "*", 1, true) then
        return
    end

    local content = LoadResourceFile(
        resource,
        file
    )

    if not content then
        return
    end

    filesScanned = filesScanned + 1

    scanThreatDatabase(resource, file, content)
    scanCombinations(resource, file, content)
    scanObfuscation(resource, file, content)
end

local function scanMetadataFiles(resource, metadataName)
    local count =
        GetNumResourceMetadata(
            resource,
            metadataName
        ) or 0

    for i = 0, count - 1 do
        local file =
            GetResourceMetadata(
                resource,
                metadataName,
                i
            )

        if file and file ~= "" then
            scanFile(resource, file)
        end
    end
end

local function scanResource(resource)
    if not resource or resource == "" then
        return
    end

    if Config.Scanner.IgnoreOwnResource
        and resource == RESOURCE_NAME
    then
        return
    end

    resourcesScanned = resourcesScanned + 1

    if isResourceAllowed(resource) then
        allowedResources = allowedResources + 1
        return
    end

    scanFile(resource, "fxmanifest.lua")
    scanFile(resource, "__resource.lua")

    scanMetadataFiles(resource, "server_script")
    scanMetadataFiles(resource, "client_script")
    scanMetadataFiles(resource, "shared_script")
    scanMetadataFiles(resource, "file")
end

local function discordRequest(webhook, payload)
    if not Config.Discord.Enabled
        or not webhook
        or webhook == ""
    then
        return
    end

    PerformHttpRequest(
        webhook,
        function(statusCode)
            if statusCode < 200
                or statusCode >= 300
            then
                print(
                    "^1[SIFO] Discord webhook failed: HTTP "
                    .. tostring(statusCode)
                    .. "^7"
                )
            end
        end,
        "POST",
        json.encode(payload),
        {
            ["Content-Type"] = "application/json"
        }
    )
end

local function discordEmbed(
    webhook,
    title,
    description,
    color
)
    if not webhook or webhook == "" then
        return
    end

    discordRequest(
        webhook,
        {
            username = "SIFO Anti Backdoor",
            embeds = {{
                title = title,
                description = description,
                color = color,
                footer = {
                    text = "SIFO Anti Backdoor"
                },
                timestamp =
                    os.date(
                        "!%Y-%m-%dT%H:%M:%SZ"
                    )
            }}
        }
    )
end

local function getCriticalFindings()
    local result = {}

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL"
            or finding.score
                >= Config.Discord.MinScoreForCritical
        then
            result[#result + 1] = finding
        end
    end

    return result
end

local function formatFinding(finding)
    local location =
        tostring(finding.resource)
        .. "/"
        .. tostring(finding.file)

    if tonumber(finding.line)
        and finding.line > 0
    then
        location =
            location
            .. ":"
            .. tostring(finding.line)
    end

    return "**"
        .. tostring(finding.severity)
        .. " | "
        .. tostring(finding.category)
        .. " | +"
        .. tostring(finding.score)
        .. "**\n"
        .. location
        .. "\nIndicator: ["
        .. tostring(finding.indicator)
        .. "]\nReason: "
        .. tostring(finding.reason)
        .. "\nCode: ["
        .. tostring(finding.code)
        .. "]"
end

local function sendDiscordList(
    webhook,
    title,
    list,
    color
)
    if not webhook
        or webhook == ""
        or #list == 0
    then
        return
    end

    local chunk = {}

    for _, finding in ipairs(list) do
        chunk[#chunk + 1] =
            formatFinding(finding)

        if #chunk
            >= Config.Discord.MaxFindingsPerMessage
        then
            discordEmbed(
                webhook,
                title,
                table.concat(
                    chunk,
                    "\n\n"
                ),
                color
            )

            chunk = {}
        end
    end

    if #chunk > 0 then
        discordEmbed(
            webhook,
            title,
            table.concat(
                chunk,
                "\n\n"
            ),
            color
        )
    end
end

local function sendDiscordReport()
    local allWebhook =
        getWebhook(
            Config.Discord.AllWebhook,
            Config.Discord.AllWebhookConvar
        )

    local criticalWebhook =
        getWebhook(
            Config.Discord.CriticalWebhook,
            Config.Discord.CriticalWebhookConvar
        )

    local critical = 0
    local high = 0
    local medium = 0
    local low = 0

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            critical = critical + 1
        elseif finding.severity == "HIGH" then
            high = high + 1
        elseif finding.severity == "MEDIUM" then
            medium = medium + 1
        else
            low = low + 1
        end
    end

    local summary =
        "**SIFO Threat Intelligence Scan**\n"
        .. "Resources: **"
        .. tostring(resourcesScanned)
        .. "**\n"
        .. "Allowed: **"
        .. tostring(allowedResources)
        .. "**\n"
        .. "Files: **"
        .. tostring(filesScanned)
        .. "**\n"
        .. "Findings: **"
        .. tostring(#findings)
        .. "**\n"
        .. "Critical: **"
        .. tostring(critical)
        .. "**\n"
        .. "High: **"
        .. tostring(high)
        .. "**\n"
        .. "Medium: **"
        .. tostring(medium)
        .. "**\n"
        .. "Low: **"
        .. tostring(low)
        .. "**"

    if Config.Discord.SendCleanSummary
        or #findings > 0
    then
        local color = 3066993

        if critical > 0 then
            color = 15158332
        elseif high > 0 then
            color = 15844367
        elseif medium > 0 then
            color = 16776960
        end

        discordEmbed(
            allWebhook,
            "SIFO • Scan Summary",
            summary,
            color
        )
    end

    sendDiscordList(
        allWebhook,
        "SIFO • All Findings",
        findings,
        15844367
    )

    sendDiscordList(
        criticalWebhook,
        "SIFO • CRITICAL ALERT",
        getCriticalFindings(),
        15158332
    )
end

local function writeReport()
    if not Config.LocalReport.Enabled then
        return
    end

    local output = {
        "SIFO THREAT INTELLIGENCE REPORT",
        "TIME=" .. os.date("%Y-%m-%d %H:%M:%S"),
        "RESOURCES=" .. tostring(resourcesScanned),
        "FILES=" .. tostring(filesScanned),
        "FINDINGS=" .. tostring(#findings),
        "----------------------------------------"
    }

    for _, finding in ipairs(findings) do
        output[#output + 1] =
            tostring(finding.severity)
            .. "|"
            .. tostring(finding.score)
            .. "|"
            .. tostring(finding.category)
            .. "|"
            .. tostring(finding.resource)
            .. "|"
            .. tostring(finding.file)
            .. "|LINE="
            .. tostring(finding.line or 0)
            .. "|"
            .. tostring(finding.indicator)
            .. "|"
            .. tostring(finding.code)
    end

    local content =
        table.concat(output, "\n")

    SaveResourceFile(
        RESOURCE_NAME,
        Config.LocalReport.OutputFile,
        content,
        #content
    )
end

local function printResourceRisk()
    local list = {}

    for resource, score in pairs(resourceScores) do
        list[#list + 1] = {
            resource = resource,
            score = score
        }
    end

    table.sort(
        list,
        function(a, b)
            return a.score > b.score
        end
    )

    print("^5[SIFO] Resource Risk Scores:^7")

    if #list == 0 then
        print("^2[SIFO] No findings.^7")
        return
    end

    for _, item in ipairs(list) do
        print(
            "^3[SIFO] "
            .. item.resource
            .. " -> "
            .. tostring(item.score)
            .. "/100 ("
            .. scoreLabel(item.score)
            .. ")^7"
        )
    end
end

local function printSummary()
    local critical = 0
    local high = 0
    local medium = 0
    local low = 0

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            critical = critical + 1
        elseif finding.severity == "HIGH" then
            high = high + 1
        elseif finding.severity == "MEDIUM" then
            medium = medium + 1
        else
            low = low + 1
        end
    end

    print("")
    print("^5==============================================^7")
    print("^5       SIFO THREAT INTELLIGENCE SCANNER^7")
    print("^5==============================================^7")
    print("^7Resources scanned: ^3"
        .. tostring(resourcesScanned)
        .. "^7")
    print("^7Allowlisted:       ^3"
        .. tostring(allowedResources)
        .. "^7")
    print("^7Files scanned:     ^3"
        .. tostring(filesScanned)
        .. "^7")
    print("^7Findings:          ^3"
        .. tostring(#findings)
        .. "^7")
    print("^1Critical:          "
        .. tostring(critical)
        .. "^7")
    print("^1High:              "
        .. tostring(high)
        .. "^7")
    print("^3Medium:            "
        .. tostring(medium)
        .. "^7")
    print("^7Low:               "
        .. tostring(low)
        .. "^7")
    print("^5==============================================^7")

    printResourceRisk()

    print("^5==============================================^7")
    print("")
end

local scanRunning = false

local function startScan()
    if scanRunning then
        print("^3[SIFO] A scan is already running.^7")
        return
    end

    scanRunning = true

    findings = {}
    findingKeys = {}
    resourceScores = {}
    resourcesScanned = 0
    filesScanned = 0
    allowedResources = 0

    print(
        "^5[SIFO] Threat intelligence scan started...^7"
    )

    local total = GetNumResources()

    for i = 0, total - 1 do
        local resource =
            GetResourceByFindIndex(i)

        if resource then
            scanResource(resource)
        end
    end

    writeReport()
    sendDiscordReport()
    printSummary()

    scanRunning = false
end

RegisterCommand(
    "sifo_scan",
    function(source)
        if source ~= 0 then
            return
        end

        startScan()
    end,
    false
)

RegisterCommand(
    "sifo_risk",
    function(source)
        if source ~= 0 then
            return
        end

        printResourceRisk()
    end,
    false
)

AddEventHandler(
    "onResourceStart",
    function(resource)
        if resource ~= RESOURCE_NAME then
            return
        end

        if not Config.Scanner.ScanOnResourceStart then
            return
        end

        CreateThread(function()
            Wait(Config.Scanner.ScanDelay)
            startScan()
        end)
    end
)

if not SIFO_THREATS then
    print("^1[SIFO] Threat database failed to load.^7")
end
