local RESOURCE_NAME = GetCurrentResourceName()

local Config = {
    Discord = {
        Enabled = true,
        -- Webhook for the channel that receives ALL findings.
        AllWebhook = "",
        -- Webhook for the channel that receives CRITICAL findings only.
        CriticalWebhook = "",
        SendCleanSummary = true,
        MaxFindingsPerMessage = 8
    },

    LocalReport = {
        Enabled = false,
        OutputFile = "sifo_forensic.log"
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

    CriticalStrings = {
        "JohnsUrUncle",
        "admins.json",
        "txData",
        "txAdmin",

        "cipher-panel",
        "cipher-panel.me",
        "ketamin.cc",
        "helperServer",
        "Enchanced_Tabs",
        "eszjqvpjhiou.mom",
        "pqzskjptss",
        "GlobalState.miauss",
        "GlobalState.ggWP",
        "all_permissions",
        "RESOURCE_EXCLUDE_LIST",

        "MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR"
    },

    -- عمليات يمكن استخدامها في Backdoors
    SuspiciousStrings = {
        "PerformHttpRequest",
        "PerformHttpRequestInternal",

        "SaveResourceFile",
        "LoadResourceFile",

        "ExecuteCommand",
        "execute",

        "os.execute",
        "io.popen",

        "loadstring",
        "load(",
        "assert(load",

        "RunString",
        "RunStringEx",

        "AddEventHandler",
        "RegisterNetEvent",
        "TriggerServerEvent",
        "TriggerClientEvent",

        "webhook",
        "discord.com/api/webhooks",

        "http://",
        "https://",

        "GetConvar",
        "GetConvarReplicated",

        "Citizen.InvokeNative",
        "StartResource",
        "StopResource",
        "package.loadlib",
        "dofile(",
        "debug.sethook",
        "debug.getinfo",
        "_G[",
        "_ENV[",
        "string.char",
        "string.byte",
        "Base64",
        "base64",
        "fromBase64",
        "decode64"
    }
}

local findings = {}

local resourcesScanned = 0
local filesScanned = 0

local function lower(text)
    return string.lower(text or "")
end

local function extensionOf(path)
    local ext = path:match("%.([^%.]+)$")

    if not ext then
        return nil
    end

    return lower(ext)
end

local function addFinding(
    severity,
    resource,
    file,
    lineNumber,
    keyword,
    line
)
    findings[#findings + 1] = {
        severity = severity,
        resource = resource,
        file = file,
        line = lineNumber,
        keyword = keyword,
        code = line
    }
end

local function searchLine(
    resource,
    file,
    lineNumber,
    line
)
    local lowerLine = lower(line)

    for _, keyword in ipairs(Config.CriticalStrings) do
        if string.find(
            lowerLine,
            lower(keyword),
            1,
            true
        ) then

            addFinding(
                "CRITICAL",
                resource,
                file,
                lineNumber,
                keyword,
                line
            )
        end
    end

    for _, keyword in ipairs(Config.SuspiciousStrings) do
        if string.find(
            lowerLine,
            lower(keyword),
            1,
            true
        ) then

            addFinding(
                "SUSPICIOUS",
                resource,
                file,
                lineNumber,
                keyword,
                line
            )
        end
    end
end


local CombinationRules = {
    {
        name = "Dynamic code execution + network",
        require = {"loadstring", "PerformHttpRequest"}
    },
    {
        name = "Dynamic code execution + resource file access",
        require = {"loadstring", "LoadResourceFile"}
    },
    {
        name = "Dynamic code execution + encoded strings",
        require = {"loadstring", "string.char"}
    },
    {
        name = "Runtime command execution + external request",
        require = {"ExecuteCommand", "PerformHttpRequest"}
    }
}

local function checkCombinations(resource, file, content)
    local whole = lower(content)

    for _, rule in ipairs(CombinationRules) do
        local matched = true

        for _, required in ipairs(rule.require) do
            if not string.find(whole, lower(required), 1, true) then
                matched = false
                break
            end
        end

        if matched then
            addFinding(
                "CRITICAL",
                resource,
                file,
                0,
                table.concat(rule.require, " + "),
                "",
                rule.name
            )
        end
    end

    -- Obfuscation heuristics.
    for line in content:gmatch("[^\r\n]+") do
        if #line >= 1800 then
            addFinding(
                "SUSPICIOUS",
                resource,
                file,
                0,
                "VERY_LONG_LINE",
                line,
                "Very long line can indicate generated/obfuscated code"
            )
            break
        end

        if #line >= 900 and string.find(lower(line), "string.char", 1, true) then
            addFinding(
                "CRITICAL",
                resource,
                file,
                0,
                "OBFUSCATED_PAYLOAD",
                line,
                "Large string.char payload"
            )
            break
        end
    end
end

local function scanFile(resource, file)
    local extension = extensionOf(file)

    if not extension then
        return
    end

    if not Config.ScanExtensions[extension] then
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

    local lineNumber = 0

    for line in content:gmatch("[^\r\n]+") do
        lineNumber = lineNumber + 1

        searchLine(
            resource,
            file,
            lineNumber,
            line
        )
    end

    checkCombinations(resource, file, content)
end

local function scanResource(resource)
    resourcesScanned = resourcesScanned + 1

    local manifestFiles = {
        "fxmanifest.lua",
        "__resource.lua"
    }

    for _, manifest in ipairs(manifestFiles) do
        scanFile(resource, manifest)
    end

    local serverCount =
        GetNumResourceMetadata(
            resource,
            "server_script"
        ) or 0

    for i = 0, serverCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "server_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local clientCount =
        GetNumResourceMetadata(
            resource,
            "client_script"
        ) or 0

    for i = 0, clientCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "client_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local sharedCount =
        GetNumResourceMetadata(
            resource,
            "shared_script"
        ) or 0

    for i = 0, sharedCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "shared_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local fileCount =
        GetNumResourceMetadata(
            resource,
            "file"
        ) or 0

    for i = 0, fileCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "file",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end
end


local function discordRequest(webhook, payload)
    if not Config.Discord.Enabled or not webhook or webhook == "" then
        return
    end

    PerformHttpRequest(
        webhook,
        function(statusCode)
            if statusCode < 200 or statusCode >= 300 then
                print("^1[SIFO] Discord webhook failed. HTTP "
                    .. tostring(statusCode) .. "^7")
            end
        end,
        "POST",
        json.encode(payload),
        {
            ["Content-Type"] = "application/json"
        }
    )
end

local function discordEmbed(webhook, title, description, severity)
    if not webhook or webhook == "" then
        return
    end

    local color = 3066993

    if severity == "CRITICAL" then
        color = 15158332
    elseif severity == "SUSPICIOUS" then
        color = 15844367
    end

    discordRequest(webhook, {
        username = "SIFO Anti Backdoor",
        embeds = {{
            title = title,
            description = description,
            color = color,
            footer = {
                text = "SIFO Anti Backdoor • "
                    .. os.date("%Y-%m-%d %H:%M:%S")
            },
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }}
    })
end

local function formatFinding(finding)
    local location =
        tostring(finding.resource)
        .. "/"
        .. tostring(finding.file)

    if tonumber(finding.line) and finding.line > 0 then
        location = location .. ":" .. tostring(finding.line)
    end

    local code = tostring(finding.code or "")
        :gsub("\r", " ")
        :gsub("\n", " ")
        :gsub("|", "/")

    if #code > 650 then
        code = code:sub(1, 650) .. "..."
    end

    return "**"
        .. tostring(finding.severity)
        .. "** "
        .. location
        .. "\nIndicator: "
        .. tostring(finding.keyword)
        .. "\nReason: "
        .. tostring(finding.reason or finding.keyword)
        .. "\nCode: "
        .. code
end

local function sendDiscordFindings()
    local critical = 0
    local suspicious = 0

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            critical = critical + 1
        elseif finding.severity == "SUSPICIOUS" then
            suspicious = suspicious + 1
        end
    end

    if Config.Discord.SendCleanSummary or #findings > 0 then
        local summary =
            "Scan completed\n"
            .. "Resources: " .. tostring(resourcesScanned) .. "\n"
            .. "Files: " .. tostring(filesScanned) .. "\n"
            .. "Findings: " .. tostring(#findings) .. "\n"
            .. "Critical: " .. tostring(critical) .. "\n"
            .. "Suspicious: " .. tostring(suspicious)

        discordEmbed(
            Config.Discord.AllWebhook,
            "SIFO Security Scan",
            summary,
            critical > 0 and "CRITICAL"
                or (suspicious > 0 and "SUSPICIOUS" or "OK")
        )
    end

    if #findings == 0 then
        return
    end

    -- Channel 1: everything.
    local all = {}

    for _, finding in ipairs(findings) do
        all[#all + 1] = formatFinding(finding)

        if #all >= Config.Discord.MaxFindingsPerMessage then
            discordEmbed(
                Config.Discord.AllWebhook,
                "SIFO • Findings",
                table.concat(all, "\n\n"),
                "SUSPICIOUS"
            )
            all = {}
        end
    end

    if #all > 0 then
        discordEmbed(
            Config.Discord.AllWebhook,
            "SIFO • Findings",
            table.concat(all, "\n\n"),
            "SUSPICIOUS"
        )
    end

    -- Channel 2: CRITICAL only.
    local criticalList = {}

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            criticalList[#criticalList + 1] = formatFinding(finding)

            if #criticalList >= Config.Discord.MaxFindingsPerMessage then
                discordEmbed(
                    Config.Discord.CriticalWebhook,
                    "SIFO • CRITICAL ALERT",
                    table.concat(criticalList, "\n\n"),
                    "CRITICAL"
                )
                criticalList = {}
            end
        end
    end

    if #criticalList > 0 then
        discordEmbed(
            Config.Discord.CriticalWebhook,
            "SIFO • CRITICAL ALERT",
            table.concat(criticalList, "\n\n"),
            "CRITICAL"
        )
    end
end

local function writeReport()
    local output = {}

    output[#output + 1] = "SIFO FORENSIC SCAN"
    output[#output + 1] = "TIME=" .. os.date("%Y-%m-%d %H:%M:%S")
    output[#output + 1] = "RESOURCES=" .. tostring(resourcesScanned)
    output[#output + 1] = "FILES=" .. tostring(filesScanned)
    output[#output + 1] = "FINDINGS=" .. tostring(#findings)
    output[#output + 1] = "----------------------------------------"

    for _, finding in ipairs(findings) do
        local code = tostring(finding.code or "")
            :gsub("\r", " ")
            :gsub("\n", " ")
            :gsub("|", "/")

        output[#output + 1] =
            finding.severity
            .. "|"
            .. finding.resource
            .. "|"
            .. finding.file
            .. "|LINE="
            .. tostring(finding.line)
            .. "|"
            .. finding.keyword
            .. "|"
            .. code
    end

    local content = table.concat(output, "\n")

    if not Config.LocalReport.Enabled then
        return
    end

    local success = SaveResourceFile(
        RESOURCE_NAME,
        Config.LocalReport.OutputFile,
        content,
        #content
    )

    print("")
    print("^5========== SIFO REPORT =========^7")

    print("^7Resource:^3 " .. RESOURCE_NAME .. "^7")
    print("^7File:^3 " .. Config.LocalReport.OutputFile .. "^7")
    print("^7Size:^3 " .. tostring(#content) .. " bytes^7")

    if success then
        print("^2[OK] Report saved successfully.^7")
        print(
            "^2[PATH] ^7resources/[...]/"
            .. RESOURCE_NAME
            .. "/"
            .. Config.OutputFile
        )
    else
        print("^1[ERROR] SaveResourceFile failed!^7")
    end

    print("^5================================^7")
    print("")
end

local function printSummary()

    print("")
    print("^5==============================================^7")
    print("^5        SIFO FORENSIC SECURITY SCANNER^7")
    print("^5==============================================^7")

    print("^7Resources: ^3" .. resourcesScanned .. "^7")
    print("^7Files:     ^3" .. filesScanned .. "^7")
    print("^7Findings:  ^1" .. #findings .. "^7")

    local critical = 0
    local suspicious = 0

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            critical = critical + 1
        else
            suspicious = suspicious + 1
        end
    end

    print("^1Critical:   " .. critical .. "^7")
    print("^3Suspicious: " .. suspicious .. "^7")

    print("^5----------------------------------------------^7")

    if critical > 0 then
        print("^1[!] CRITICAL INDICATORS FOUND^7")
    elseif suspicious > 0 then
        print("^3[!] Suspicious indicators found^7")
    else
        print("^2[OK] No configured indicators found^7")
    end

    print("^5----------------------------------------------^7")

    local displayed = {}

    for _, finding in ipairs(findings) do

        local key =
            finding.resource
            .. "/"
            .. finding.file
            .. ":"
            .. finding.keyword

        if not displayed[key] then

            displayed[key] = true

            if finding.severity == "CRITICAL" then

                print(
                    "^1[CRITICAL]^7 "
                    .. finding.resource
                    .. "/"
                    .. finding.file
                    .. " -> "
                    .. finding.keyword
                )

            else

                print(
                    "^3[SUSPICIOUS]^7 "
                    .. finding.resource
                    .. "/"
                    .. finding.file
                    .. " -> "
                    .. finding.keyword
                )
            end
        end
    end

    print("^5==============================================^7")

    print(
        "^7Report: ^3"
        .. RESOURCE_NAME
        .. "/"
        .. Config.OutputFile
        .. "^7"
    )

    print("^5==============================================^7")
    print("")
end

local function startScan()

    print("")
    print("^5[SIFO] Starting forensic scan...^7")

    local total =
        GetNumResources()

    for i = 0, total - 1 do

        local resource =
            GetResourceByFindIndex(i)

        if resource
            and resource ~= RESOURCE_NAME
        then

            scanResource(resource)

        end
    end

    writeReport()
    sendDiscordFindings()

    printSummary()
end

AddEventHandler(
    "onResourceStart",
    function(resource)

        if resource ~= RESOURCE_NAME then
            return
        end

        CreateThread(function()

            Wait(3000)

            startScan()

        end)
    end
)