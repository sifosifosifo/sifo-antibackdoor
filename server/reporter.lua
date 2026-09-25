function SIFO.formatFinding(finding)
    local location = tostring(finding.resource) .. "/" .. tostring(finding.file)

    if tonumber(finding.line) and finding.line > 0 then
        location = location .. ":" .. tostring(finding.line)
    end

    return "**" .. tostring(finding.severity)
        .. " | " .. tostring(finding.category)
        .. " | +" .. tostring(finding.score) .. "**\n"
        .. location
        .. "\nIndicator: [" .. tostring(finding.indicator) .. "]"
        .. "\nReason: " .. tostring(finding.reason)
        .. "\nCode: [" .. tostring(finding.code) .. "]"
end

function SIFO.discordRequest(webhook, payload)
    if not Config.Discord.Enabled or not webhook or webhook == "" then return end

    PerformHttpRequest(webhook, function(statusCode)
        if statusCode < 200 or statusCode >= 300 then
            print("^1[SIFO] Discord webhook failed: HTTP " .. tostring(statusCode) .. "^7")
        end
    end, "POST", json.encode(payload), {
        ["Content-Type"] = "application/json"
    })
end

function SIFO.discordEmbed(webhook, title, description, color)
    if not webhook or webhook == "" then return end

    SIFO.discordRequest(webhook, {
        username = "SIFO Anti Backdoor",
        embeds = {{
            title = title,
            description = description,
            color = color,
            footer = { text = "SIFO Anti Backdoor" },
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }}
    })
end

function SIFO.getCriticalFindings()
    local result = {}
    for _, finding in ipairs(SIFO.Findings) do
        if finding.severity == "CRITICAL"
            or finding.score >= Config.Discord.MinScoreForCritical
        then
            result[#result + 1] = finding
        end
    end
    return result
end

function SIFO.sendDiscordList(webhook, title, list, color)
    if not webhook or webhook == "" or #list == 0 then return end

    local chunk = {}
    for _, finding in ipairs(list) do
        chunk[#chunk + 1] = SIFO.formatFinding(finding)

        if #chunk >= Config.Discord.MaxFindingsPerMessage then
            SIFO.discordEmbed(webhook, title, table.concat(chunk, "\n\n"), color)
            chunk = {}
        end
    end

    if #chunk > 0 then
        SIFO.discordEmbed(webhook, title, table.concat(chunk, "\n\n"), color)
    end
end

function SIFO.sendDiscordReport()
    local allWebhook = SIFO.getWebhook(Config.Discord.AllWebhook, Config.Discord.AllWebhookConvar)
    local criticalWebhook = SIFO.getWebhook(Config.Discord.CriticalWebhook, Config.Discord.CriticalWebhookConvar)

    local critical, high, medium, low = 0, 0, 0, 0

    for _, finding in ipairs(SIFO.Findings) do
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

    local summary = "**SIFO Threat Intelligence Scan**\n"
        .. "Resources: **" .. tostring(SIFO.ResourcesScanned) .. "**\n"
        .. "Allowed: **" .. tostring(SIFO.AllowedResources) .. "**\n"
        .. "Files: **" .. tostring(SIFO.FilesScanned) .. "**\n"
        .. "Findings: **" .. tostring(#SIFO.Findings) .. "**\n"
        .. "Critical: **" .. tostring(critical) .. "**\n"
        .. "High: **" .. tostring(high) .. "**\n"
        .. "Medium: **" .. tostring(medium) .. "**\n"
        .. "Low: **" .. tostring(low) .. "**"

    if Config.Discord.SendCleanSummary or #SIFO.Findings > 0 then
        local color = 3066993
        if critical > 0 then color = 15158332
        elseif high > 0 then color = 15844367
        elseif medium > 0 then color = 16776960 end

        SIFO.discordEmbed(allWebhook, "SIFO • Scan Summary", summary, color)
    end

    SIFO.sendDiscordList(allWebhook, "SIFO • All Findings", SIFO.Findings, 15844367)
    SIFO.sendDiscordList(allWebhook, "SIFO • CRITICAL ALERT", SIFO.getCriticalFindings(), 15158332)
end

function SIFO.writeReport()
    if not Config.LocalReport.Enabled then return end

    local output = {
        "SIFO THREAT INTELLIGENCE REPORT",
        "TIME=" .. os.date("%Y-%m-%d %H:%M:%S"),
        "RESOURCES=" .. tostring(SIFO.ResourcesScanned),
        "FILES=" .. tostring(SIFO.FilesScanned),
        "FINDINGS=" .. tostring(#SIFO.Findings),
        "----------------------------------------"
    }

    for _, finding in ipairs(SIFO.Findings) do
        output[#output + 1] =
            tostring(finding.severity) .. "|"
            .. tostring(finding.score) .. "|"
            .. tostring(finding.category) .. "|"
            .. tostring(finding.resource) .. "|"
            .. tostring(finding.file) .. "|LINE="
            .. tostring(finding.line or 0) .. "|"
            .. tostring(finding.indicator) .. "|"
            .. tostring(finding.code)
    end

    local content = table.concat(output, "\n")
    SaveResourceFile(SIFO.ResourceName, Config.LocalReport.OutputFile, content, #content)
end

function SIFO.printResourceRisk()
    local list = {}

    for resource, score in pairs(SIFO.ResourceScores) do
        list[#list + 1] = { resource = resource, score = score }
    end

    table.sort(list, function(a, b) return a.score > b.score end)

    print("^5[SIFO] Resource Risk Scores:^7")
    if #list == 0 then
        print("^2[SIFO] No findings.^7")
        return
    end

    for _, item in ipairs(list) do
        print("^3[SIFO] " .. item.resource .. " -> "
            .. tostring(item.score) .. "/100 ("
            .. SIFO.scoreLabel(item.score) .. ")^7")
    end
end

function SIFO.printSummary()
    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 }

    for _, finding in ipairs(SIFO.Findings) do
        counts[finding.severity] = (counts[finding.severity] or 0) + 1
    end

    print("")
    print("^5==============================================^7")
    print("^5       SIFO THREAT INTELLIGENCE SCANNER^7")
    print("^5==============================================^7")
    print("^7Resources scanned: ^3" .. tostring(SIFO.ResourcesScanned) .. "^7")
    print("^7Allowlisted:       ^3" .. tostring(SIFO.AllowedResources) .. "^7")
    print("^7Files scanned:     ^3" .. tostring(SIFO.FilesScanned) .. "^7")
    print("^7Findings:          ^3" .. tostring(#SIFO.Findings) .. "^7")
    print("^1Critical:          " .. tostring(counts.CRITICAL) .. "^7")
    print("^1High:              " .. tostring(counts.HIGH) .. "^7")
    print("^3Medium:            " .. tostring(counts.MEDIUM) .. "^7")
    print("^7Low:               " .. tostring(counts.LOW) .. "^7")
    print("^5==============================================^7")
    SIFO.printResourceRisk()
    print("^5==============================================^7")
    print("")
end
