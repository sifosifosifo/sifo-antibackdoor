local function getDiscordWebhook()
    if not Config.Discord.Enabled then return nil end
    local webhook = Config.Discord.AllWebhook
    if type(webhook) ~= "string" or webhook == "" then return nil end
    return webhook
end

local function getCriticalWebhook()
    if not Config.Discord.Enabled then return nil end
    local webhook = Config.Discord.CriticalWebhook
    if type(webhook) ~= "string" or webhook == "" then return getDiscordWebhook() end
    return webhook
end

function SIFO.formatFinding(finding)
    local location = tostring(finding.resource) .. "/" .. tostring(finding.file)
    if tonumber(finding.line) and finding.line > 0 then location = location .. ":" .. tostring(finding.line) end
    return "**" .. tostring(finding.severity) .. " | " .. tostring(finding.category) .. " | +" .. tostring(finding.score) .. "**\n"
        .. location .. "\nIndicator: [" .. tostring(finding.indicator) .. "]"
        .. "\nReason: " .. tostring(finding.reason) .. "\nCode: [" .. tostring(finding.code) .. "]"
end

function SIFO.discordRequest(webhook, payload)
    if not Config.Discord.Enabled or not webhook or webhook == "" then return end
    PerformHttpRequest(webhook, function(statusCode)
        if statusCode < 200 or statusCode >= 300 then
            print("^1[SIFO] Discord webhook failed: HTTP " .. tostring(statusCode) .. "^7")
        end
    end, "POST", json.encode(payload), { ["Content-Type"] = "application/json" })
end

function SIFO.discordEmbed(webhook, title, description, color)
    if not webhook or webhook == "" then return end
    SIFO.discordRequest(webhook, {
        username = "SIFO Sentinel",
        embeds = {{
            title = title,
            description = description,
            color = color,
            footer = { text = "SIFO Sentinel • FiveM Security Scanner" },
            timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ")
        }}
    })
end

function SIFO.sendDiscordStart()
    local webhook = getDiscordWebhook()
    if not webhook then
        print("^3[SIFO] Discord reporting is enabled but AllWebhook is empty.^7")
        return
    end
    SIFO.discordEmbed(webhook, "🛡️ SIFO Sentinel • Scan Started", "A new FiveM security scan has started.\nThe scanner is analyzing server resources now.", 3447003)
end

function SIFO.getCriticalFindings()
    local result = {}
    for _, finding in ipairs(SIFO.Findings) do
        if finding.severity == "CRITICAL" or finding.score >= Config.Discord.MinScoreForCritical then result[#result + 1] = finding end
    end
    table.sort(result, function(a, b) return (tonumber(a.score) or 0) > (tonumber(b.score) or 0) end)
    return result
end

function SIFO.getHighFindings()
    local result = {}
    for _, finding in ipairs(SIFO.Findings) do
        if finding.severity == "HIGH" and finding.score < Config.Discord.MinScoreForCritical then result[#result + 1] = finding end
    end
    table.sort(result, function(a, b) return (tonumber(a.score) or 0) > (tonumber(b.score) or 0) end)
    return result
end

function SIFO.sendDiscordList(webhook, title, list, color, limit)
    if not webhook or webhook == "" or #list == 0 then return end
    local maxItems = limit or Config.Discord.MaxFindingsPerMessage or 6
    local chunk = {}
    local sent = 0
    for _, finding in ipairs(list) do
        if sent >= maxItems then break end
        chunk[#chunk + 1] = SIFO.formatFinding(finding)
        sent = sent + 1
        if #chunk >= Config.Discord.MaxFindingsPerMessage then
            SIFO.discordEmbed(webhook, title, table.concat(chunk, "\n\n"), color)
            chunk = {}
        end
    end
    if #chunk > 0 then SIFO.discordEmbed(webhook, title, table.concat(chunk, "\n\n"), color) end
end

function SIFO.sendDiscordVerificationReport()
    local webhook = getDiscordWebhook()
    if not webhook then return end

    if type(SIFO.getVerificationSummary) ~= "function" then
        print("^3[SIFO] Official-source verification report skipped: verifier module is not loaded.^7")
        return
    end

    local summary = SIFO.getVerificationSummary()
        local modified, unavailable = {}, {}

    for _, result in ipairs(SIFO.VerificationResults or {}) do
        if result.status == "MODIFIED" then
            modified[#modified + 1] = result
        elseif result.status == "UNAVAILABLE" then
            unavailable[#unavailable + 1] = result
        end
    end

    SIFO.discordEmbed(
        webhook,
        "🔎 SIFO Sentinel • Official Source Verification",
        "Official sources checked: **" .. tostring(#(SIFO.VerificationResults or {})) .. "**\n"
            .. "Verified: **" .. tostring(summary.verified) .. "**\n"
            .. "Modified: **" .. tostring(summary.modified) .. "**\n"
            .. "GitHub unavailable: **" .. tostring(summary.unavailable) .. "**",
        summary.modified > 0 and 15105570 or 3066993
    )

    for _, result in ipairs(modified) do
        local files = {}
        for _, path in ipairs(result.modified or {}) do files[#files + 1] = path end
        for _, path in ipairs(result.extra or {}) do files[#files + 1] = path .. " (not in official tree)" end

        local dangerous = false
        for _, finding in ipairs(SIFO.Findings or {}) do
            if finding.resource == result.resource
                and (finding.severity == "CRITICAL" or (tonumber(finding.score) or 0) >= Config.Discord.MinScoreForCritical)
            then
                dangerous = true
                break
            end
        end

        local title = dangerous and "🚨 MODIFIED + SECURITY THREAT DETECTED" or "⚠️ OFFICIAL RESOURCE MODIFIED"
        local description = "Resource: **" .. result.resource .. "**\n"
            .. "Official: **" .. result.source .. "**\n"
            .. "GitHub: " .. result.repository .. "\n"
            .. "Ref: " .. result.ref .. "\n\n"
            .. "Changed files: " .. (#files > 0 and table.concat(files, ", ") or "none")

        SIFO.discordEmbed(webhook, title, description, dangerous and 15158332 or 15105570)
    end

    for _, result in ipairs(unavailable) do
        SIFO.discordEmbed(
            webhook,
            "⚠️ Official Source Check Unavailable",
            "Resource: **" .. result.resource .. "**\nSource: **" .. result.source .. "**\n" .. tostring(result.error),
            9807270
        )
    end
end

function SIFO.sendDiscordReport()
    local allWebhook = getDiscordWebhook()
    local criticalWebhook = getCriticalWebhook()
    if not allWebhook and not criticalWebhook then
        print("^3[SIFO] Discord report skipped: no webhook configured.^7")
        return
    end

    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 }
    for _, finding in ipairs(SIFO.Findings) do counts[finding.severity] = (counts[finding.severity] or 0) + 1 end

    local summary = table.concat({
        "**Scan completed successfully.**", "",
        "Resources scanned: **" .. tostring(SIFO.ResourcesScanned) .. "**",
        "Files scanned: **" .. tostring(SIFO.FilesScanned) .. "**",
        "Findings: **" .. tostring(#SIFO.Findings) .. "**", "",
        "Critical: **" .. tostring(counts.CRITICAL) .. "**",
        "High: **" .. tostring(counts.HIGH) .. "**",
        "Medium: **" .. tostring(counts.MEDIUM) .. "**",
        "Low: **" .. tostring(counts.LOW) .. "**"
    }, "\n")

    SIFO.discordEmbed(allWebhook or criticalWebhook, "📊 SIFO Sentinel • Scan Complete", summary, counts.CRITICAL > 0 and 15158332 or 3066993)
    SIFO.sendDiscordVerificationReport()

    local critical = SIFO.getCriticalFindings()
    if #critical > 0 then SIFO.sendDiscordList(criticalWebhook or allWebhook, "🚨 Critical Security Findings", critical, 15158332, 12) end

    local high = SIFO.getHighFindings()
    if #high > 0 then SIFO.sendDiscordList(allWebhook or criticalWebhook, "⚠️ Important High Findings", high, 15105570, 8) end
end

function SIFO.writeReport()
    if not Config.LocalReport.Enabled then return end
    local verification = type(SIFO.getVerificationSummary) == "function"
        and SIFO.getVerificationSummary()
        or { verified = 0, modified = 0, unavailable = 0 }
    local output = {
        "SIFO THREAT INTELLIGENCE REPORT",
        "TIME=" .. os.date("%Y-%m-%d %H:%M:%S"),
        "RESOURCES=" .. tostring(SIFO.ResourcesScanned),
        "FILES=" .. tostring(SIFO.FilesScanned),
        "FINDINGS=" .. tostring(#SIFO.Findings),
        "OFFICIAL_VERIFIED=" .. tostring(verification.verified),
        "OFFICIAL_MODIFIED=" .. tostring(verification.modified),
        "----------------------------------------"
    }
    for _, finding in ipairs(SIFO.Findings) do
        output[#output + 1] = tostring(finding.severity) .. "|" .. tostring(finding.score) .. "|" .. tostring(finding.category) .. "|" .. tostring(finding.resource) .. "|" .. tostring(finding.file) .. "|LINE=" .. tostring(finding.line or 0) .. "|" .. tostring(finding.indicator) .. "|" .. tostring(finding.code)
    end
    local content = table.concat(output, "\n")
    SaveResourceFile(SIFO.ResourceName, Config.LocalReport.OutputFile, content, #content)
end

function SIFO.printResourceRisk()
    local list = {}
    for resource, score in pairs(SIFO.ResourceScores) do list[#list + 1] = { resource = resource, score = score } end
    table.sort(list, function(a, b) return a.score > b.score end)
    print("^5[SIFO] Resource Risk Scores:^7")
    if #list == 0 then print("^2[SIFO] No findings.^7"); return end
    for _, item in ipairs(list) do print("^3[SIFO] " .. item.resource .. " -> " .. tostring(item.score) .. "/100 (" .. SIFO.scoreLabel(item.score) .. ")^7") end
end

function SIFO.printSummary()
    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0 }
    for _, finding in ipairs(SIFO.Findings) do counts[finding.severity] = (counts[finding.severity] or 0) + 1 end
    local verification = type(SIFO.getVerificationSummary) == "function"
        and SIFO.getVerificationSummary()
        or { verified = 0, modified = 0, unavailable = 0 }
    print("")
    print("^5==============================================^7")
    print("^5       SIFO THREAT INTELLIGENCE SCANNER^7")
    print("^5==============================================^7")
    print("^7Resources scanned: ^3" .. tostring(SIFO.ResourcesScanned) .. "^7")
    print("^7Allowlisted:       ^3" .. tostring(SIFO.AllowedResources) .. "^7")
    print("^7Files scanned:     ^3" .. tostring(SIFO.FilesScanned) .. "^7")
    print("^7Findings:          ^3" .. tostring(#SIFO.Findings) .. "^7")
    print("^7Official verified: ^2" .. tostring(verification.verified) .. "^7")
    print("^7Official modified: ^3" .. tostring(verification.modified) .. "^7")
    print("^7Official unavailable: ^3" .. tostring(verification.unavailable) .. "^7")
    print("^1Critical:          " .. tostring(counts.CRITICAL) .. "^7")
    print("^1High:              " .. tostring(counts.HIGH) .. "^7")
    print("^3Medium:            " .. tostring(counts.MEDIUM) .. "^7")
    print("^7Low:               " .. tostring(counts.LOW) .. "^7")
    print("^5==============================================^7")
    SIFO.printResourceRisk()
    print("^5==============================================^7")
    print("")
end
