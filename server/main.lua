SIFO = SIFO or {}

SIFO.ResourceName = GetCurrentResourceName()
SIFO.Findings = {}
SIFO.FindingKeys = {}
SIFO.ResourceScores = {}
SIFO.VerificationResults = {}
SIFO.VerificationPending = 0
SIFO.VerificationStarted = {}
SIFO.ResourcesScanned = 0
SIFO.FilesScanned = 0
SIFO.AllowedResources = 0
SIFO.ScanYieldCounter = 0
SIFO.ScanRunning = false

-- Low-confidence APIs are useful as context for behavioral rules, but they are
-- not security findings by themselves. Keeping them out of the finding list
-- prevents normal FiveM resources from being classified as compromised.
SIFO.CONTEXT_ONLY_THREATS = {
    event_register = true,
    server_event_trigger = true,
    client_event_trigger = true,
    event_handler = true,
    outbound_http = true,
    internal_http = true,
    http_url = true,
    https_url = true,
    resource_read = true,
    convar_access = true,
    replicated_convar_access = true,
    debug_info = true,
    dynamic_global = true,
    dynamic_environment = true,
    string_byte = true,
    base64 = true,
    decode64 = true,
    from_base64 = true,
    admin_file = true,
    txdata = true,
    sql_raw_concat = true,
    sql_update = true,
    nui_callback = true,
    state_bag = true,
    entity_network_control = true,
    raw_sql_execute = true,
    client_server_trust_money = true,
    inventory_mutation_sink = true,
    dynamic_code_assert_load = true
}

function SIFO.lower(value)
    return string.lower(tostring(value or ""))
end

function SIFO.trim(value)
    return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

function SIFO.contains(text, needle)
    return string.find(SIFO.lower(text), SIFO.lower(needle), 1, true) ~= nil
end

function SIFO.extensionOf(path)
    local ext = tostring(path or ""):match("%.([^%.]+)$")
    return ext and SIFO.lower(ext) or nil
end

function SIFO.scoreLabel(score)
    if score >= 80 then return "CRITICAL" end
    if score >= 60 then return "HIGH" end
    if score >= 30 then return "MEDIUM" end
    if score > 0 then return "LOW" end
    return "CLEAN"
end

function SIFO.addScore(resource, score)
    SIFO.ResourceScores[resource] = math.min(100, (SIFO.ResourceScores[resource] or 0) + math.max(0, score or 0))
end

function SIFO.isResourceAllowed(resource)
    for _, name in ipairs(Config.Allowlist.Resources or {}) do
        if SIFO.lower(name) == SIFO.lower(resource) then return true end
    end
    return false
end

function SIFO.isIndicatorAllowed(resource, indicator)
    for _, item in ipairs(Config.Allowlist.Indicators or {}) do
        if item.resource and item.indicator
            and SIFO.lower(item.resource) == SIFO.lower(resource)
            and SIFO.lower(item.indicator) == SIFO.lower(indicator)
        then
            return true
        end
    end
    return false
end

function SIFO.addFinding(data)
    if not data or not data.resource or not data.file then return end
    if SIFO.CONTEXT_ONLY_THREATS[data.id] then return end
    if SIFO.isIndicatorAllowed(data.resource, data.indicator or data.id or "") then return end

    local key = table.concat({
        tostring(data.resource), tostring(data.file), tostring(data.line or 0),
        tostring(data.id or data.indicator or ""), tostring(data.category or "")
    }, "|")

    if SIFO.FindingKeys[key] or #SIFO.Findings >= Config.Scanner.MaxFindingsStored then return end

    SIFO.FindingKeys[key] = true
    data.severity = data.severity or "LOW"
    data.score = tonumber(data.score) or 0
    data.code = SIFO.trim(data.code):gsub("\\r", " "):gsub("\\n", " ")

    if #data.code > Config.Scanner.MaxCodePreview then
        data.code = data.code:sub(1, Config.Scanner.MaxCodePreview) .. "..."
    end

    SIFO.Findings[#SIFO.Findings + 1] = data
    SIFO.addScore(data.resource, data.score)
end

function SIFO.estimateEntropy(text)
    local length = #text
    if length < 1 then return 0 end
    local counts = {}
    for i = 1, length do
        local byte = text:byte(i)
        counts[byte] = (counts[byte] or 0) + 1
    end
    local entropy = 0
    for _, count in pairs(counts) do
        local p = count / length
        entropy = entropy - (p * (math.log(p) / math.log(2)))
    end
    return entropy
end

function SIFO.getWebhook(configValue)
    if type(configValue) ~= "string" then return nil end
    return configValue
end

function SIFO.reset()
    SIFO.Findings = {}
    SIFO.FindingKeys = {}
    SIFO.ResourceScores = {}
    SIFO.VerificationResults = {}
    SIFO.VerificationPending = 0
    SIFO.VerificationStarted = {}
    SIFO.ResourcesScanned = 0
    SIFO.FilesScanned = 0
    SIFO.AllowedResources = 0
    SIFO.ScanYieldCounter = 0
end
