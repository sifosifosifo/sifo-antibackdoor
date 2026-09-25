SIFO = SIFO or {}

SIFO.ResourceName = GetCurrentResourceName()
SIFO.Findings = {}
SIFO.FindingKeys = {}
SIFO.ResourceScores = {}
SIFO.ResourcesScanned = 0
SIFO.FilesScanned = 0
SIFO.AllowedResources = 0
SIFO.ScanRunning = false

function SIFO.lower(value)
    return string.lower(tostring(value or ""))
end

function SIFO.trim(value)
    return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

function SIFO.contains(text, needle)
    return string.find(
        SIFO.lower(text),
        SIFO.lower(needle),
        1,
        true
    ) ~= nil
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
    SIFO.ResourceScores[resource] = math.min(
        100,
        (SIFO.ResourceScores[resource] or 0) + math.max(0, score or 0)
    )
end

function SIFO.isResourceAllowed(resource)
    for _, name in ipairs(Config.Allowlist.Resources or {}) do
        if SIFO.lower(name) == SIFO.lower(resource) then
            return true
        end
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
    if not data or not data.resource or not data.file then
        return
    end

    if SIFO.isIndicatorAllowed(
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

    if SIFO.FindingKeys[key]
        or #SIFO.Findings >= Config.Scanner.MaxFindingsStored
    then
        return
    end

    SIFO.FindingKeys[key] = true
    data.severity = data.severity or "LOW"
    data.score = tonumber(data.score) or 0
    data.code = SIFO.trim(data.code)
        :gsub("\r", " ")
        :gsub("\n", " ")

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

function SIFO.getWebhook(configValue, convarName)
    local convar = GetConvar(convarName, "")
    if convar and convar ~= "" then
        return convar
    end
    return configValue
end

function SIFO.reset()
    SIFO.Findings = {}
    SIFO.FindingKeys = {}
    SIFO.ResourceScores = {}
    SIFO.ResourcesScanned = 0
    SIFO.FilesScanned = 0
    SIFO.AllowedResources = 0
end
