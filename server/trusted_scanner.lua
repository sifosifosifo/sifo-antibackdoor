SIFO.VerificationResults = {}
SIFO.VerificationPending = 0
SIFO.VerificationStarted = {}

local function sourceForResource(resource)
    for _, source in ipairs(SIFO_TRUSTED_SOURCES or {}) do
        if source.enabled ~= false then
            for _, name in ipairs(source.resourceNames or {}) do
                if SIFO.lower(name) == SIFO.lower(resource) then
                    return source
                end
            end
        end
    end
end

local function addVerification(result)
    SIFO.VerificationResults[#SIFO.VerificationResults + 1] = result
end

local function buildTreeUrl(source)
    local encodedRef = tostring(source.ref or "main"):gsub("#", "%%23"):gsub(" ", "%%20")
    return "https://api.github.com/repos/" .. source.repository
        .. "/git/trees/" .. encodedRef .. "?recursive=1"
end

local function addFileList(resource, list)
    local seen = {}

    local function addMetadata(kind)
        local count = GetNumResourceMetadata(resource, kind) or 0
        for i = 0, count - 1 do
            local file = GetResourceMetadata(resource, kind, i)
            if type(file) == "string" and file ~= "" and not file:find("%*") then
                if not seen[file] then
                    seen[file] = true
                    list[#list + 1] = file
                end
            end
        end
    end

    addMetadata("server_script")
    addMetadata("client_script")
    addMetadata("shared_script")
    addMetadata("file")

    if not seen["fxmanifest.lua"] then list[#list + 1] = "fxmanifest.lua" end
    if LoadResourceFile(resource, "__resource.lua") and not seen["__resource.lua"] then
        list[#list + 1] = "__resource.lua"
    end
end

local function treeMap(tree)
    local map = {}
    for _, item in ipairs(tree or {}) do
        if item.type == "blob" and item.path and item.sha then
            map[item.path] = item.sha
        end
    end
    return map
end

local function compareResource(resource, source, officialTree)
    local files = {}
    addFileList(resource, files)

    local modified = {}
    local extra = {}
    local checked = 0

    for _, path in ipairs(files) do
        local localContent = LoadResourceFile(resource, path)
        if localContent then
            local officialSha = officialTree[path]
            if officialSha then
                checked = checked + 1
                local localSha = SIFO.gitBlobSha1(localContent)
                if SIFO.lower(localSha) ~= SIFO.lower(officialSha) then
                    modified[#modified + 1] = path
                end
            else
                extra[#extra + 1] = path
            end
        end
    end

    local status = "VERIFIED"
    if #modified > 0 or #extra > 0 then
        status = "MODIFIED"
    end

    addVerification({
        resource = resource,
        source = source.name,
        repository = source.repository,
        ref = source.ref or "main",
        status = status,
        checked = checked,
        modified = modified,
        extra = extra
    })
end

function SIFO.verifyTrustedResource(resource)
    if SIFO.VerificationStarted[resource] then return end

    local source = sourceForResource(resource)
    if not source then return end

    SIFO.VerificationStarted[resource] = true
    SIFO.VerificationPending = SIFO.VerificationPending + 1

    PerformHttpRequest(buildTreeUrl(source), function(statusCode, body)
        if statusCode ~= 200 or not body or body == "" then
            addVerification({
                resource = resource,
                source = source.name,
                repository = source.repository,
                ref = source.ref or "main",
                status = "UNAVAILABLE",
                error = "GitHub tree request failed (HTTP " .. tostring(statusCode) .. ")"
            })
            SIFO.VerificationPending = math.max(0, SIFO.VerificationPending - 1)
            return
        end

        local ok, payload = pcall(json.decode, body)
        if not ok or type(payload) ~= "table" or type(payload.tree) ~= "table" then
            addVerification({
                resource = resource,
                source = source.name,
                repository = source.repository,
                ref = source.ref or "main",
                status = "UNAVAILABLE",
                error = "GitHub returned an invalid tree response"
            })
            SIFO.VerificationPending = math.max(0, SIFO.VerificationPending - 1)
            return
        end

        compareResource(resource, source, treeMap(payload.tree))
        SIFO.VerificationPending = math.max(0, SIFO.VerificationPending - 1)
    end, "GET", "", {
        ["User-Agent"] = "SIFO-Sentinel",
        ["Accept"] = "application/vnd.github+json"
    })
end

function SIFO.waitForTrustedVerification(timeoutMs)
    local timeout = tonumber(timeoutMs) or 10000
    local started = GetGameTimer()

    while SIFO.VerificationPending > 0 do
        if (GetGameTimer() - started) >= timeout then
            print("^3[SIFO] Trusted-source verification timed out; continuing with available results.^7")
            break
        end
        Wait(50)
    end
end

function SIFO.getVerificationSummary()
    local summary = { verified = 0, modified = 0, unavailable = 0 }
    for _, result in ipairs(SIFO.VerificationResults) do
        if result.status == "VERIFIED" then
            summary.verified = summary.verified + 1
        elseif result.status == "MODIFIED" then
            summary.modified = summary.modified + 1
        elseif result.status == "UNAVAILABLE" then
            summary.unavailable = summary.unavailable + 1
        end
    end
    return summary
end
