-- SIFO Anti Backdoor - automatic updater
local RESOURCE_NAME = GetCurrentResourceName()
local LOCAL_VERSION_FILE = "version.txt"

local GITHUB_API_BASE = "https://api.github.com/repos/sifosifosifo/sifo-antibackdoor/contents/"
local GITHUB_REF = "main"

local function githubHeaders()
    local headers = {
        ["User-Agent"] = "SIFO-AntiBackdoor-Updater",
        ["Accept"] = "application/vnd.github.raw+json",
        ["X-GitHub-Api-Version"] = "2022-11-28"
    }

    if Config and Config.GitHub and Config.GitHub.Enabled
        and type(Config.GitHub.Token) == "string"
        and Config.GitHub.Token ~= ""
    then
        headers["Authorization"] = "Bearer " .. Config.GitHub.Token
    end

    return headers
end

local function encodePath(path)
    return tostring(path):gsub("([^%w%._%-%/])", function(char)
        return string.format("%%%02X", string.byte(char))
    end)
end

local function githubFileUrl(path)
    return GITHUB_API_BASE .. encodePath(path) .. "?ref=" .. GITHUB_REF
end

local function requestFile(path, callback)
    PerformHttpRequest(githubFileUrl(path), function(status, body)
        callback(status, body or "")
    end, "GET", "", githubHeaders())
end

local function readLocalVersion()
    local value = LoadResourceFile(RESOURCE_NAME, LOCAL_VERSION_FILE)
    value = tostring(value or ""):gsub("%s+", "")
    return value ~= "" and value or "0.0.0"
end

local function versionParts(version)
    local a, b, c = tostring(version or "0.0.0"):match("^(%d+)%.(%d+)%.(%d+)")
    return tonumber(a) or 0, tonumber(b) or 0, tonumber(c) or 0
end

local function isNewer(remote, localVersion)
    local ra, rb, rc = versionParts(remote)
    local la, lb, lc = versionParts(localVersion)

    if ra ~= la then return ra > la end
    if rb ~= lb then return rb > lb end
    return rc > lc
end

local function log(message)
    print(("[SIFO Updater] %s"):format(message))
end

local function updateFiles(manifest, localVersion)
    local files = manifest.files or {}
    if #files == 0 then
        log("^1Update manifest contains no files.^7")
        return
    end

    log(("Update found: %s -> %s"):format(localVersion, manifest.version))
    log("Downloading update files. New code loads on the next restart.")

    local index = 1
    local failed = false

    local function nextFile()
        local entry = files[index]
        index = index + 1

        if not entry then
            if failed then
                log("^1Update incomplete. Version marker was not changed; it will retry next start.^7")
                return
            end

            SaveResourceFile(RESOURCE_NAME, LOCAL_VERSION_FILE, tostring(manifest.version) .. "\n", -1)
            log(("^2Update %s downloaded successfully.^7"):format(manifest.version))
            return
        end

        local path = type(entry) == "string" and entry or entry.path

        -- Customer-owned configuration must never be replaced by public updates.
        if path == "config.lua" then
            log("Skipping private config.lua")
            nextFile()
            return
        end

        if type(path) ~= "string" or path == "" or path:find("%.%.", 1, true) then
            failed = true
            log(("^1Rejected invalid update path: %s^7"):format(tostring(path)))
            nextFile()
            return
        end

        requestFile(path, function(status, body)
            if status ~= 200 or body == "" then
                failed = true
                log(("^1Failed to download %s (HTTP %s).^7"):format(path, tostring(status)))

                if status == 401 or status == 403 or status == 404 then
                    log("^3Check Config.GitHub.Token and make sure it has Contents: Read-only access to the repository.^7")
                end

                nextFile()
                return
            end

            local ok = SaveResourceFile(RESOURCE_NAME, path, body, -1)
            if not ok then
                failed = true
                log(("^1Failed to save %s.^7"):format(path))
            end

            nextFile()
        end)
    end

    nextFile()
end

CreateThread(function()
    Wait(1500)

    if not Config or not Config.GitHub or not Config.GitHub.Enabled then
        log("GitHub updater is disabled in config.lua.")
        return
    end

    local localVersion = readLocalVersion()
    log(("Current version: %s"):format(localVersion))
    log("Checking GitHub for updates...")

    if type(Config.GitHub.Token) ~= "string" or Config.GitHub.Token == "" then
        log("^3No GitHub token configured. Private repository update checks require Config.GitHub.Token.^7")
    end

    requestFile("update_manifest.json", function(status, body)
        if status ~= 200 or body == "" then
            log(("^3Could not check GitHub for updates (HTTP %s). Continuing normally.^7"):format(tostring(status)))

            if status == 401 or status == 403 or status == 404 then
                log("^3For a private repository, verify Config.GitHub.Token and Contents: Read-only permission.^7")
            end

            return
        end

        local ok, manifest = pcall(json.decode, body)
        if not ok or type(manifest) ~= "table" or type(manifest.version) ~= "string" then
            log("^1GitHub update manifest is invalid. Continuing normally.^7")
            return
        end

        if not isNewer(manifest.version, localVersion) then
            log("^2No update available.^7")
            return
        end

        updateFiles(manifest, localVersion)
    end)
end)
