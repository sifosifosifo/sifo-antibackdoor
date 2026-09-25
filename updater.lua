-- SIFO Sentinel - public GitHub automatic updater
local RESOURCE_NAME = GetCurrentResourceName()
local VERSION_FILE = "version.txt"
local MANIFEST_URL = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/update_manifest.json"
local FILE_BASE_URL = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/"

local function log(message)
    print(("[SIFO Updater] %s"):format(message))
end

local function readLocalVersion()
    local value = LoadResourceFile(RESOURCE_NAME, VERSION_FILE)
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

local function request(url, callback)
    PerformHttpRequest(url, function(status, body)
        callback(status, body or "")
    end, "GET", "", {
        ["User-Agent"] = "SIFO-Sentinel-Updater",
        ["Accept"] = "application/json"
    })
end

local function updateFiles(manifest, localVersion)
    local files = manifest.files or {}
    if #files == 0 then
        log("^1Update manifest contains no files.^7")
        return
    end

    log(("^3This installation is outdated: %s -> %s.^7"):format(localVersion, manifest.version))
    log("^3The update will be downloaded now and will become active on the next resource/server restart.^7")

    local index = 1
    local failed = false

    local function nextFile()
        local entry = files[index]
        index = index + 1

        if not entry then
            if failed then
                log("^1Update incomplete. The old version will remain active; the update will retry on the next start.^7")
                return
            end

            SaveResourceFile(RESOURCE_NAME, VERSION_FILE, tostring(manifest.version) .. "\n", -1)
            log(("^2Update %s is ready. Restart the resource/server to activate it.^7"):format(manifest.version))
            return
        end

        local path = type(entry) == "string" and entry or entry.path

        if path == "config.lua" then
            log("Skipping customer config.lua")
            nextFile()
            return
        end

        if type(path) ~= "string" or path == "" or path:find("%.%.", 1, true) then
            failed = true
            log(("^1Rejected invalid update path: %s^7"):format(tostring(path)))
            nextFile()
            return
        end

        request(FILE_BASE_URL .. path, function(status, body)
            if status ~= 200 or body == "" then
                failed = true
                log(("^1Failed to download %s (HTTP %s).^7"):format(path, tostring(status)))
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

    local localVersion = readLocalVersion()
    log(("Current version: %s"):format(localVersion))
    log("Checking official SIFO Sentinel repository for updates...")

    request(MANIFEST_URL, function(status, body)
        if status ~= 200 or body == "" then
            log(("^3Could not check for updates (HTTP %s). Continuing normally.^7"):format(tostring(status)))
            return
        end

        local ok, manifest = pcall(json.decode, body)
        if not ok or type(manifest) ~= "table" or type(manifest.version) ~= "string" then
            log("^1Update manifest is invalid. Continuing normally.^7")
            return
        end

        if not isNewer(manifest.version, localVersion) then
            log(("^2SIFO Sentinel is up to date (%s). Starting normally.^7"):format(localVersion))
            return
        end

        updateFiles(manifest, localVersion)
    end)
end)
