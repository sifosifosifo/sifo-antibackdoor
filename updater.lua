-- SIFO Anti Backdoor - automatic updater
-- Checks the official GitHub repository on every resource start.
-- Updates are written to disk while the current process keeps running.
-- The new files are loaded on the next resource/server start.

local UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/update_manifest.json"
local RESOURCE_NAME = GetCurrentResourceName()
local LOCAL_VERSION_FILE = "version.txt"

local function request(url, callback)
    PerformHttpRequest(url, function(status, body)
        callback(status, body or "")
    end, "GET", "", {
        ["User-Agent"] = "SIFO-AntiBackdoor-Updater",
        ["Accept"] = "application/json, text/plain, */*"
    })
end

local function readLocalVersion()
    local value = LoadResourceFile(RESOURCE_NAME, LOCAL_VERSION_FILE)
    value = tostring(value or ""):gsub("%s+", "")
    if value == "" then
        return "0.0.0"
    end
    return value
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
    print(("^5[SIFO Updater]^7 %s"):format(message))
end

local function updateFiles(manifest, localVersion)
    local files = manifest.files or {}
    if #files == 0 then
        log("^1Update manifest contains no files.^7")
        return
    end

    log(("Update found: %s -> %s"):format(localVersion, manifest.version))
    log("Downloading update files. Current code will remain active until the next start.")

    local downloaded = {}
    local index = 1
    local failed = false

    local function nextFile()
        local entry = files[index]
        index = index + 1

        if not entry then
            if failed then
                log("^1Update was incomplete. The old version marker was kept; it will retry on the next start.^7")
                return
            end

            SaveResourceFile(RESOURCE_NAME, LOCAL_VERSION_FILE, tostring(manifest.version) .. "\\n", -1)
            log(("^2Update %s downloaded successfully. Restart the resource/server to load it.^7"):format(manifest.version))
            return
        end

        local path = entry.path
        if type(path) ~= "string" or path == "" or path:find("%.%.", 1, true) then
            failed = true
            log(("^1Rejected invalid update path: %s^7"):format(tostring(path)))
            nextFile()
            return
        end

        local url = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/" .. path
        request(url, function(status, body)
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
            else
                downloaded[#downloaded + 1] = path
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
    log("Checking GitHub for updates...")

    request(UPDATE_MANIFEST_URL, function(status, body)
        if status ~= 200 or body == "" then
            log(("^3Could not check GitHub for updates (HTTP %s). Continuing normally.^7"):format(tostring(status)))
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
