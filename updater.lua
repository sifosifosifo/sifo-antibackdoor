-- SIFO Sentinel - automatic updater
-- Downloads every file before replacing anything, preserves config.lua, then restarts
-- only this resource (never the whole FiveM server) when a complete update succeeds.

local RESOURCE_NAME = GetCurrentResourceName()
local VERSION_FILE = "version.txt"
local MANIFEST_URL = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/update_manifest.json"
local FILE_BASE_URL = "https://raw.githubusercontent.com/sifosifosifo/sifo-antibackdoor/main/"
local CHECK_INTERVAL_MS = math.max(5, tonumber(Config.GitHub and Config.GitHub.CheckIntervalMinutes) or 60) * 60 * 1000

local checkInProgress = false
local updateInProgress = false

local function log(message)
    print(("[SIFO Updater] %s"):format(message))
end

local function readLocalVersion()
    local value = LoadResourceFile(RESOURCE_NAME, VERSION_FILE)
    value = tostring(value or ""):gsub("%s+", "")
    return value ~= "" and value or "0.0.0"
end

local function versionParts(version)
    local a, b, c = tostring(version or ""):match("^(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return tonumber(a), tonumber(b), tonumber(c)
end

local function isNewer(remote, localVersion)
    local ra, rb, rc = versionParts(remote)
    local la, lb, lc = versionParts(localVersion)
    if not ra or not la then return false end
    if ra ~= la then return ra > la end
    if rb ~= lb then return rb > lb end
    return rc > lc
end

local function isSafeRelativePath(path)
    if type(path) ~= "string" or path == "" then return false end
    if path:sub(1, 1) == "/" or path:find("\\", 1, true) then return false end
    if path:find("..", 1, true) or path:find("//", 1, true) then return false end
    if not path:match("^[%w_./%-]+$") or path:sub(-1) == "/" then return false end

    for segment in path:gmatch("[^/]+") do
        if segment == "." or segment == ".." then return false end
    end

    -- These files are handled separately or contain customer-specific settings.
    if path == "config.lua" or path == VERSION_FILE or path == "update_manifest.json" then
        return false
    end

    return true
end

local function request(url, callback)
    PerformHttpRequest(url, function(status, body)
        callback(tonumber(status) or 0, body or "")
    end, "GET", "", {
        ["User-Agent"] = "SIFO-Sentinel-Updater",
        ["Accept"] = "application/json"
    })
end

local function restartResourceWhenSafe()
    CreateThread(function()
        -- Do not interrupt a scan that is currently in progress.
        while SIFO and SIFO.ScanRunning do Wait(1000) end
        Wait(1500)
        log("Restarting only resource '" .. RESOURCE_NAME .. "' to activate the update.")
        ExecuteCommand("restart " .. RESOURCE_NAME)
    end)
end

local function updateFiles(manifest, localVersion)
    if updateInProgress then return end
    if type(manifest.files) ~= "table" or #manifest.files == 0 then
        log("^1Update manifest contains no files.^7")
        return
    end

    updateInProgress = true
    log(("^3Update available: installed %s, latest %s.^7"):format(localVersion, manifest.version))
    log("^3Downloading and validating all update files before applying any changes...^7")

    local files = {}
    local seen = {}
    for _, entry in ipairs(manifest.files) do
        local path = type(entry) == "string" and entry or (type(entry) == "table" and entry.path)
        if not isSafeRelativePath(path) then
            log(("^1Rejected unsafe or unsupported update path: %s^7"):format(tostring(path)))
            updateInProgress = false
            return
        end
        if seen[path] then
            log(("^1Duplicate path in update manifest: %s^7"):format(path))
            updateInProgress = false
            return
        end
        seen[path] = true
        files[#files + 1] = path
    end

    local downloaded = {}
    local index = 1

    local function downloadNext()
        local path = files[index]
        if not path then
            -- All downloads succeeded. Back up current files before writing any.
            local backups = {}
            for _, filePath in ipairs(files) do
                backups[filePath] = LoadResourceFile(RESOURCE_NAME, filePath)
            end

            local written = {}
            for _, filePath in ipairs(files) do
                local ok = SaveResourceFile(RESOURCE_NAME, filePath, downloaded[filePath], -1)
                if not ok then
                    log(("^1Could not save %s. Attempting to restore previously written files.^7"):format(filePath))
                    for i = #written, 1, -1 do
                        local priorPath = written[i]
                        if backups[priorPath] ~= nil then
                            local restored = SaveResourceFile(RESOURCE_NAME, priorPath, backups[priorPath], -1)
                            if not restored then
                                log(("^1WARNING: rollback failed for %s; inspect this file manually.^7"):format(priorPath))
                            end
                        else
                            log(("^1WARNING: no backup was available for %s; inspect this file manually.^7"):format(priorPath))
                        end
                    end
                    updateInProgress = false
                    log("^1Update was not completed. No version bump was recorded; it will be retried later.^7")
                    return
                end
                written[#written + 1] = filePath
            end

            local versionSaved = SaveResourceFile(RESOURCE_NAME, VERSION_FILE, manifest.version .. "\n", -1)
            if not versionSaved then
                log("^1Could not save version.txt; attempting rollback of updated files.^7")
                for i = #written, 1, -1 do
                    local priorPath = written[i]
                    if backups[priorPath] ~= nil then
                        local restored = SaveResourceFile(RESOURCE_NAME, priorPath, backups[priorPath], -1)
                        if not restored then
                            log(("^1WARNING: rollback failed for %s; inspect this file manually.^7"):format(priorPath))
                        end
                    end
                end
                updateInProgress = false
                return
            end

            log(("^2Update %s downloaded and applied successfully. Customer config.lua was preserved.^7"):format(manifest.version))
            updateInProgress = false
            if not (Config.GitHub and Config.GitHub.AutoRestart == false) then
                log("^3The resource will restart automatically to activate the new files; the FiveM server will not restart.^7")
                restartResourceWhenSafe()
            else
                log("^3Automatic resource restart is disabled. Run restart " .. RESOURCE_NAME .. " to activate the update.^7")
            end
            return
        end

        index = index + 1
        request(FILE_BASE_URL .. path, function(status, body)
            if status ~= 200 or body == "" then
                log(("^1Update download failed for %s (HTTP %s). No files have been replaced.^7"):format(path, tostring(status)))
                updateInProgress = false
                return
            end
            downloaded[path] = body
            downloadNext()
        end)
    end

    downloadNext()
end

local function checkForUpdates()
    if Config.GitHub and Config.GitHub.Enabled == false then
        log("Automatic update checks are disabled in config.lua.")
        return
    end
    if checkInProgress or updateInProgress then return end
    checkInProgress = true

    local localVersion = readLocalVersion()
    log(("Current version: %s"):format(localVersion))
    log("Checking the official SIFO Sentinel repository for updates...")

    request(MANIFEST_URL, function(status, body)
        checkInProgress = false
        if status ~= 200 or body == "" then
            log(("^3Could not check for updates (HTTP %s). Continuing normally; will retry later.^7"):format(tostring(status)))
            return
        end

        local ok, manifest = pcall(json.decode, body)
        if not ok or type(manifest) ~= "table" or type(manifest.version) ~= "string"
            or not versionParts(manifest.version) then
            log("^1Update manifest is invalid or has an unsupported version. Continuing normally.^7")
            return
        end

        if not isNewer(manifest.version, localVersion) then
            log(("^2SIFO Sentinel is up to date (%s)."):format(localVersion))
            return
        end

        updateFiles(manifest, localVersion)
    end)
end

CreateThread(function()
    Wait(1500)
    checkForUpdates()

    while true do
        Wait(CHECK_INTERVAL_MS)
        checkForUpdates()
    end
end)
