function SIFO.startScan()
    if SIFO.ScanRunning then
        print("^3[SIFO] A scan is already running.^7")
        return
    end

    SIFO.ScanRunning = true
    SIFO.reset()

    print("^5[SIFO] Threat intelligence scan started...^7")
    SIFO.sendDiscordStart()

    local ok, err = xpcall(function()
        SIFO.scanAllResources()

        if type(SIFO.waitForTrustedVerification) == "function" then
            SIFO.waitForTrustedVerification(10000)
        else
            print("^3[SIFO] Trusted-source verification module is not loaded; continuing without official-source verification.^7")
            print("^3[SIFO] Ensure server/trusted_scanner.lua is present and restart the resource.^7")
        end

        SIFO.writeReport()
        SIFO.sendDiscordReport()
        SIFO.printSummary()
    end, debug.traceback)

    SIFO.ScanRunning = false

    if not ok then
        print("^1[SIFO] Scan aborted by an internal error:^7")
        print("^1" .. tostring(err) .. "^7")
        print("^3[SIFO] Scan state was reset. You can run /sifo_scan again after fixing the error.^7")
    end
end

RegisterCommand("sifo_scan", function(source)
    if source ~= 0 then return end
    SIFO.startScan()
end, false)

RegisterCommand("sifo_risk", function(source)
    if source ~= 0 then return end
    if type(SIFO.printResourceRisk) ~= "function" then
        print("^1[SIFO] Resource risk reporter is not loaded.^7")
        print("^3[SIFO] Check that server/reporter.lua is present in fxmanifest.lua and restart sifo-antibackdoor.^7")
        return
    end
    SIFO.printResourceRisk()
end, false)

AddEventHandler("onResourceStart", function(resource)
    if resource == SIFO.ResourceName then
        if not Config.Scanner.ScanOnResourceStart then return end

        CreateThread(function()
            Wait(Config.Scanner.ScanDelay)
            SIFO.startScan()
        end)
        return
    end

    if SIFO.ScanRunning then return end

    CreateThread(function()
        Wait(750)
        if not SIFO.ScanRunning and GetResourceState(resource) == "started" then
            SIFO.scanResource(resource)
        end
    end)
end)

if not SIFO_THREATS then
    print("^1[SIFO] Threat database failed to load.^7")
end

if not SIFO_COMBINATION_RULES then
    print("^1[SIFO] Combination rules failed to load.^7")
end

if not SIFO_TRUSTED_SOURCES then
    print("^1[SIFO] Trusted-source database failed to load.^7")
end

if type(SIFO.verifyTrustedResource) ~= "function" then
    print("^3[SIFO] Trusted-source verifier is not loaded. Check that server/trusted_scanner.lua is included in fxmanifest.lua.^7")
end
