function SIFO.startScan()
    if SIFO.ScanRunning then
        print("^3[SIFO] A scan is already running.^7")
        return
    end

    SIFO.ScanRunning = true
    SIFO.reset()

    print("^5[SIFO] Threat intelligence scan started...^7")
    SIFO.sendDiscordStart()

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

    SIFO.ScanRunning = false
end

RegisterCommand("sifo_scan", function(source)
    if source ~= 0 then return end
    SIFO.startScan()
end, false)

RegisterCommand("sifo_risk", function(source)
    if source ~= 0 then return end
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

    CreateThread(function()
        Wait(750)
        if GetResourceState(resource) == "started" then
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
