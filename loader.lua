local RESOURCE_NAME = GetCurrentResourceName()

local Config = {
    OutputFile = "sifo_forensic.log",

    ScanExtensions = {
        lua = true,
        js = true,
        json = true,
        cfg = true,
        txt = true,
        sql = true,
        html = true,
        css = true
    },

    CriticalStrings = {
        "JohnsUrUncle",
        "admins.json",
        "txData",
        "txAdmin",

        "cipher-panel",
        "cipher-panel.me",
        "ketamin.cc",
        "helperServer",
        "Enchanced_Tabs",

        "MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR"
    },

    -- عمليات يمكن استخدامها في Backdoors
    SuspiciousStrings = {
        "PerformHttpRequest",
        "PerformHttpRequestInternal",

        "SaveResourceFile",
        "LoadResourceFile",

        "ExecuteCommand",
        "execute",

        "os.execute",
        "io.popen",

        "loadstring",
        "load(",
        "assert(load",

        "RunString",
        "RunStringEx",

        "AddEventHandler",
        "RegisterNetEvent",
        "TriggerServerEvent",
        "TriggerClientEvent",

        "webhook",
        "discord.com/api/webhooks",

        "http://",
        "https://",

        "GetConvar",
        "GetConvarReplicated",

        "Citizen.InvokeNative"
    }
}

local findings = {}

local resourcesScanned = 0
local filesScanned = 0

local function lower(text)
    return string.lower(text or "")
end

local function extensionOf(path)
    local ext = path:match("%.([^%.]+)$")

    if not ext then
        return nil
    end

    return lower(ext)
end

local function addFinding(
    severity,
    resource,
    file,
    lineNumber,
    keyword,
    line
)
    findings[#findings + 1] = {
        severity = severity,
        resource = resource,
        file = file,
        line = lineNumber,
        keyword = keyword,
        code = line
    }
end

local function searchLine(
    resource,
    file,
    lineNumber,
    line
)
    local lowerLine = lower(line)

    for _, keyword in ipairs(Config.CriticalStrings) do
        if string.find(
            lowerLine,
            lower(keyword),
            1,
            true
        ) then

            addFinding(
                "CRITICAL",
                resource,
                file,
                lineNumber,
                keyword,
                line
            )
        end
    end

    for _, keyword in ipairs(Config.SuspiciousStrings) do
        if string.find(
            lowerLine,
            lower(keyword),
            1,
            true
        ) then

            addFinding(
                "SUSPICIOUS",
                resource,
                file,
                lineNumber,
                keyword,
                line
            )
        end
    end
end

local function scanFile(resource, file)
    local extension = extensionOf(file)

    if not extension then
        return
    end

    if not Config.ScanExtensions[extension] then
        return
    end

    local content = LoadResourceFile(
        resource,
        file
    )

    if not content then
        return
    end

    filesScanned = filesScanned + 1

    local lineNumber = 0

    for line in content:gmatch("[^\r\n]+") do
        lineNumber = lineNumber + 1

        searchLine(
            resource,
            file,
            lineNumber,
            line
        )
    end
end

local function scanResource(resource)
    resourcesScanned = resourcesScanned + 1

    local manifestFiles = {
        "fxmanifest.lua",
        "__resource.lua"
    }

    for _, manifest in ipairs(manifestFiles) do
        scanFile(resource, manifest)
    end

    local serverCount =
        GetNumResourceMetadata(
            resource,
            "server_script"
        ) or 0

    for i = 0, serverCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "server_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local clientCount =
        GetNumResourceMetadata(
            resource,
            "client_script"
        ) or 0

    for i = 0, clientCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "client_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local sharedCount =
        GetNumResourceMetadata(
            resource,
            "shared_script"
        ) or 0

    for i = 0, sharedCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "shared_script",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end

    local fileCount =
        GetNumResourceMetadata(
            resource,
            "file"
        ) or 0

    for i = 0, fileCount - 1 do
        local file =
            GetResourceMetadata(
                resource,
                "file",
                i
            )

        if file then
            scanFile(resource, file)
        end
    end
end

local function writeReport()
    local output = {}

    output[#output + 1] = "SIFO FORENSIC SCAN"
    output[#output + 1] = "TIME=" .. os.date("%Y-%m-%d %H:%M:%S")
    output[#output + 1] = "RESOURCES=" .. tostring(resourcesScanned)
    output[#output + 1] = "FILES=" .. tostring(filesScanned)
    output[#output + 1] = "FINDINGS=" .. tostring(#findings)
    output[#output + 1] = "----------------------------------------"

    for _, finding in ipairs(findings) do
        local code = tostring(finding.code or "")
            :gsub("\r", " ")
            :gsub("\n", " ")
            :gsub("|", "/")

        output[#output + 1] =
            finding.severity
            .. "|"
            .. finding.resource
            .. "|"
            .. finding.file
            .. "|LINE="
            .. tostring(finding.line)
            .. "|"
            .. finding.keyword
            .. "|"
            .. code
    end

    local content = table.concat(output, "\n")

    local success = SaveResourceFile(
        RESOURCE_NAME,
        Config.OutputFile,
        content,
        #content
    )

    print("")
    print("^5========== SIFO REPORT =========^7")

    print("^7Resource:^3 " .. RESOURCE_NAME .. "^7")
    print("^7File:^3 " .. Config.OutputFile .. "^7")
    print("^7Size:^3 " .. tostring(#content) .. " bytes^7")

    if success then
        print("^2[OK] Report saved successfully.^7")
        print(
            "^2[PATH] ^7resources/[...]/"
            .. RESOURCE_NAME
            .. "/"
            .. Config.OutputFile
        )
    else
        print("^1[ERROR] SaveResourceFile failed!^7")
    end

    print("^5================================^7")
    print("")
end

local function printSummary()

    print("")
    print("^5==============================================^7")
    print("^5        SIFO FORENSIC SECURITY SCANNER^7")
    print("^5==============================================^7")

    print("^7Resources: ^3" .. resourcesScanned .. "^7")
    print("^7Files:     ^3" .. filesScanned .. "^7")
    print("^7Findings:  ^1" .. #findings .. "^7")

    local critical = 0
    local suspicious = 0

    for _, finding in ipairs(findings) do
        if finding.severity == "CRITICAL" then
            critical = critical + 1
        else
            suspicious = suspicious + 1
        end
    end

    print("^1Critical:   " .. critical .. "^7")
    print("^3Suspicious: " .. suspicious .. "^7")

    print("^5----------------------------------------------^7")

    if critical > 0 then
        print("^1[!] CRITICAL INDICATORS FOUND^7")
    elseif suspicious > 0 then
        print("^3[!] Suspicious indicators found^7")
    else
        print("^2[OK] No configured indicators found^7")
    end

    print("^5----------------------------------------------^7")

    local displayed = {}

    for _, finding in ipairs(findings) do

        local key =
            finding.resource
            .. "/"
            .. finding.file
            .. ":"
            .. finding.keyword

        if not displayed[key] then

            displayed[key] = true

            if finding.severity == "CRITICAL" then

                print(
                    "^1[CRITICAL]^7 "
                    .. finding.resource
                    .. "/"
                    .. finding.file
                    .. " -> "
                    .. finding.keyword
                )

            else

                print(
                    "^3[SUSPICIOUS]^7 "
                    .. finding.resource
                    .. "/"
                    .. finding.file
                    .. " -> "
                    .. finding.keyword
                )
            end
        end
    end

    print("^5==============================================^7")

    print(
        "^7Report: ^3"
        .. RESOURCE_NAME
        .. "/"
        .. Config.OutputFile
        .. "^7"
    )

    print("^5==============================================^7")
    print("")
end

local function startScan()

    print("")
    print("^5[SIFO] Starting forensic scan...^7")

    local total =
        GetNumResources()

    for i = 0, total - 1 do

        local resource =
            GetResourceByFindIndex(i)

        if resource
            and resource ~= RESOURCE_NAME
        then

            scanResource(resource)

        end
    end

    writeReport()

    printSummary()
end

AddEventHandler(
    "onResourceStart",
    function(resource)

        if resource ~= RESOURCE_NAME then
            return
        end

        CreateThread(function()

            Wait(3000)

            startScan()

        end)
    end
)