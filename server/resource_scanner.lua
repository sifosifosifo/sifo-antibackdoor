function SIFO.scanFile(resource, file)
    local extension = SIFO.extensionOf(file)
    if not extension or not Config.ScanExtensions[extension] then return end
    if string.find(file, "*", 1, true) then return end

    local content = LoadResourceFile(resource, file)
    if not content then return end

    SIFO.FilesScanned = SIFO.FilesScanned + 1
    SIFO.scanThreatDatabase(resource, file, content)
    SIFO.scanTxAdminEventRCE(resource, file, content)
    SIFO.scanBehavioralSecurity(resource, file, content)
    SIFO.scanCombinations(resource, file, content)
    SIFO.scanObfuscation(resource, file, content)
end

function SIFO.scanMetadataFiles(resource, metadataName)
    local count = GetNumResourceMetadata(resource, metadataName) or 0
    for i = 0, count - 1 do
        local file = GetResourceMetadata(resource, metadataName, i)
        if file and file ~= "" then SIFO.scanFile(resource, file) end
    end
end

function SIFO.scanResource(resource)
    if not resource or resource == "" then return end

    if Config.Scanner.IgnoreOwnResource and resource == SIFO.ResourceName then
        return
    end

    SIFO.ResourcesScanned = SIFO.ResourcesScanned + 1

    if SIFO.isResourceAllowed(resource) then
        SIFO.AllowedResources = SIFO.AllowedResources + 1
        return
    end

    SIFO.scanFile(resource, "fxmanifest.lua")
    SIFO.scanFile(resource, "__resource.lua")
    SIFO.scanMetadataFiles(resource, "server_script")
    SIFO.scanMetadataFiles(resource, "client_script")
    SIFO.scanMetadataFiles(resource, "shared_script")
    SIFO.scanMetadataFiles(resource, "file")
end

function SIFO.scanAllResources()
    local total = GetNumResources()
    for i = 0, total - 1 do
        local resource = GetResourceByFindIndex(i)
        if resource then SIFO.scanResource(resource) end
    end
end
