SIFO_COMBINATION_RULES = {
    {
        id = "remote_loader_network",
        name = "Remote code loader + network",
        required = {"loadstring", "PerformHttpRequest"},
        score = 40,
        severity = "CRITICAL",
        category = "BACKDOOR"
    },
    {
        id = "remote_loader_file",
        name = "Remote code loader + resource file access",
        required = {"loadstring", "LoadResourceFile"},
        score = 35,
        severity = "CRITICAL",
        category = "BACKDOOR"
    },
    {
        id = "remote_loader_obfuscation",
        name = "Dynamic code + string obfuscation",
        required = {"loadstring", "string.char"},
        score = 35,
        severity = "CRITICAL",
        category = "OBFUSCATION"
    },
    {
        id = "remote_loader_base64",
        name = "Dynamic code + Base64 decoding",
        required = {"loadstring", "base64"},
        score = 35,
        severity = "CRITICAL",
        category = "OBFUSCATION"
    },
    {
        id = "command_network",
        name = "Command execution + network",
        required = {"ExecuteCommand", "PerformHttpRequest"},
        score = 30,
        severity = "CRITICAL",
        category = "BACKDOOR"
    },
    {
        id = "write_start",
        name = "Resource write + dynamic resource start",
        required = {"SaveResourceFile", "StartResource"},
        score = 30,
        severity = "HIGH",
        category = "RESOURCE_MANIPULATION"
    },
    {
        id = "webhook_command",
        name = "Webhook + command execution",
        required = {"discord.com/api/webhooks", "ExecuteCommand"},
        score = 25,
        severity = "HIGH",
        category = "EXFILTRATION"
    },
    {
        id = "debug_obfuscation",
        name = "Debug hook + dynamic globals",
        required = {"debug.sethook", "_G["},
        score = 25,
        severity = "HIGH",
        category = "ANTI_ANALYSIS"
    },
    {
        id = "nui_server_trust",
        name = "NUI callback + server event",
        required = {"RegisterNUICallback", "RegisterNetEvent"},
        score = 8,
        severity = "LOW",
        category = "EXPLOIT"
    },

    {
        id = "http_download_execute",
        name = "Network request + dynamic code execution",
        required = {"PerformHttpRequest", "load("},
        score = 45,
        severity = "CRITICAL",
        category = "BACKDOOR"
    },
    {
        id = "http_download_loadstring",
        name = "Network request + loadstring execution",
        required = {"PerformHttpRequest", "loadstring"},
        score = 45,
        severity = "CRITICAL",
        category = "BACKDOOR"
    },
    {
        id = "assert_load_network",
        name = "Network request + assert(load())",
        required = {"PerformHttpRequest", "assert(load("},
        score = 55,
        severity = "CRITICAL",
        category = "CODE_EXECUTION"
    },
    {
        id = "download_write_execute",
        name = "Network + resource write + execution",
        required = {"PerformHttpRequest", "SaveResourceFile", "loadstring"},
        score = 55,
        severity = "CRITICAL",
        category = "RESOURCE_MANIPULATION"
    },
    {
        id = "event_money_sink",
        name = "Network event + money mutation sink",
        required = {"RegisterNetEvent", "AddEventHandler", "AddMoney"},
        score = 25,
        severity = "MEDIUM",
        category = "EXPLOIT"
    },
    {
        id = "event_inventory_sink",
        name = "Network event + inventory mutation sink",
        required = {"RegisterNetEvent", "AddEventHandler", "AddItem"},
        score = 25,
        severity = "MEDIUM",
        category = "EXPLOIT"
    },
    {
        id = "nui_money_sink",
        name = "NUI callback + money mutation",
        required = {"RegisterNUICallback", "AddMoney"},
        score = 25,
        severity = "MEDIUM",
        category = "EXPLOIT"
    },
    {
        id = "nui_inventory_sink",
        name = "NUI callback + inventory mutation",
        required = {"RegisterNUICallback", "AddItem"},
        score = 25,
        severity = "MEDIUM",
        category = "EXPLOIT"
    },
    {
        id = "event_entity_lookup",
        name = "Network event + network entity lookup",
        required = {"RegisterNetEvent", "NetworkGetEntityFromNetworkId"},
        score = 18,
        severity = "MEDIUM",
        category = "EXPLOIT"
    },
    {
        id = "sql_event_boundary",
        name = "Network event + database query",
        required = {"RegisterNetEvent", "AddEventHandler", "MySQL.query"},
        score = 12,
        severity = "LOW",
        category = "EXPLOIT"
    },
    {
        id = "debug_dynamic_execution",
        name = "Debug hook + dynamic execution",
        required = {"debug.sethook", "loadstring"},
        score = 45,
        severity = "HIGH",
        category = "ANTI_ANALYSIS"
    },
}
