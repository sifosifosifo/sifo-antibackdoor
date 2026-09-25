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
    }
}
