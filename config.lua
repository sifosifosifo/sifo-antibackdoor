-- SIFO Sentinel
-- All customer configuration lives in this file.
-- No server.cfg / convar setup is required.

Config = {
    GitHub = {
        Enabled = true,
        Token = "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"
    },

    Discord = {
        Enabled = true,

        -- Put your Discord webhook URLs here.
        AllWebhook = "https://discord.com/api/webhooks/1552840835043696730/EubDeU7OFmSnrXGG--X43q0RoSYkBIWa4DU4X26yednwVnsA4toygwPN5DQwUfW1QlLg",
        CriticalWebhook = "https://discord.com/api/webhooks/1552840902538563666/VAiElJSUt6yIHDL7dhfOW3xzVbicrJP2Zbd45Yexf5ptrLLhV-6kcxP6cLD6UvOvG0Pa",


        SendCleanSummary = false,
        MaxFindingsPerMessage = 6,
        MinScoreForCritical = 80
    },

    Scanner = {
        ScanDelay = 5000,
        ScanOnResourceStart = true,
        IgnoreOwnResource = true,
        MaxCodePreview = 700,
        MaxFindingsStored = 5000,

        LongLineLength = 1800,
        HugeStringLength = 900,
        EntropyMinLength = 300,
        EntropyThreshold = 4.6,

        -- Yield during large scans so the FiveM server thread stays responsive.
        YieldEveryFiles = 5,
        YieldDelay = 0
    },

    LocalReport = {
        Enabled = false,
        OutputFile = "sifo_forensic.log"
    },

    Allowlist = {
        Resources = {},
        Indicators = {}
    },

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
}
