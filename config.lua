-- SIFO Sentinel
-- All customer configuration lives in this file.
-- No server.cfg / convar setup is required.

Config = {
    Discord = {
        Enabled = true,

        -- Put your Discord webhook URLs here.
        AllWebhook = "",
        CriticalWebhook = "",


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
