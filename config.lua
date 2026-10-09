-- SIFO Sentinel
-- All customer configuration lives in this file.
-- No server.cfg / convar setup is required.

Config = {
    -- Public automatic updater. No customer token or private repository is required.
    GitHub = {
        Enabled = true,
        -- Check for new versions every N minutes (minimum 5).
        CheckIntervalMinutes = 60,
        -- Restart only this resource after a complete update so changes become active.
        -- Set false if you prefer to restart the resource manually.
        AutoRestart = true
    },

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
