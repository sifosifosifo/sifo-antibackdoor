-- SIFO Sentinel
-- Zero-configuration security scanner.
-- No Discord/webhook/server.cfg setup is required.

Config = {
    Discord = {
        -- Discord reporting is disabled in the standalone version.
        Enabled = true,

        AllWebhook = "",
        CriticalWebhook = "",

        AllWebhookConvar = "",
        CriticalWebhookConvar = "",

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
        EntropyThreshold = 4.6
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
