-- SIFO Anti Backdoor
-- Main configuration file.
-- Keep webhook secrets in server.cfg ConVars when possible.

Config = {
    Discord = {
        Enabled = true,

        -- Optional inline webhooks.
        -- Recommended: leave empty and use server.cfg ConVars.
        AllWebhook = "",
        CriticalWebhook = "",

        -- server.cfg:
        -- set sifo_antibackdoor_all_webhook "YOUR_WEBHOOK"
        -- set sifo_antibackdoor_critical_webhook "YOUR_WEBHOOK"
        AllWebhookConvar = "sifo_antibackdoor_all_webhook",
        CriticalWebhookConvar = "sifo_antibackdoor_critical_webhook",

        -- Send a summary even when no threats are found.
        SendCleanSummary = true,

        -- Maximum findings included in one Discord embed.
        MaxFindingsPerMessage = 6,

        -- Resource score at/above this value is also sent to Critical.
        MinScoreForCritical = 80
    },

    Scanner = {
        -- Delay before the automatic startup scan.
        ScanDelay = 5000,

        -- Run a scan automatically when SIFO starts.
        ScanOnResourceStart = true,

        -- Do not scan SIFO Anti Backdoor itself.
        IgnoreOwnResource = true,

        -- Maximum characters shown for a code preview.
        MaxCodePreview = 700,

        -- Maximum findings kept in memory per scan.
        MaxFindingsStored = 5000,

        -- Obfuscation heuristics.
        LongLineLength = 1800,
        HugeStringLength = 900,
        EntropyMinLength = 300,
        EntropyThreshold = 4.6
    },

    LocalReport = {
        -- Writes sifo_forensic.log inside this resource.
        Enabled = false,
        OutputFile = "sifo_forensic.log"
    },

    -- Resources listed here are skipped completely.
    Allowlist = {
        Resources = {
            -- "qb-core",
            -- "ox_lib",
            -- "my-trusted-resource"
        },

        -- Ignore one specific indicator for one resource.
        Indicators = {
            -- { resource = "my-resource", indicator = "PerformHttpRequest" }
        }
    },

    -- File extensions scanned from resource metadata.
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
