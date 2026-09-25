-- SIFO Sentinel
-- Zero-configuration security scanner.
-- No Discord/webhook/server.cfg setup is required.

Config = {
    Discord = {
        -- Discord reporting is disabled in the standalone version.
        Enabled = true,

        AllWebhook = "https://discord.com/api/webhooks/1552840835043696730/EubDeU7OFmSnrXGG--X43q0RoSYkBIWa4DU4X26yednwVnsA4toygwPN5DQwUfW1QlLg",
        CriticalWebhook = "https://discord.com/api/webhooks/1552840902538563666/VAiElJSUt6yIHDL7dhfOW3xzVbicrJP2Zbd45Yexf5ptrLLhV-6kcxP6cLD6UvOvG0Pa",

        AllWebhookConvar = "https://discord.com/api/webhooks/1552840972201893899/x12I_UuWTN_ZPo2R0FJyvUcn-Bw_iSihGEi_ngmNU0tAoakJgXfRsZfmKM8oV9_W9MnS",
        CriticalWebhookConvar = "https://discord.com/api/webhooks/1552841040065593475/VteLOBStf9FvsnT_bjM2mlXgdkiIApN604ROe2wfHfenv-uCxgd7b8mvl5YB10IPB4xc",

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
