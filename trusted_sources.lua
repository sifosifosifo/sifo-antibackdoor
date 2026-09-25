-- SIFO Sentinel - Trusted Official Sources
-- Add official FiveM resources here.
--
-- repository = GitHub owner/repository
-- ref = branch, tag, or preferably a pinned commit SHA
-- resourceNames = local FiveM resource names that should use this source
--
-- The scanner compares local Git blob SHA-1 values against the selected
-- GitHub tree. A difference means MODIFIED; it is not automatically malware.

SIFO_TRUSTED_SOURCES = {
    {
        id = "qb_core",
        name = "QBCore",
        repository = "qbcore-fivem/qb-core",
        ref = "main",
        resourceNames = { "qb-core" },
        enabled = true
    },

    {
        id = "pma_voice",
        name = "pma-voice",
        repository = "AvarianKnight/pma-voice",
        ref = "master",
        resourceNames = { "pma-voice" },
        enabled = true
    },

    {
        id = "ox_lib",
        name = "ox_lib",
        repository = "overextended/ox_lib",
        ref = "main",
        resourceNames = { "ox_lib" },
        enabled = true
    },

    {
        id = "txadmin",
        name = "txAdmin",
        repository = "citizenfx/txAdmin",
        ref = "master",
        resourceNames = { "txAdmin", "txadmin" },
        enabled = true
    }
}
