fx_version "adamant"

game "gta5"

server_scripts {
    -- Updater runs first so the next start loads the newest files.
    "updater.lua",

    "config.lua",
    "threats.lua",
    "rules.lua",

    "server/main.lua",
    "server/threat_scanner.lua",
    "server/behavior_scanner.lua",
    "server/rules_scanner.lua",
    "server/resource_scanner.lua",
    "server/reporter.lua",
    "server/commands.lua"
}
