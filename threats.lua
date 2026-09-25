SIFO_THREATS = {
    {
        id = "TXADMIN_MONITOR_EVENT_RCE",
        category = "CODE_EXECUTION",
        severity = "CRITICAL",
        score = 100,
        match = "helpEmptyCode",
        reason = "Known txAdmin monitor Event-to-Code-Execution/RCE indicator"
    },
    {
        id = "known_cipher_panel",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 95,
        match = "cipher-panel",
        reason = "Known malicious/backdoor indicator"
    },
    {
        id = "cipher_panel_domain",
        category = "C2",
        severity = "CRITICAL",
        score = 100,
        match = "cipher-panel.me",
        reason = "Known malicious infrastructure indicator"
    },
    {
        id = "ketamin_domain",
        category = "C2",
        severity = "CRITICAL",
        score = 100,
        match = "ketamin.cc",
        reason = "Known malicious infrastructure indicator"
    },
    {
        id = "known_c2_domain_1",
        category = "C2",
        severity = "CRITICAL",
        score = 100,
        match = "eszjqvpjhiou.mom",
        reason = "Known malicious infrastructure indicator"
    },
    {
        id = "TXADMIN_ADMIN_COMPROMISE_INDICATOR",
        category = "TXADMIN_COMPROMISE",
        severity = "CRITICAL",
        score = 100,
        match = "JohnsUrUncle",
        reason = "Known txAdmin/admin compromise indicator; presence strongly suggests unauthorized admin/backdoor artifacts and requires immediate investigation of txAdmin, monitor, and installed resources"
    },
    {
        id = "known_backdoor_marker_2",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "pqzskjptss",
        reason = "Known backdoor marker"
    },
    {
        id = "known_backdoor_state_1",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "GlobalState.miauss",
        reason = "Known malicious state marker"
    },
    {
        id = "known_backdoor_state_2",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "GlobalState.ggWP",
        reason = "Known malicious state marker"
    },
    {
        id = "known_permission_marker",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "all_permissions",
        reason = "Known malicious permission marker"
    },
    {
        id = "resource_exclude_list",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "RESOURCE_EXCLUDE_LIST",
        reason = "Known malicious exclusion marker"
    },
    {
        id = "helper_server",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 95,
        match = "helperServer",
        reason = "Known helper/backdoor marker"
    },
    {
        id = "enhanced_tabs",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 95,
        match = "Enchanced_Tabs",
        reason = "Known backdoor marker"
    },
    {
        id = "long_known_marker",
        category = "KNOWN_BACKDOOR",
        severity = "CRITICAL",
        score = 100,
        match = "MpWxwQeLMRJaDFLKmxVIFNeVfzVKaTBiVRvjBoePYciqfpJzxjNPIXedbOtvIbpDxqdoJR",
        reason = "Known malicious payload marker"
    },

    {
        id = "remote_code_loadstring",
        category = "CODE_EXECUTION",
        severity = "MEDIUM",
        score = 25,
        match = "loadstring",
        reason = "Dynamic Lua code execution"
    },
    {
        id = "remote_code_load",
        category = "CODE_EXECUTION",
        severity = "MEDIUM",
        score = 20,
        match = "load(",
        reason = "Dynamic Lua code loading"
    },
    {
        id = "remote_code_assert_load",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 35,
        match = "assert(load",
        reason = "Dynamic code execution chain"
    },
    {
        id = "remote_code_runstring",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 55,
        match = "RunString",
        reason = "Runtime code execution API"
    },
    {
        id = "shell_execution",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 65,
        match = "os.execute",
        reason = "Operating-system command execution"
    },
    {
        id = "process_pipe",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 65,
        match = "io.popen",
        reason = "Process execution through pipe"
    },
    {
        id = "native_dynamic_execution",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 50,
        match = "Citizen.InvokeNative",
        reason = "Dynamic native invocation; context required"
    },

    {
        id = "outbound_http",
        category = "NETWORK",
        severity = "MEDIUM",
        score = 18,
        match = "PerformHttpRequest",
        reason = "Outbound HTTP request; common legitimate API but risky in combinations"
    },
    {
        id = "internal_http",
        category = "NETWORK",
        severity = "MEDIUM",
        score = 20,
        match = "PerformHttpRequestInternal",
        reason = "Internal HTTP request API"
    },
    {
        id = "discord_webhook",
        category = "EXFILTRATION",
        severity = "MEDIUM",
        score = 25,
        match = "discord.com/api/webhooks",
        reason = "Discord webhook endpoint; inspect data flow"
    },
    {
        id = "http_url",
        category = "NETWORK",
        severity = "LOW",
        score = 8,
        match = "http://",
        reason = "Plain HTTP endpoint"
    },
    {
        id = "https_url",
        category = "NETWORK",
        severity = "LOW",
        score = 3,
        match = "https://",
        reason = "HTTPS endpoint; informational"
    },

    {
        id = "resource_write",
        category = "RESOURCE_MANIPULATION",
        severity = "MEDIUM",
        score = 15,
        match = "SaveResourceFile",
        reason = "Can write files into resources"
    },
    {
        id = "resource_read",
        category = "RESOURCE_ACCESS",
        severity = "MEDIUM",
        score = 18,
        match = "LoadResourceFile",
        reason = "Reads files from resources; inspect combinations"
    },
    {
        id = "resource_start",
        category = "RESOURCE_MANIPULATION",
        severity = "MEDIUM",
        score = 15,
        match = "StartResource",
        reason = "Can start resources dynamically"
    },
    {
        id = "resource_stop",
        category = "RESOURCE_MANIPULATION",
        severity = "MEDIUM",
        score = 15,
        match = "StopResource",
        reason = "Can stop resources dynamically"
    },

    {
        id = "command_execution",
        category = "COMMAND_ABUSE",
        severity = "LOW",
        score = 10,
        match = "ExecuteCommand",
        reason = "Server command execution; context required"
    },
    {
        id = "convar_access",
        category = "SECRETS",
        severity = "MEDIUM",
        score = 20,
        match = "GetConvar",
        reason = "Reads server convars; inspect sensitive values"
    },
    {
        id = "replicated_convar_access",
        category = "SECRETS",
        severity = "MEDIUM",
        score = 25,
        match = "GetConvarReplicated",
        reason = "Reads replicated convars"
    },

    {
        id = "debug_hook",
        category = "ANTI_ANALYSIS",
        severity = "HIGH",
        score = 40,
        match = "debug.sethook",
        reason = "Debug hook can be used for control-flow manipulation"
    },
    {
        id = "debug_info",
        category = "ANTI_ANALYSIS",
        severity = "MEDIUM",
        score = 20,
        match = "debug.getinfo",
        reason = "Debug introspection; context required"
    },
    {
        id = "dynamic_global",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 20,
        match = "_G[",
        reason = "Dynamic global lookup"
    },
    {
        id = "dynamic_environment",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 20,
        match = "_ENV[",
        reason = "Dynamic environment lookup"
    },
    {
        id = "string_char",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 25,
        match = "string.char",
        reason = "Character-based string construction"
    },
    {
        id = "string_byte",
        category = "OBFUSCATION",
        severity = "LOW",
        score = 10,
        match = "string.byte",
        reason = "Byte-level string manipulation"
    },
    {
        id = "base64",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 20,
        match = "base64",
        reason = "Base64 decoding/encoding marker"
    },
    {
        id = "decode64",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 25,
        match = "decode64",
        reason = "Base64 decoding marker"
    },
    {
        id = "from_base64",
        category = "OBFUSCATION",
        severity = "MEDIUM",
        score = 25,
        match = "fromBase64",
        reason = "Base64 decoding marker"
    },
    {
        id = "dofile",
        category = "CODE_EXECUTION",
        severity = "MEDIUM",
        score = 30,
        match = "dofile(",
        reason = "Loads and executes another Lua file"
    },
    {
        id = "package_loadlib",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 55,
        match = "package.loadlib",
        reason = "Loads native libraries dynamically"
    },

    {
        id = "event_register",
        category = "EVENT_SECURITY",
        severity = "LOW",
        score = 4,
        match = "RegisterNetEvent",
        reason = "Network event registration; normal API, inspect handler validation"
    },
    {
        id = "server_event_trigger",
        category = "EVENT_SECURITY",
        severity = "LOW",
        score = 4,
        match = "TriggerServerEvent",
        reason = "Client-to-server event trigger; normal API, inspect trust boundaries"
    },
    {
        id = "client_event_trigger",
        category = "EVENT_SECURITY",
        severity = "LOW",
        score = 4,
        match = "TriggerClientEvent",
        reason = "Server-to-client event trigger; inspect authorization"
    },
    {
        id = "event_handler",
        category = "EVENT_SECURITY",
        severity = "LOW",
        score = 2,
        match = "AddEventHandler",
        reason = "Event handler registration; informational"
    },

    {
        id = "permissions_marker",
        category = "AUTHORIZATION",
        severity = "HIGH",
        score = 50,
        match = "all_permissions",
        reason = "Permission bypass/backdoor marker"
    },
    {
        id = "admin_file",
        category = "AUTHORIZATION",
        severity = "MEDIUM",
        score = 20,
        match = "admins.json",
        reason = "Admin permission file access"
    },
    {
        id = "txdata",
        category = "AUTHORIZATION",
        severity = "MEDIUM",
        score = 15,
        match = "txData",
        reason = "txAdmin data access; context required"
    },

    {
        id = "sql_raw_concat",
        category = "EXPLOIT",
        severity = "MEDIUM",
        score = 25,
        match = "SELECT ",
        reason = "SQL statement found; inspect for unsafe string concatenation"
    },
    {
        id = "sql_update",
        category = "EXPLOIT",
        severity = "LOW",
        score = 8,
        match = "UPDATE ",
        reason = "SQL update statement; informational"
    },
    {
        id = "nui_callback",
        category = "EXPLOIT",
        severity = "LOW",
        score = 5,
        match = "RegisterNUICallback",
        reason = "NUI callback; validate all client-supplied values"
    },
    {
        id = "state_bag",
        category = "EXPLOIT",
        severity = "LOW",
        score = 5,
        match = "AddStateBagChangeHandler",
        reason = "State bag handler; validate source/entity ownership"
    },

    {
        id = "dynamic_code_assert_load",
        category = "CODE_EXECUTION",
        severity = "HIGH",
        score = 60,
        match = "assert(load(",
        reason = "Dynamic code execution chain commonly used by remote loaders"
    },
    {
        id = "environment_rebinding",
        category = "ANTI_ANALYSIS",
        severity = "MEDIUM",
        score = 25,
        match = "setfenv",
        reason = "Environment rebinding can alter runtime execution context"
    },
    {
        id = "client_server_trust_money",
        category = "EXPLOIT",
        severity = "MEDIUM",
        score = 30,
        match = "AddMoney",
        reason = "Money mutation sink; server-side event inputs must be validated"
    },
    {
        id = "inventory_mutation_sink",
        category = "EXPLOIT",
        severity = "MEDIUM",
        score = 30,
        match = "AddItem",
        reason = "Inventory mutation sink; server-side event inputs must be validated"
    },
    {
        id = "entity_network_control",
        category = "EXPLOIT",
        severity = "LOW",
        score = 12,
        match = "NetworkGetEntityFromNetworkId",
        reason = "Network entity lookup; validate ownership and entity type"
    },
    {
        id = "raw_sql_execute",
        category = "EXPLOIT",
        severity = "LOW",
        score = 10,
        match = "MySQL.query",
        reason = "Database query sink; inspect interpolation and parameterization"
    },
}
