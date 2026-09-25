function SIFO.scanCombinations(resource, file, content)
    local whole = SIFO.lower(content)

    for _, rule in ipairs(SIFO_COMBINATION_RULES or {}) do
        local matched = true

        for _, required in ipairs(rule.required) do
            if not string.find(whole, SIFO.lower(required), 1, true) then
                matched = false
                break
            end
        end

        if matched then
            SIFO.addFinding({
                id = rule.id,
                resource = resource,
                file = file,
                line = 0,
                indicator = table.concat(rule.required, " + "),
                category = rule.category,
                severity = rule.severity,
                score = rule.score,
                reason = rule.name,
                code = "Combination rule matched"
            })
        end
    end
end
