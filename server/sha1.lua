-- Minimal SHA-1 implementation for Git blob verification.
-- Git blob hash = SHA1("blob " .. #content .. "\\0" .. content)

local function rol(value, bits)
    return ((value << bits) | (value >> (32 - bits))) & 0xffffffff
end

local function add32(a, b)
    return (a + b) & 0xffffffff
end

local function sha1(data)
    local bytes = { data:byte(1, #data) }
    local bitLen = #bytes * 8
    bytes[#bytes + 1] = 0x80

    while (#bytes % 64) ~= 56 do
        bytes[#bytes + 1] = 0
    end

    local high = math.floor(bitLen / 0x100000000)
    local low = bitLen % 0x100000000

    for shift = 24, 0, -8 do
        bytes[#bytes + 1] = math.floor(high / (2 ^ shift)) % 256
    end
    for shift = 24, 0, -8 do
        bytes[#bytes + 1] = math.floor(low / (2 ^ shift)) % 256
    end

    local h0 = 0x67452301
    local h1 = 0xefcdab89
    local h2 = 0x98badcfe
    local h3 = 0x10325476
    local h4 = 0xc3d2e1f0

    for chunkStart = 1, #bytes, 64 do
        local w = {}

        for i = 0, 15 do
            local p = chunkStart + (i * 4)
            w[i] = (
                (bytes[p] << 24)
                | (bytes[p + 1] << 16)
                | (bytes[p + 2] << 8)
                | bytes[p + 3]
            ) & 0xffffffff
        end

        for i = 16, 79 do
            w[i] = rol((w[i - 3] ~ w[i - 8] ~ w[i - 14] ~ w[i - 16]) & 0xffffffff, 1)
        end

        local a, b, c, d, e = h0, h1, h2, h3, h4

        for i = 0, 79 do
            local f, k
            if i < 20 then
                f = (b & c) | ((~b) & d)
                k = 0x5a827999
            elseif i < 40 then
                f = b ~ c ~ d
                k = 0x6ed9eba1
            elseif i < 60 then
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            else
                f = b ~ c ~ d
                k = 0xca62c1d6
            end

            local temp = add32(add32(add32(add32(rol(a, 5), f & 0xffffffff), e), k), w[i])
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp
        end

        h0 = add32(h0, a)
        h1 = add32(h1, b)
        h2 = add32(h2, c)
        h3 = add32(h3, d)
        h4 = add32(h4, e)
    end

    return string.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
end

function SIFO.gitBlobSha1(content)
    content = tostring(content or "")
    return sha1("blob " .. tostring(#content) .. "\\0" .. content)
end
