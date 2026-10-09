-- Regression tests for Git-compatible blob hashing.
-- Run from the repository root with: lua tests/sha1_test.lua
SIFO = {}
dofile("server/sha1.lua")

assert(
    SIFO.gitBlobSha1("") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
    "Empty file must match Git's canonical blob SHA-1"
)
assert(
    SIFO.gitBlobSha1("test") == "30d74d258442c7c65512eafab474568dd706c430",
    "Text file must match Git's canonical blob SHA-1"
)

print("SIFO Sentinel Git blob SHA-1 tests passed.")
