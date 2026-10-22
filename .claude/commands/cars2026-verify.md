# cars2026-verify

Read-only verification of output/paper/android_empirical_alignment_final/.
If absent in this worktree, inspect the main checkout's bundle without copying/regenerating.
Locate its checksum manifest; enumerate entries (expect 29) and compute SHA-256.
Enumerate selected runtime UUIDs from retained CSVs (expect 123); inspect each exact
run manifest and hash its referenced PCAP. Validate UUID/package/build linkage.
Resolve historical paths only with an explicit old-root/current-root mapping;
record both paths. Never choose captures by basename alone or edit manifests.
Report actual versus expected totals, MATCH/DIFFERS/UNAVAILABLE, missing/duplicate items.
A missing item is not a match; successful hashes do not establish QA validity.
Preserve original bytes; any requested report belongs outside frozen bundles.
