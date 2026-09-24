# Scientific instrument V2: bounded offline acceptance

This contract covers the dedicated disposable-worker, benign-only acceptance
instrument. It does not authorize malware execution or change the ordinary
physical-device capture workflow into a VM workflow.

## Measurement

`DynamicAnalysis/lab/scientific_guest.py` defines
`offline_300s_no_touch_v2`. Each repeat starts with a fresh outer Linux VM,
fresh ext4 scratch disk and fresh Android userdata from the same read-only AOSP
image. No snapshots are resumed. Arms alternate sham/launch three times.
The approved fixture SHA is checked before installation and after installation;
the sham never installs or launches it. Startup positive network controls must
succeed before observation begins. Android `sys.boot_completed` alone is not a
network-readiness guarantee; the positive control has five bounded attempts.

Observer order is capture at emulator launch, logcat clear/start, clock bracket,
ten-second settle, launch acknowledgement (or sham no-op), then t=0. t=0 is the
worker realtime/monotonic bracket immediately after that acknowledgement.
The analysis interval is **[t0, t0 + 300 seconds)**. A monotonic deadline controls
observation; actual scheduler delay is recorded and must be at most two seconds.
The packet filter uses exact decimal boundaries, not rounded minute boundaries.
This interval intentionally excludes launch activity before acknowledgement.
There is no UI interaction within the window. Process/activity snapshots occur
at scheduled offsets 0, 150 and 299 seconds; these are snapshots, not continuous
process tracking. Worker realtime mapping residual must remain within 50 ms.
Android realtime is bracketed over ADB before/after the window.

Packet/byte/DNS/destination counts describe the captured virtual link, including
system, multicast, guest and virtual-router traffic. They are not app-attributed
traffic or external destinations. DNS count means query-bearing packet count.
No sham subtraction is performed. Emulator drop counters are unavailable and
logcat completeness is not proven. Record those limitations, never zero loss.
Three repeats support descriptive variability only, not population inference.

## Worker and parser boundaries

`lab/vm_worker.py` constructs the outer Linux/KVM worker. QEMU has no NIC,
monitor, user config, or default devices. Rootless bubblewrap limits its host
filesystem to read-only public runtime tools, SDK, boot/control inputs and fresh
writable scratch/export directories. No host home, credentials, DB sockets,
physical USB device, or normal LAN is exposed. Android uses a private Unix ADB
server socket within the disposable VM. The worker has its own kernel instance;
the host CPU, KVM/hypervisor and read-only `/usr` runtime files remain shared.
This is a concrete containment boundary, not proof against hypervisor escapes.

`lab/worker_entry.py` stops the Android harness, then launches
`lab/isolated_parser.py` as UID/GID 65534 in a separate all-unshared bubblewrap
namespace inside that outer VM. The parser gets only read-only inputs/runtime
and a dedicated output directory, with no KVM, SDK, control directory or network
beyond loopback. PCAP dissection and APK ZIP metadata parsing occur there. Logs
are exported as bytes, not interpreted by privileged host parsers. Host import
copies/hashes bounded regular files only after worker exit; it consumes JSON
receipts. It does not mount or interpret the discarded scratch filesystem.

The acceptance controller is retained with its exact commands and source/image
hashes in the dated audit packet. It is pinned to the approved benign fixture;
it is not an authorized generic sample executor.

## Hostname correlation

`pcap/hostname_overlap_v2.py` emits additive `hostname_overlap_v2` output before
sealing. Existing legacy `static_dynamic_overlap.json` remains unchanged.
Three metrics have separate numerators and denominators:

- `exact_host_overlap_v2`: unique normalized host equality.
- `subdomain_relation_overlap_v2`: static host equals or is a label-boundary
  parent of a dynamic host; directional, not symmetric.
- `registrable_domain_overlap_v2`: strict offline PSL eTLD+1 intersection,
  including private suffix rules; no last-two-label or unknown-suffix fallback.

Normalization preserves all raw inputs and exclusion reasons, uses nontransitional
UTS46/STD3 IDNA, lowercase and one root-dot removal. URL authority/port syntax is
validated; wildcard prefixes are explicitly recorded. IPs, public suffixes and
synthetic/local names are excluded. Unknown suffixes can participate in exact
and directional comparisons but cannot obtain a fabricated registrable domain.
Relations do not prove ownership, attribution, maliciousness or safety.

## Final sealing and grading

`core/sealing_v2.py` is the single final hashing authority. The writer inventories
all retained files, including files omitted by producers, and fills declared
artifact SHA/size fields centrally. Each inventory row has role, source, origin,
collection status and either hash/size or an explicit failure reason. Unknown
provenance remains unknown; hashing does not manufacture collection provenance.
Missing, unsafe or unreadable files make sealing incomplete. Symlinks are not
followed. Verification checks inventory structure, completeness, bytes and size.

`run_manifest.json` is the explicit self-reference exception, anchored externally
by its SHA. The transient in-progress marker is excluded and removed after seal.
Ordinary retained files must all hash successfully for acceptance. Producers must
stop before sealing; the contract does not claim filesystem-level immutability
against unrelated processes. Independent post-seal verification detects change.

V2 EvidencePackWriter refuses writes into a sealed pack. Operational events,
persistence receipts and engine summaries use sibling `<run>.postseal` paths.
Those derivatives are outside the canonical seal and are not silently treated
as captured evidence. Legacy V1 paths retain compatibility. The legacy automatic
Profile V3 ML derivation is explicitly refused for V2 sealed inputs because it
writes inside packs; a separately versioned external derivation workflow is
required. No model training is part of this acceptance study.

The grader consumes the same V2 integrity verification and separately retains
telemetry/required-artifact/provenance checks. Integrity does not change `tier`,
`countable` or `valid_dataset_run`. Benign/sham acceptance packs are deliberately
`lab_acceptance`, non-countable and ineligible as malware dataset observations.
Capture validity, evidence integrity, research eligibility and countability are
four separate conclusions.
