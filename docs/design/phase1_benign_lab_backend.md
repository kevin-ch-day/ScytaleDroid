# Phase 1 benign-only Android lab

The real acceptance backend extends the earlier synthetic evidence-pack prototype.
It uses a dedicated AOSP API 30 x86_64 image, Android Emulator 37.1.11, KVM and
Bubblewrap filesystem/PID/user/network isolation. It is **not authorized or
implemented as a general malware runner**: the launcher accepts only the exact
reviewed benign fixture SHA pinned in `DynamicAnalysis/lab/sandbox.py`.

The selected software graphics mode is explicit `lavapipe`. `off` and
`swiftshader_indirect` are rejected by the supported launcher. Initial RenderThread
SIGSEGVs occurred in the bundled SwiftShader GLES library, not Fedora QEMU.
Detailed mode comparisons, repeat evidence and root-cause limits live in the
Phase 1 audit. No SELinux, KVM, libvirt, BIOS or Fedora QEMU change was made.

## Launch contract

`scripts/dynamic/lab_acceptance.py --help` is credential-free and side-effect free.
Example for one **new** output directory, using the dedicated SDK root and the
already built/pinned fixture:

```bash
.venv/bin/python scripts/dynamic/lab_acceptance.py boot \
  --lab-root /home/systemadmin/.local/share/scytaledroid-malware-lab \
  --fixture /path/to/pinned/fixture.apk --output /path/to/new/boot-evidence

.venv/bin/python scripts/dynamic/lab_acceptance.py benign \
  --lab-root /home/systemadmin/.local/share/scytaledroid-malware-lab \
  --fixture /path/to/pinned/fixture.apk --output /path/to/new/benign-evidence
```

The boot command never installs an APK. Boot diagnostics can add `--control wipe`,
then `grpc`, `dns`, `pcap` cumulatively. Benign acceptance always uses all controls.
Each trial has bounded boot/operation/outer timeouts and a newly initialized AVD.
No consumer-device selection is exposed. ADB is addressed explicitly as
`127.0.0.1:5555` through an ADB server listening on the filesystem Unix socket
`/work/adb-server.sock`. The emulator transport remains inside the private network
namespace; the ADB controller no longer listens on guest-reachable TCP port 5038.
KVM acceleration is required explicitly with `-accel on`.

## Containment and limitations

Only `/usr`, the dedicated read-only SDK, one pinned fixture, one trusted harness,
KVM and a fresh workspace are mounted. The launcher clears inherited environment,
drops capabilities and forbids nested user namespaces. It never exposes home,
USB, production sockets, desktop bus or the normal ADB server. The namespace has
only loopback and no external route. Golden SDK image hashes are checked before
and after; the entire writable AVD workspace is removed after exporting evidence.

`-dns-server 127.0.0.1` is intentionally a **disabled resolver** in this no-external-
network profile. No listener is running on port 53. It must not be described as
sinkholed DNS or successful resolution. DNS packets/attempts can be captured;
blocked connectivity is not dormant behavior. A real fake-service/sinkhole profile
requires its own implementation and acceptance, not a silently enabled host route.

Acceptance checks both guest-loopback and guest-to-namespace positive canaries,
rejects reachable personal-host service ports, verifies the Unix control socket,
and rejects a TCP ADB controller listener. Guest-to-namespace emulator management
interfaces still exist; this is not a claim that every management surface is absent. gRPC uses
JWT authentication. Namespace isolation does not establish immunity to guest,
VMM or host-kernel vulnerabilities and does not provide the outer analysis VM
proposed for stronger separation. Host-side PCAP parsing is tested only with this
benign fixture. These limits remain part of malware execution readiness review.

## Evidence and reset proof

The local Java fixture has one INTERNET declaration, a launch counter, local
marker, deterministic UI button and bounded documentation-address network probes.
It uses no real accounts or provider API. `tests/fixtures/android_lab` holds the
reviewable source. The fixture's signing key is research-only; changing its build
requires reviewing and repinning the resulting SHA, never accepting arbitrary APKs.

Benign acceptance checks absence before install, exact installed SHA, launch,
zero previous counter, controlled button event, a within-run second-launch counter
of two, PCAP with packets, common Scytale PCAP/features/summary processing, unchanged
SDK images and teardown. A later fresh run must reset the counter. Evidence uses
RunManifest/ArtifactRecord and immutable sealing, explicitly identifies the lab
backend and remains excluded from the consumer dataset. No production DB writer
is called. Failure packs are retained and never rewritten as successes.

Acceptance also requires emulator exit code zero, no premature emulator exit,
and an explicit empty cleanup-error list. All five expected SDK image files must
exist before launch; an empty image inventory cannot pass identity verification.
A nonempty PCAP alone is insufficient: the fixture's `fixture.invalid` DNS canary
must appear in the parsed capture. This positive control does not establish
per-app attribution of other guest traffic or successful external DNS resolution.

Shared flow/time-series enrichment recognizes IPv6 addresses and keeps ICMP
quoted transport headers out of transport flows. ICMP frames still count toward
packet/byte totals. Multi-IP tunnels with ambiguous transport attribution remain
unassigned. This correction does not redefine unrelated DNS, protocol-hierarchy
or media metrics, and historical sealed reports are not rewritten.
