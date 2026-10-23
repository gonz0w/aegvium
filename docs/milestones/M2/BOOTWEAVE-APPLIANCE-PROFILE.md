# Aegvium appliance profile requirements

Source/design direction, 2026-10-23. The maintainer selected Bootweave to turn
stock OpenBSD into hardened, preconfigured appliances with little setup and
useful logging/monitoring. OpenBSD 8.0 is the prospective release baseline;
amd64 is an initial qualification candidate, not a product-wide architecture limit;
[the official release page](https://www.openbsd.org/80.html) identifies 8.0.
No 8.0 image/source acquisition, build, installation, setting, credential or native
execution is authorized or qualified by this document. Preserve all 7.9 evidence.

Bootweave owns the production installer and its constrained target-operation
contract. This document supplies Aegvium's consumer requirements, **not a new
Bootweave schema or authority issuer**. `tools/commission-owner.py` and the private
`install.site` remain closed 7.9 experimental source. Their `install79.iso`,
`site79.tgz`, set paths, answer file and target compiler assumptions must not be
ported by string replacement or shipped as arbitrary product-provided root hooks.
Bootweave is an installation integration, not an Aegvium runtime dependency.

## Product and supported-target acceptance

Bootweave's three appliance profiles are **Aegvium, Nomvium and Arxwall**.
Vectivium retains its independent package/service product; it is neither a fourth
required ISO profile nor an Aegvium prerequisite. Aegvium's goal is a WAF image
for a VM or supported bare metal, not merely an inspector component or research
bundle. Actual inspection, rejection without bypass, application/backend isolation,
protected startup/restart, operational logging and honest health must pass for the
installed profile. Hardened defaults are an acceptance target, not absolute security.

Only necessary site inputs should remain: interface/management binding, application
authorities/backends and protected per-instance identity/trust material. Their absence
must produce a clear unconfigured/refusing state, never an uninspected fallback.
The installer must not bake common keys or infer operational credential authority
from this product clarification. A conforming non-suite frontend must be accepted
and tested; optional Vectivium integration cannot replace standalone acceptance.
The image also needs a concrete supplied public frontend and its owned startup/
pairing path: a protocol specification or private inspector endpoint alone is not
a ready-to-protect standalone WAF. Reusing a standard frontend component is allowed
in principle, but its actual generation/lifetime handoff must be delivered without
requiring the Vectivium product. This paragraph selects no new launch authority.

The architecture/media interface must permit independently qualified amd64/arm64
VM and bare-metal profiles, plus board-specific media where supported. An ISO is
not a universal board boot image. The versioned [OpenBSD 8.0 arm64 installation
instructions](https://ftp.openbsd.org/pub/OpenBSD/8.0/arm64/INSTALL.arm64) list Pi
3/3 B+/4/400/Compute Module 4/5; the [arm64 page](https://www.openbsd.org/arm64.html)
explains firmware and board differences. This is OS support evidence, **not WAF
compatibility**. Exact boot firmware/device tree, console, NIC/storage, confinement,
resource and protection behavior require profile-specific qualification. No hardware
profile is qualified here; generic GOOS/GOARCH compilation does not qualify a board.

## Required product inputs and target operations

- Authenticated stock 8.0 release/architecture, installer, kernel/base/compiler
  provenance and complete built S/I/loader/module closure. A generic GOOS build
  proves no specific OpenBSD release. No existing 7.9 hash or receipt becomes 8.0
  evidence; exact syscall/pledge/closefrom/wait/crypto/storage behavior must qualify.
- Fixed Aegvium supervisor and inspector locations under
  `/usr/local/libexec/aegvium`, root:wheel, mode 0555, single-link; private namespace
  `/var/db/aegvium` with protected `launch.state`, `launch.intent`, `pair.snapshot`
  and `inspector.pin`. The current archive has five files and an inspector cap
  of 64 MiB; its hash/metadata are staging equality, never release authenticity.
- Exactly one dedicated `_aegvium` principal, disabled login, no secondary groups;
  protected role-local files below `/etc/aegvium/inspector`, root:dedicated-GID, mode 0440,
  fixed names and source limits from [roles](../../../internal/commission/roles.go)
  and [private backends](PRIVATE-BACKENDS.md). No public frontend key on I, common
  image secret, ambient trust or installer-generated credential policy is adopted.
- The actual fresh target owner must maintain exclusive never-started custody
  through protected placement/readback, file/directory durability and the genuine
  frontend-owner paired handoff. It must not export, clone or start a partial
  target. Archive bytes, a path/FD, parsed C or a receipt cannot establish freshness.
  Any qualifying frontend may implement the explicit protocol; Vectivium is optional.
- Boot/service ordering must preserve the actual sole-S launch/wait owner and
  independent backend isolation. Qualified setup should start the appliance
  automatically with few operator inputs; unknown pairing/isolation must refuse.
  No guessed PID control, hot update, crash-restart loop or supervisor-loss repair.
  The current S/I entry gates remain false; service activation is not delivered.

## Logging, monitoring and minimal setup are acceptance work

Current I construction maps fd 0–2 to `/dev/null`; Coraza's transaction logging
phase is not a delivered operational audit sink. Current source also supplies no
qualified external health/status interface. These are concrete implementation gaps,
not native evidence or optional polish. Bound/redact events and retention, separate
service/inspection/backend/cleanup health, and keep request bodies, keys, cookies
and query values out of logs. No collector or suite product may be mandatory.

Recommend base OpenBSD local logging/rotation and an explicit read-only health
interface, coordinated with Bootweave's profile contract. The exact I log transport
and S health/control boundary still need a scoped design: adding a descriptor or
Unix-socket privilege cannot silently change existing leaf/S resource contracts.
Do not infer Aegvium control-socket approval from Vectivium's separate decision.

The next integration step is Bootweave's concrete typed placement/account/service/
logging interface plus a genuine paired-target handoff provider. Then connect
Aegvium's production profile without a second installer. Initial private inputs,
8.0 qualification, resource/four-second proof and standalone installation remain required;
no image here is presently hardened, ready to run or deployable.
