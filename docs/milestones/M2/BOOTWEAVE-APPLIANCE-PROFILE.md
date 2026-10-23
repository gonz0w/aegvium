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

Bootweave's four appliance profiles are **Aegvium, Nomvium, Arxwall and Vectivium**.
The maintainer also selected a Vectivium appliance on 2026-10-23, using the same
product code as its independent package/service distribution. Aegvium remains
optional for Vectivium, and Vectivium remains optional for Aegvium. This does not
create a required suite runtime dependency. Aegvium's goal is a WAF image
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

The approved [local diagnostics source](LOCAL-STATUS.md) maps I fd 0–1 to
`/dev/null`, fd 2 to its private nonblocking diagnostics channel and fd 3 to
bootstrap/Stop/ACK. The same S consumes bounded redacted frames and sends local
logging datagrams; overload or stop may lose diagnostics. This is source only,
not a complete forensic audit or a qualified external health/status interface.
Required durable authority-changing security records and finite retention still
need their scoped contract. These are concrete appliance acceptance gaps, not
optional polish. Keep request bodies, keys, cookies and query values out of logs;
no collector or suite product may be mandatory.

Base local logging is connected in source with explicit six-descriptor private
acquisition accounting and two additional S integration descriptors. This is not
a whole-process/kernel/storage bound. Periodic rotation is not a hard disk cap.
An explicit read-only health interface, complete retention and the installed
8.0 resource profile remain unqualified; no health/control socket is adopted.
Do not infer Aegvium control-socket authority from Vectivium's separate decision.

The next integration step is Bootweave's concrete typed placement/account/service/
logging interface plus a genuine paired-target handoff provider. Then connect
Aegvium's production profile without a second installer. Initial private inputs,
8.0 qualification, resource/four-second proof and standalone installation remain required;
no image here is presently hardened, ready to run or deployable.
