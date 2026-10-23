# Aegvium appliance profile requirements

Source/design direction, 2026-10-23. The maintainer selected Bootweave to turn
stock OpenBSD into hardened, preconfigured appliances with little setup and
useful logging/monitoring. OpenBSD 8.0/amd64 is the new prospective baseline;
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
