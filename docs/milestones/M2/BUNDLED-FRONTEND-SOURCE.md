# Bundled stock-HAProxy frontend source

Source delivery for [#31](https://github.com/gonz0w/aegvium/issues/31),
[#32](https://github.com/gonz0w/aegvium/issues/32) and
[#23](https://github.com/gonz0w/aegvium/issues/23), following the maintainer's
2026-10-23 recommendation5 approval. Aegvium owns this component. It does not
import or invoke the Vectivium product. Installed entries still refuse and no
credential, listener, process, image or service operation was executed.

## Fixed configuration and placement

`internal/frontendconfig.Compile` consumes the existing canonical
AGPAIR2/M2-H1/3 descriptor, one explicitly selected allowed frontend role and a
canonical unicast IPv4 public listen endpoint. CONTROL-only AGPAIR1 cannot create
this DATA component. All routes must bind the same DATA/CONTROL endpoints,
inspector name, server/client anchors and selected role. No endpoint is inferred
from Host, no backend address is accepted, and the public listener cannot equal
CONTROL or DATA. The returned bytes/digest are detached configuration data.

The closed configuration is for one stock foreground HAProxy child, one thread,
four connections and the existing fixed h1/close-only time/size profile. Its only
server is descriptor DATA, with required TLS1.3/name/CA/client authentication,
no connection reuse, retries or direct application fallback. Same accepted public
SNI/socket facts supply the six frozen context fields. The retained stock
pre-HTTP prefix guard precedes HTTP fetches and the existing header/body/route
rules. This source ordering is **not native strict-framing qualification**.
The fixed config includes package-principal `_haproxy` and `/var/empty` chroot;
exact loader, key-before-drop, dependency, privilege and chroot behavior remain
native requirements.

The existing closed offline coordinator now requires an explicit protected
`commission-inputs/frontend-mode`: exactly `bundled` plus LF or `external` plus
LF. An external mode with bundled input present refuses. A bundled mode requires
AGPAIR2 and exactly seven bounded protected files below
`commission-inputs/frontend`: `frontend-role`, `frontend-listen`, `public.pem`,
`frontend.pem`, `inspector-root.pem`, `server.der` and `client.der`.
A missing or malformed requested bundle never becomes the external profile.
These inputs remain private; source, tests, receipts and repository contain no
real credential bytes. No credential issuance or provisioning is implemented.

The existing target placement path consumes those same fixed inputs. It compiles
configuration itself rather than accepting raw HAProxy configuration. DER roots
must match the full descriptor pins; the PEM inspector root must be the exact
canonical representation of that same opaque DER. Certificate validity, key
pairing, role/EKU and authenticated CONTROL remain actual loader gates.
It requires the pre-existing package `_haproxy`604:604 account/group to be locked,
unique, noninteractive and distinct from the inspector; it never creates or
repairs that account. Those numeric package facts come from retained source and
must be reverified on the exact OpenBSD8.0 package before qualification.

Only a new `etc/aegvium/frontend` directory is created, root:wheel0700. Its fixed
configuration, role/listen references and five material files are root:wheel0600,
single-link regular files, with same-descriptor readback and file/directory sync
through the existing placement implementation. Inspector materials remain in
their separate root:inspector0440 namespace. Failure retains partial state;
there is no repair, cleanup, service start or launch authority. The retained7.9
coordinator stays experimental; this does not replace Bootweave's production8.0
installer/product interface or authenticate its package inputs.

## Reuse and notices

The renderer and prefix guard are adapted from private user-owned Vectivium
commit `e28959892903225887d855677c307712a59ce071`. Exact source readback matched:

| Retained source | SHA256 |
|---|---|
| `internal/inspectorpair/frontend_source.go` | `ca1fe93fa80c0115a6b1d75c43408ac5bcad7f01c9d4533cbadb97bdf1b88d62` |
| `internal/h1guard/fragment_source.go` | `84bb722ec49bdeb2654fd2433a4a699cbe7d78e4a42e1d0d7d864fca1fd4134a` |
| Original private status notice | `5581734019ec5adb4a52f6361f6b9156758e37fee2e7f93a287f86cf73f99f48` |

The complete unchanged notice is retained at
`internal/frontendconfig/LICENSE.Vectivium`. It makes no public license grant;
these adapted files are not relabeled BSD. Eventual public appliance/source
release needs the existing owner's release/licensing decision and complete
package/dependency notices. Private reuse creates no Vectivium runtime dependency.
Removal/replacement is confined to the fixed frontend compiler/placement inputs;
it must preserve requested-inspection refusal and never add an origin fallback.

## Checks and remaining acceptance

Focused pure Go controls cover descriptor/role/listener rejection, cross-route
binding, exact DATA-only configuration, context/guard ordering, detached output,
opaque root equality and separate package-account metadata. Two intercepted
Python methods cover explicit mode and bounded offline input selection; they
perform no filesystem, process, credential or network operations. One initial
multi-route test duplicated an authority and was rejected by the existing parser;
the test fixture was corrected to use a distinct public name, with the original
failure retained. No production rejection rule was relaxed.

Remaining delivery is the real same-generation frontend lifecycle/CONTROL/first
DATA composition, exact HAProxy8.0 package/dependency provenance and Bootweave
placement, authenticated TLS/material lifecycle, distinct-principal backend
isolation, original-wire/inspection/backend fidelity, installed start/restart,
whole-appliance CPU/RSS/FD/disk bounds, and mandatory four-second shutdown.
The compiler, hashes and placement observation prove none of these gates.

## Separate frontend owner source continuation

The separate source owner now composes the installed fixed configuration and
material with actual CONTROL and original-child ownership. It does not expand
inspector S or touch its child protocol, U/C state, required security records or
four-second boundary. `cmd/aegvium-frontend-owner` is a distinct fixed root-invoked
entry. Every installed/default/source entry currently returns77 before native,
file, credential, signal, TLS or child operations; there is no enable argument,
caller receipt or test provider. The private native path is typechecked only.

The source owner opens protected no-follow root components and its own
`var/db/aegvium/frontend` namespace on local FFS. A nonblocking exclusive
`writer.lock` remains held through the actual child/cleanup lifetime. At most4096
canonical generation files are retained; malformed, partial, unreadable or full
history refuses. The selected full104-byte G/D/Q record is created exclusively,
read back and file/directory synced before it is consumed. A name remains burned
on failure. There is no unlink, reset, imported PID/FD, repair or automatic restart.

An additional fixed160-byte `launch.state` is this frontend owner's interlock,
separate from the inspector checkpoint and required audit log. Its format is
`AEGFRN1` plus LF, C/U phase, reserved zeros, the full104-byte record, checksum
and reserved zeros. The initial C has no prior record. Independent Python
literals were frozen before its Go codec. The actual same owner writes/readbacks/
syncs U before Start can be attempted. U or malformed state blocks another launch
and requires the already selected cold-recovery treatment; it never guesses
retirement after helper loss. Counters/files cannot detect unannounced rollback
or clones. C is written only after its original child was actually waited, or
private source ordering proves Start was never called, and non-storage handles
are certainly closed. Unknown birth/wait/close remains retained. State/namespace/
writer handles stay through settlement, with the writer closed last. These C bytes
are not owner-process retirement, timing, image freshness or serving proof.

The fixed loader recompiles exact `frontend.cfg`, retains that actual read-only
configuration FD, rechecks the protected package-principal databases and obtains
only its own configured frontend client material. It uses the existing Aeg
`pairmodel` and `frontendconfig`, rather than copying another descriptor parser
or renderer. The client validates bounded local chains/keys, exact role/EKU,
DER pins, validity, TLS1.3/h1 and nonresumption, on its own actual numeric CONTROL
connection. Its exact request/response/EOF carries the common G/full D/Q tuple.
The endpoint receives one close attempt and active operations must finish before
successful historical comparison. Parsing and TLS have not been executed here.

Only that private successful operation permits the next source step: fixed
`/usr/local/sbin/haproxy -db -f /dev/fd/3`, inheriting only the exact held config
as fd3. No raw configuration/argv/PID, shell, daemon/master-worker mode, reload,
foreign process or direct application destination is accepted. The actual
successful Cmd.Process is the sole child origin; private kqueue NOTE_EXIT precedes
the one consuming Wait. Stop withdraws local preparation before at most one TERM
and one KILL. Signal rights are sealed before Wait and never reconstructed after
loss. The original retirement deadline is not renewed by errors. Expiry or any
unknown cleanup retains the owner/U/lock and blocks replacement. No state or log
I/O participates in active stop/wait. Actual blocking calls, helper loss and the
unchanged mandatory appliance shutdown bound still need native qualification.

Successful CONTROL is historical prepared-data comparison, not Ready/allow or
frontend acceptance. HAProxy's own DATA TLS and Aeg's same-request transaction/
lease/backend barrier remain mandatory. Inspector loss or stale generation must
still refuse rather than select an application fallback. Strict original-wire,
O/I/B fidelity, same-appliance principal/network isolation and actual key/loader/
chroot behavior remain unqualified. No code-only result enables public serving.

For bundled mode the existing fresh writer additionally places its same signed
source-built frontend-owner image root:wheel0555, the exact paired descriptor in
its private configuration directory, and an exclusively new frontend history
namespace with empty lock/consumed directory and initial160-byte C data. No state
is adopted from a serialized freshness receipt; the existing builder must still
own the actual never-started target continuously. External mode creates none of
this namespace or owner placement and retains the explicit non-suite interface.
The retained7.9 coordinator remains experimental, and exact8.0 production payload/
Bootweave/package/first-start/stop/restart integration is still incomplete.

The owner/client reuse immutable Vect e289598 original source with complete
private notices; the original file fingerprints are recorded below. The only
new module is the reviewed source binding in
[ADR0015](../../architecture/adr-0015-frontend-openbsd-bindings.md). Full required
frontend audit coverage, package/executable/update custody, service composition,
complete aggregate CPU/RSS/FD/disk accounting and actual native enforcement/
shutdown remain delivery gates. U/C interlock data is not a substitute for the
required security audit stream or its selected clean-boundary retention policy.

| Reused original file at e289598 | SHA256 |
|---|---|
| `internal/inspectorpair/client_source.go` | `1f47111799c81c4e3a3c8d5e5de9319c06518a5dd182f3ed82785d1b1bd505ba` |
| `internal/inspectorpair/endpoint_source.go` | `881baea5a29802b2369b7fbd8a8df788cf2ac29e3831dd5bca985118b496de93` |
| `internal/inspectorpair/record_source.go` | `1da30f3e5229fed5a28eabae5d8cc9e41aeb4056593ab92f074765365fe6a57b` |
| `internal/inspectorpair/client_source_test.go` | `78c73810242789d4c6f0d3b7e8da7b28ae1b4c1aa6218e46bf50b0a7b1cc3667` |
| `internal/inspectorpair/descriptor2_binding_source_test.go` | `5551eacf60856c476257c55331059663118f26f5ee3a7484b36973a4a9cb7110` |
| `internal/inspectorpair/record_source_test.go` | `5abfb8351b06290273e2e004c6fcb8413aa85121997e6cc3d4e9f60b23309d6d` |
| `internal/startupowner/policy_source.go` | `34869dad592326beabb2c5765dc7340e32fdc3081018097567cc7cc895b296e1` |
| `internal/startupowner/material_source.go` | `1b836f9d89df2f5df380d46abddeec56c1bc59b946fa482fc2598fd3a574e1c7` |
| `internal/startupowner/policy_source_test.go` | `c321a22fbed8c15b611ca8d83a7f1b74cfdf6d04210f487432e816da7293b6f8` |
| `internal/startupowner/material_source_test.go` | `3418918ffcda21903a1d4e34f86c3a23e84b8f626ff9164c4e0d6b5c61c71a25` |
| `internal/startupowner/profile_history_source_test.go` | `c7948182d08a7a824f44b6e4ed7f8d5256cc10d7589909b31db4f7cb1a1292b5` |
| `internal/startupowner/history_openbsd_source.go` | `f33c926bc27d63664293b688cf4f0b07dd2b476a845220b2b8d4b3c144301b15` |
| `internal/startupowner/frontend_openbsd_source.go` | `b456368bf4191b59b6bbf50339f6092b743d13f98c141994b3cd42bc3b9e4145` |
| `internal/startupowner/child_openbsd_source.go` | `96878408e5bcbe69f1bcb32ea5c7eae46be6772c391ab84cbc05a9bb04d9d225` |
