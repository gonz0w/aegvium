# Inert inspector and sole-supervisor source path

Status: source implementation only. Default inspector and supervisor entries
return77. No source entry, credential reader, engine constructor, actual fork,
pledge, signal or native operation was executed in this slice. Draft126's
validation pause and mandatory four-second shutdown requirement remain.

## Concrete executable composition

`cmd/aegvium-inspector` reaches the real startup only on OpenBSD with all three
tags `aegvium_transport_source,aegvium_engine_source,no_fs_access`. It consumes
the actual inherited FD3 AGBOOT descriptor, loads fixed protected role-local
materials, constructs the existing explicit-root TLS receiver, requires every
route to select the actual pinned engine policy, constructs that engine and
binds its single generation. It then writes AGSTART112 and transfers access to
the same retained control file to the existing Stop/retirement handler. There
is no second FD owner, FileConn, duplicate, reopen or public material provider.
Partial startup remains owned; neither engine Close nor an ACK proves cleanup.

Role files are fixed below `/etc/aegvium/inspector`: `cert.pem`, `key.pem`,
`server.der`, and `client-<configured lowercase SHA256>.der` for every configured
frontend anchor. Ancestors are nonsymlink root:wheel directories without special
or group/other-write bits. Files are root:dedicated-inspector-GID0440, regular,
nlink1; no ambient roots or public-endpoint key is used. Existing bounds are
65536 certificate bytes,16384 private-key bytes,16384 bytes per DER anchor and
at most eight client anchors. Cap+1 reads, independent readback, current named/
opened identity checks and once-only Close precede actual credential parsing.
Read buffers and uncertain handles stay process-owned. Account/material
installation now has an unexecuted fixed fresh-builder source connection; no real
account or role file was inspected, created or changed. See
[fixed commissioning](FIXED-COMMISSION-OWNER.md) for its private-media obligations.

AGSTART112 is eight ASCII bytes `AGSTART1` followed by existing AGCHECK104.
For the retained public fixture its SHA256 is
`1512f8456b86df34f0780bb7b399d60440b308b2263507c64c970481cf8acbcb`.
It reports local prepared configuration/policy, never serving readiness, an
allow verdict, frontend acceptance or supervisor identity.

`cmd/aegvium-supervisor/main.c`, built explicitly with
`AEG_INSPECTOR_SOURCE`, is one fixed single-threaded source caller. It commits
durable U through existing storage/pair code before forking. The adapter checks
root real/effective/saved IDs, resolves only the dedicated `_aegvium` account,
sets SIGCHLD to default with no auto-reaping and retains only the actual positive
fork receipt as its signal/wait target. Parent duplicate closure still runs if
clock observation fails. Child preparation reuses existing FD3/closefrom/triple-ID
reduction and fixed pathname exec with an empty environment; failure exits77.
Only that private channel's exact cached tuple can match AGSTART. No supplied
PID, FD, receipt, callback or historical process can enter this constructor.

Stop/tick use existing controller deadlines and fixed Stop/ACK frames. Reads and
waitpid are nonblocking; no journal I/O enters active stop/escalation/wait.
SIGKILL is attempted once only while the captured child remains exclusively
wait-owned. Terminal wait or lost wait identity permanently prevents later
signaling. Sent/missing/denied signals and ACK retain the envelope; actual known
terminal plus one successful local parent-end Close precede logical reclamation.
Fork failure has an actual owned-pair cleanup path. Close uncertainty never
authorizes retry. There is no TerminalClean/U→C writer, recovery or replacement.

## Qualification and remaining product connections

The exec-surviving `stdio rpath prot_exec` restriction is an **unqualified inert
startup candidate**, derived from this no-network command's file/loader reads,
memory/timer/thread/FD use and executable mapping. It excludes inet, proc, exec,
id and descriptor passing after exec. It is not the serving leaf profile. Actual
Go/loader/Coraza/X509 syscall compatibility, exec survival and no-descendant/
no-export behavior must qualify before any operational entry is admitted.

The initializer has no listener, application request path, backend connection,
Ready or forwarding authority. Supervisor build/placement and dedicated account/
role installation are connected source only. Remaining source connections are
the actual Vectivium owner's paired handoff and complete authenticated request/
backend/isolation integration. Matching descriptor bytes and a retained target
FD cannot stand in for Vectivium's real ownership/acceptance. BootWeave is unchanged.

The [private backend loader](PRIVATE-BACKENDS.md) now joins fixed startup and
fresh-builder placement. It prepares exact route/role/root-bound TLS state only;
it grants no backend attempt. The common control/DATA endpoint decision remains
unadopted, and no DATA listener or new pairing version is inferred.

Native acceptance still needs exact installed S/I/loader/compiler/cache lineage,
fresh-image and matching pair custody, protected material read/failure controls,
SIGCHLD/exclusive wait/PID reuse controls, stuck startup/control/engine faults,
stop/ACK/escalation/terminal/descriptor cleanup, resources and the entire original
four-second target. Host pure/intercepted tests and OpenBSD compile-only output
provide none of these runtime receipts. No new user trust decision is adopted.
