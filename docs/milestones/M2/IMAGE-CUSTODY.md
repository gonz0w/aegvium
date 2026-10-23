# Fixed image-file verification under launch exclusion

Source basis0bfb64d; scoped implementation under ADR0014. This connects actual
protected-file and base SHA calls to the existing normal launch path BEFORE U
commitment/controller/pair construction. It has no operational caller and adds
no fork/exec, leaf profile, initial-C, paired frontend, Ready or cleanup issuer.

## Fixed path and equality data

After closing strict launch.intent, open only existing
`/var/db/aegvium/inspector.pin` RDONLY|NOFOLLOW|CLOEXEC. Require UID0/GID0,
regular0600/nlink1/size65, actual descriptor/path matching identity and metadata
before and after an exact read. Require64 lowercasehex SHA256 digits plusLF,
decode32 bytes, then close once. Root mode and this digest are configuration/
equality data, not release authenticity, commissioning provenance or mTLS.
The later [offline payload assembler](OFFLINE-COMMISSIONING.md) produces the pin,
intent, snapshot and initial C as staging data. There is no installed initializer,
update channel, supplied path/digest/FD or runtime provider. A qualified fresh
paired-image builder must still install and hand over those bytes.

Open fixed `/usr/local/libexec/aegvium/inspector` through `/`,usr,local,libexec,
aegvium with DIRECTORY|NOFOLLOW|CLOEXEC. Every ancestor must be UID0-owned,
not group/other writable, and other-searchable (the future unprivileged I must
be able to execute through this path). Open only the existing file RDONLY|
NOFOLLOW|CLOEXEC; require UID0/GID0 regular0555/nlink1/size1..67108864. No actual
permission or installation change occurs. Require fstat/fstatat current identity
and metadata, stream SHA256 using4096-byte pread chunks with exact counts/no
continuation or retry, and one extra pread1 at declared size returning0. Compare
against pin, then require current descriptor/path and original dev/ino/size again.

Close image FD once, then its directory once, BEFORE U encoding/write. The
checkpoint EX remains continuously held. Every supported updater/writer must
refuse inode content, file/path/ancestor mutation and replacement for the whole
S/unresolved-I lifetime; entry/namespace changes require planned cold maintenance
after genuine physical retirement. Flock is advisory, not protection from a
noncooperating root actor. No fexecve exists in retained target API: a held FD
would not itself bind future pathname exec. This source is deliberately NOT a
retained-FD or qualified pathname-execution claim.

Any pin/open/metadata/read/hash/EOF/inode/close fault consumes this process attempt,
retains EX/known references and uncertainty, and forbids U/controller/pair. A close
error is never retried, nor followed by another normal step. Invalid/alias FD
receipts never authorize guessed closes. No image/storage I/O enters active
stop/escalation/wait. Local known-reference peak4 and fixed4096-byte hash block
are source accounting only, not whole-S/native FD/RSS admission.

## Source and independent focused checks

Frozen packet SHA256aa95ea05567892126c19b246fcb0524dad52f60b576543b94da26b91355928e4
preceded source. Independent image literal:4113 bytes, bytei=i%251, SHA256
`d855ba636ffdfea364522538421fa585c1927fe5ef4d8065b89549c6bf744213`.
The pin is exactly that64-byte ASCII hex plusLF. Independent stream calls are
pread(0,4096)=4096/update4096, pread(4096,17)=17/update17,
pread(4113,1)=0, Final32. Existing checkpoint literals remain independent.

The actual fixed wrappers/sequence compile with ALL image/storage/SHA/clock and
existing native calls intercepted; test data and FD numbers are synthetic.
No real host file/FD/permission/socket/identity/process/engine effect occurs.
The existing96 storage cases remain;76 fixed prefix failures cover every new
nonvoid edge plus pin/ancestor/file identity, modes/bounds, malformed pins,
counts, both stream chunks, extra EOF, changed bytes/digest and close ordering.
One compiler30s,172 normal modes5s each, strict outer600s command deadline, fresh
retained task-local TMPDIR, existing owned runner and exact source/tool hashes.
Independent finished-source/fixture review precedes execution. Ordinary hygiene,
redacted-secret hooks, signature and DCO remain; no full/native/engine/security
campaign is inferred. Timeout is failure, never a passed row or cleanup proof.

Retained historical `labproxy-openbsd-amd64` is24760184 bytes; its ELF PT_INTERP
is `/usr/libexec/ld.so`, matching retained Go1.27.2 linker source.64MiB is a
finite image-file cap only, not the future I artifact's fit or memory bound.
Loader/library/whole image custody and compatible target behavior remain
unqualified. This check cannot authenticate or freeze the rest of execution.

## Concrete positive-path prerequisites

Initial C and pins should be WAF-owned OFFLINE fresh-payload commissioning
outputs, never a runtime missing-file initializer or reset. A genuinely new
paired installation must have qualified fresh-image/installer lineage; path
absence, root mode, clean bytes or an operator assertion cannot prove it. A
replacement in an existing pair must preserve consumed lineage and establish
physical cleanup; S-loss still has no selected mechanism. No C creator/repair
actor is added. Defining WAF payload contents need not wait for a generic
BootWeave extension schema; actual commissioning requires its own exact proof.

H1 already selects operator-owned paired immutable snapshots and dedicated role
mTLS. The smallest source continuation is a bounded canonical common descriptor
whose generation also matches S intent, plus actual receiver-owned TLS chain/EKU/
exact-DNS-role verification and snapshot binding. Descriptor/hash equality is
consistency only; it never substitutes for the same connection's authenticated
peer. ADAPTER-EDD's proposed AGPAIR/preflight encoding must receive exact producer/
receiver contract review before becoming a ready path; it needs no new CA or
credential issuer merely to choose a wire format. No credentials/listener is
provisioned, and the frontend still rejects required WAF.

The actual I startup, role-local key/trust reader, data-FD ownership and runtime
syscall closure are not constructed. Derive a sufficient exec-surviving leaf
profile from that code; do not guess stdio-only compatibility or silently widen
inet/rpath/proc/exec/id/sendfd authority. Native no-descendant/no-export, actual
exclusive wait/channel closure, resource and four-second proof remain mandatory.
Full/engine/native validation pause, strict original-framing gate, independent
backend isolation and TLS key custody remain unchanged.
