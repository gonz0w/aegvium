# Aegvium private native construction source — pre-code packet

Base504fccdcec1b182d664d9c640a453ce60e168f48 clean. ADR0011 adopted sole-root-S /
one-unprivileged-I semantics. This slice adds actual private OS call paths for
one control pair and child descriptor/identity preparation. No caller/entrypoint,
fork, exec, signal, wait, listener, privilege effect, engine or positive startup
is activated or executed. Durable history and held pathname authority are absent.

## Production source API and fixed boundaries

Private C component native_construction.{c,h} owns one static attempted state;
fixed direct OS wrappers native_openbsd.c/native_os.h cannot be replaced at
runtime. Only test builds link/intercept known syscall names. No op table,
registration, model issuer, raw FD getter, caller-selected command/PID/path or
Ready/Owned/ACK issuer. All success is a local construction step, not startup.

Prepare claims one attempt, requires existing controller Reserved/held/nonfaulted
state, calls AF_UNIX SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK socketpair(protocol0),
then fixed /dev/null open O_RDWR|O_NOFOLLOW|O_CLOEXEC and fstat character-device
check. Every owned source descriptor is relocated to >=4 with F_DUPFD_CLOEXEC
before any standard/control target duplication; low allocations0..3 never get
silently overwritten. At most4 private construction descriptors overlap during
relocation. Exact kernel-return receipt owns descriptors; shape/bytes/getter
never manufactures a child/channel identity. Unknown/invalid descriptor output
is uncertain and never used for guessed cleanup.

Pair success keeps S/I/null source descriptors private/CLOEXEC. Future actual
fork copies state; this code does not claim that a supplied branch call proves
that fork happened. One branch attempt per state: parent closes only I-end and
null exactly once, retains S-end CLOEXEC. Child requires nonzero/non--1 fixed
future-profile UID/GID before effects, dup2(I,3), dup2(null,0/1/2), verifies3 has
CLOEXEC clear and NONBLOCK still set, then checks closefrom(4). On success the
child retains only harmless standard descriptors and control3; this is a
syscall-sequence obligation, not native no-export/descendant proof.

Child then setgroups(0,NULL), setresgid(g,g,g), setresuid(u,u,u), getgroups(0,NULL)
==0, getresgid/getresuid exact three-value equality. No names/defaultidentity/
profile issuer. Any failure/mismatch stops further normal steps, retains failure
or uncertainty, and cannot be retried/rebound. Future child caller must terminate
on failure; no such operational caller exists. No functions emit controller
NoChild/Owned/Closed/terminal events or refund its envelope.

Each owned close is attempted at most once; error never authorizes a retry on a
possibly reused descriptor. Successful independent local closes don't claim S
protocol closure or inspector reclamation. Read-only view exposes fixed stage/
held counts/faults only, no descriptor/PID capability. No reset.

## Retained primary source, read only

OpenBSD7.9 src.tar.gz at arxwall-core/.tools/ntpd-source, archive SHA256
fb305c553059b48e8ee64539f392b783cb38a67865823f6f6a94f3b220a1268b.
Exact members lib/libc/sys/{socketpair.2,setgroups.2,setresuid.2,closefrom.2,
fcntl.2,execve.2,pledge.2,unveil.2}, include/unistd.h. No extraction/fetch.
closefrom returns int/errors, never assume void success. No fexecve declaration
or manentry: held FD/hash alone cannot bind pathname exec. unveil tracks ordinary
files byname, not immutable inode. Actual target compile/behavior stays unproved.

## Frozen failures required before code

N01 one attempt only, copies/no reset don't mint another pair/branch/identity.
N02 socketpair exact arguments, fixed null open; returned distinct valid sources
relocated >=4 before target dup. Aliases/lowFD0..3 preserved correctly; output
invalidity/uncertainty never guesses close target. Native FD flags not fabricated.
N03 parent closes only I/null once, leaves S endpoint CLOEXEC; no child/cleanup or
controller event. Close error retained; failed close never retried.
N04 child trace: targetID validation before any effects; I->3 then null->0,1,2;
FD3 CLOEXEC clear/NONBLOCK set; closefrom4 checked before group/UID work.
N05 groups0 -> tripleGID -> tripleUID -> groupcount0 -> tripleGID/UID readback;
zero/-1 IDs, syscall errors or any unequal triple refuse. No later syscall after
failure except bounded cleanup of independently owned known descriptors.
N06 every acquisition/dup/flag/close/identity/readback edge can fail; consumes its
attempt, no Ready/Owned/refund/exec. Close uncertainty and closefrom failure retain
ownership without retry. Captured fixed trace rejects extra/unexpected OS calls.
N07 no actual host socketpair/open/fcntl/dup/closefrom/groups/IDs/fork/exec/wait/
signal/listener in tests; all boundaries intercepted with fixed deterministic
fakes. Source validates no PID/byte/Boolean as actual native authority.

## Proposed check containment

Independent literals before source, then exact finished fixture review. One
normal compiler invocation(timeout30s) builds production C sequence+real wrapper
source under explicit test-only syscall interception; actualOpenBSD compile and
execution unrun. Fresh retained writable task-local TMPDIR from start, no denied
systemtemp retry. Bounded fixed fake trace modes, <=48 normally exiting host
harness processes, timeout5s each, no subjects/IPC/effect calls. No fixturethread
or signals. Existing owned bounded launcher with source/tool hashes. Independent
review may narrow count after actual graph. Root Go API vet only if source graph
changed (currently notneeded); ordinary source/redactedsecret checks+hooks,
signature/DCO. No unrelated checkcampaign or repeated priorpolicy checks.

## Separate unavoidable launch prerequisite

Recommend a fixed root-controlled executable namespace with updater exclusion
through S lifetime plus cold maintenance for entry/namespace changes, combined
with bounded durable consumed-generation/exclusive-owner journal and explicit
cold reconciliation after uncertainty. This is NOT adopted here: exact namespace,
commit/fsync ordering, exclusion participants, S-crash/restore semantics and
recovery authority need a bounded design review/adoption. Alternative external
nonrollbackable witness supports rollback/clone detection but adds a trust and
availability dependency; pathname isolation alone does not detect rollback.
Exact exec-surviving pledge/leaf profile also needs the actual I startup file/
trust/syscall closure. No broad rpath/network promise or unusable stdio-only
profile is silently selected. All native no-descendant/no-export/4s proof remains.

## Current connected implementation and reviewed boundary

The production sequence and direct OpenBSD wrapper now exist. Test source compiles
that actual wrapper under explicit compile-time syscall interception, including
socket/open/fcntl flags, rather than replacing it with a runtime fake provider.
No entrypoint calls these functions. Local branch preparation is not a positive
fork/peer/history issuer. Invalid initial branch ordering burns the process
attempt (post-code hardening); no later pair preparation is permitted. Zeroed ID
readback arrays also reject an incomplete successful getter defensively.

Native held-image execution, fork, positive bootstrap, complete leaf restriction,
history, updater, signal/wait and runtime admission remain absent. No child or
parent preparation result enables C01 or grants allow/forwarding. Existing real
control Stop/retirement source is unchanged. Fixed source bounds below do not
prove target RSS, all-process descriptors, descendants, descriptor export or4s.

## Concrete unadopted launch/history recommendation

Recommend a WAF-owned root-controlled version namespace and cold-maintenance
exclusion contract. Stage a new version separately; never mutate/rename the
selected executable or any pathname ancestor while its S or unresolved I may
exist. All trusted installers/updaters/operator writers must honor the same
exclusion. Source checks ownership, modes, nonsymlink traversal and content pin,
but those checks alone cannot bind a later pathname exec without writer exclusion.
A fixed held FD remains provenance evidence; it does not supply missing fexecve.
Changing the entry/namespace requires proved cleanup and cold maintenance.

For a bounded first history profile, recommend a root-owned stable lock inode and
append-only regular journal capped at64KiB:512 fixed128-byte records, at most256
consumed launch attempts with one Consume and one TerminalClean record each.
Never prune/recycle/reset consumed entries. Exhaustion refuses further normal
launches, requiring a separately reviewed migration/maintenance plan. This is
an operational limit, not native durability/resource evidence. A streamed scan
needs one record buffer and bounded generation comparison state; no unbounded
in-memory history set. Validate the entire bounded journal, reject duplicate
consumption/torn/unknown records, and require a matching clean terminal for the
prior consumed generation before any new attempt. Failed startup burns its
Consume record. A terminal record can originate only from S's continuous exclusive
wait, actual local control closure and the qualified no-export/descendant build.
An old receipt or parsed checkpoint cannot mint those observations.

Hold exclusive nonblocking flock on the stable inode for S lifetime; don't inherit
it in I. Create/validate files through fixed root-owned nonsymlink namespace;
new files must be durably installed before normal launching is enabled. Append a
canonical Consume record and fsync before child creation; no further step after
write/sync/close uncertainty. TerminalClean follows actual cleanup and its own
write/sync commitment. Exact record layout/hash, initial file+directory durability
and filesystem semantics need focused primary-source review/native acceptance;
no positive implementation is claimed. Source corruption or S death leaves an
unclean record even if the OS releases flock, so a new S refuses rather than
adopting a guessed PID. Journal bytes do not authenticate a live child.

Cold reconciliation needs an explicit operator effects plan proving old I and
all descriptors/descendants retired before repairing authority. This source
proposal authorizes no repair/fencing or secret operation. Unannounced snapshot
rollback/live cloning remain unsupported: local files/locks cannot detect both
being restored. An external nonrollbackable witness is the practical alternative
if that capability is required, adding trusted service and availability coupling.
A compact counter checkpoint could avoid journal exhaustion but requires a new
cross-product paired-generation issuer/format contract; do not silently invent it.

The major adoption question is the WAF-specific namespace/updater exclusion and
local-history/cold-recovery availability tradeoff. Fixed byte layout/caps and OS
failure handling are routine engineering review within that choice. None of the
above is adopted by this implementation or borrowed from Nomvium approvals.

## Supplementary-group source verification

The source owner and independent reviewer separately read the retained OpenBSD7.9
kernel archive in place, without extraction, fetch or execution: sys.tar.gz
SHA256c9ef294021ef7aafd5f18ffe8ebfed63394e5a86d65d7436d6db78551f9d57f1.
Selected member hashes: kern_prot.c9d856e6aad814452481db44123acb597865befcc95aa3fd686996b8fec3389b1;
ucred.h5919e6a6afe5f50fd414e7d3830ef8986e098454c90fc61dc5e7ec85858afa5b;
param.h80017c9395be25d7dcf8a3103ddb8c032c47cde46ea5575971297cb3452812f4.
Kernel setgroups stores the requested supplementary count directly; setresgid
changes separate real/effective/saved GID fields; getgroups with capacity0 returns
the supplementary count. Thus clearing0 then triple-GID reduction does not
implicitly add a group entry. param.h identifies OpenBSD7_9/202605. This resolves
a source-ABI question only; actual target build, identity effects and complete
privilege/descriptor qualification remain unrun. The archive was retained with
Nomvium inputs, but this introduces no Nomvium runtime dependency or authority.
