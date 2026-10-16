# ADR 0008: Local backend socket ownership research

Status: bounded research decision; product adoption pending.

Sender containment prevents another local UID from forging the companion's data socket, but the owned backend ports remain directly reachable. Add separate PF policies restricting fresh loopback IPv4 backend connections to the lab companion/fixture UID, while retaining relayd-only data access. Keep the original sender-only policies as controls.

A distinct nonroot probe principal sends the same direct attack bytes to HTTP and verified HTTPS backends across open/protected/rollback/protected-again phases. Independent fixture receipts establish whether each bypass actually reaches its backend. The actual identity-enabled CLI must keep all prior inspection, authority, TLS and recovery outcomes. Root owns fixed policies and restoration; public marker synchronization cannot request privileged actions.

This selects no production UID, remote backend network policy, startup service, IPv6 or existing-state revocation contract. Root/PF administrators and allowed-UID compromise remain outside the boundary. No dependency or non-test Go change. See the [scoped PRD/EDD/tests](../milestones/M1/BACKEND-ISOLATION.md).

The [native result](../../research/native/backend-isolation-observations.json) now observes the distinct-user bypass/independent-effect matrix, unchanged inspected traffic and complete restoration. The policy follows [PF socket ownership semantics](https://man.openbsd.org/OpenBSD-7.9/pf.conf.5#user); its authority is the account that opens each socket. Actual probe UID/EUID and native binary identity are required independently of that source-based expectation. Product adoption remains pending.
