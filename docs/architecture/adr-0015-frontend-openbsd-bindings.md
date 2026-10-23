# ADR0015: bounded OpenBSD bindings for the separate frontend source owner

Status: selected engineering dependency for source implementation; independent
review remains required with this candidate. Refs #23/#31/#32 and the maintainer's
2026-10-23 bundled-HAProxy/separate-frontend-ownership approval.

The separate Aegvium frontend owner reuses private reviewed original-child,
protected-history and authenticated CONTROL source from user-owned Vectivium
`e28959892903225887d855677c307712a59ce071`. It is Aegvium source, not a Vectivium
runtime dependency or a new generic lifecycle service. The inspector's existing
C owner and required records remain unchanged.

Use `golang.org/x/sys/unix` v0.49.0 for actual OpenBSD Openat/Fstatat/Flock,
Fstatfs/Fsync, Fcntl and Kqueue/Kevent bindings. Public os.Root does not supply
the exact no-follow component opens used here, and raw syscall-number shortcuts
are not a substitute for supported OpenBSD libc entry points. The retained
compatible Vect source already uses this version. There is no new network,
listener, account, setuid bit, delegated apply API or credential issuer.

The existing cached module ZIP was copied into the isolated Aeg module cache
without its ziphash shortcut; Go recomputed/verified the exact signed retained
module sums with network disabled:

- module: `h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=`
- go.mod: `h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=`
- retained ZIP SHA256: `e73a06591ca0d7016ce3ccb45c36a8ed7128468aecc1a357f94d815c760c6b31`
- complete BSD license SHA256: `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`

The unchanged license is at `internal/frontendowner/LICENSE.x-sys`. Private
Vect original-material notices remain separately at each adapted package's
`LICENSE.Vectivium`; they make no public license grant. This decision grants no
public relicensing or distribution. Native package/dependency/advisory and
complete release NOTICE review remain required before operational/public release.
No network retrieval, scanner or native execution occurred during this source reuse.

Scope is the source-tagged OpenBSD frontend owner. The transport client uses Go
standard library and the existing Aeg descriptor parser; the inspector's runtime
module choices and authority are not changed. Deliberate version updates require
exact provenance/license review and focused changed-behavior tests; current
source checks do not establish native compatibility or security qualification.
Removal of the frontend native owner removes its unix binding usage; remove the
module only after checking the selected graph. Any replacement must preserve
same-child ownership, generation nonreuse and no bypass on failed inspection.
