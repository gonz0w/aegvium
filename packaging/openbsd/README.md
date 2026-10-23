# OpenBSD8.0 product package and commissioning source

Partial source delivery for [#23](https://github.com/gonz0w/aegvium/issues/23),
[#31](https://github.com/gonz0w/aegvium/issues/31) and
[#32](https://github.com/gonz0w/aegvium/issues/32). No native package tool, installer,
commissioning entry, credential or service has been executed. All qualification
gates remain false. This does not make Draft126 an accepted appliance.

## Package recipe

`make source-package` is a fixed **native OpenBSD8.0** recipe for amd64/arm64.
Its default target refuses77. It requires a new private `.source-package`,
nonroot build, exact project Go version and independently authenticated local
source/tool/module inputs. Module fetching and toolchain downloads are off.
It builds the existing real I, C supervisor S, frontend owner and commissioning
source entries; their operational gates are retained. The Go source and C units
are the same runtime code, not package-specific refusal replacements.

The source development name is `aegvium-0.0.0`; `pkg_create -B` uses only the new
stage, `/usr/local` prefix, the literal PLIST/DESCR and
`-P net/haproxy:=:haproxy-3.2.25`. That identifies the selected default dependency,
not authenticated package bytes or its recursively resolved closure. No Vectivium
package is required. The recipe creates no account, credential, per-instance
state, rc script, listener or autostart and has no fetch/install/cleanup target.

PLIST installs the four executable paths root:wheel0555 and
`/usr/local/share/aegvium/package.images` root:wheel0444. Its fixed equality format
is `AEGBIN1` plus LF, then three LF-terminated lines in the order `inspector`,
`supervisor`, `frontend-owner`, each `name canonical-decimal-size lowercase-sha256`.
Inspector/frontend-owner keep the64MiB source cap; S keeps the1MiB source cap.
The manifest is bounded320 bytes and creates no signature or executable custody.
The commissioner itself belongs to the separately authenticated package, not a
self-authenticating manifest. Source notices are placed under
`/usr/local/share/doc/aegvium`; the fixed Go LICENSE/PATENTS and vendored x-library LICENSE/PATENTS are copied
from the same actual GOROOT used to build. Explicit versioned module notices use
that build environment’s actual GOMODCACHE: the19-module retained engine/CRS legal
inventory plus x/sys, including the separate CRS rules license and module patent
files. No recursive inventory/collector or guessed substitute notice is used; a
missing source notice aborts packaging. The jsonschema nested test-suite license
is outside the packaged runtime input. The private Vect source release/licensing
decision and final actual artifact attribution review remain distribution gates.

Go's CGO-off flag does **not** prove a static OpenBSD image. Base libc, the dynamic
loader, the C supervisor and actual HAProxy dependencies/SONAMEs still require
native dependency inspection and pkg_create/pkg_add metadata acceptance. The recipe requires exactly one regular, nonsymlink `/usr/lib/libc.so.*` in
the guarded native8.0 build environment, derives its actual `c.major.minor`,
and passes that quoted resolved spec to `pkg_create -W`. Missing/ambiguous or
nondecimal names refuse; no version is guessed. This base-libc declaration is
not complete staged-binary dependency/loader/SONAME closure evidence. Stock release/package trust
and product package trust must be bound separately; measured hashes are equality
only. There is no signed/built product tgz or installed allocation evidence yet.

## Fixed production commissioning ABI

The product entry is **`/usr/local/libexec/aegvium/commission` with no arguments**,
invoked inside the offline target by its actual qualified installer owner. No target-root
selector, imported FD, receipt, callback, shell command or enable flag is accepted.
`nativeProductionCommissionQualified=false` refuses77 before files, accounts,
credentials, processes or output. Source builds typecheck the actual connected
body without enabling it. No environment override changes that gate.

The actual installer must continuously own **one fresh, never-started target** for
the bundled standalone appliance. Frontend and inspector share that image with
separate placement namespaces/runtime owners/principals. No second Vectivium
image is required. Both-target ownership/handoff applies only when the optional
external paired-image feature is selected. This command cannot establish either
lifetime from root status, absent paths, package equality or descriptor bytes.
Original installer/tool terminal cleanup and the actual once-only handoff remain
the owner’s responsibilities; a returned line cannot discharge them.

After independent stock/product package authentication and fixed package placement,
the owner binds the existing private input schema under **`/aegvium.install`**,
root:wheel0700. Its complete inventory is:

- `pair.snapshot`, root:wheel0400, canonical AGPAIR≤8192 bytes with nonzero
  generation. Bundled DATA requires AGPAIR2/M2-H1/3 and distinct CONTROL/DATA;
  AGPAIR1 remains CONTROL-only in the independent external profile.
- `frontend-mode`, root:wheel0400, exactly `bundled`+LF or `external`+LF.
- `roles/`, protected root-owned directory, containing exactly
  [the existing inspector/backend files and bounds](../../docs/milestones/M2/PRIVATE-BACKENDS.md).
  Files are root:wheel0400 in staging, then root:dedicated-inspectorGID0440.
  No credential/anchor issuer or automatic material generation is added.
- `frontend/`, bundled only, protected root-owned directory containing exactly
  `frontend-role`≤253, `frontend-listen`≤21, `public.pem`/`frontend.pem`≤81920 each,
  `inspector-root.pem`≤32768 and `server.der`/`client.der`≤16384 each, all0400.
  Role and canonical IPv4 listen text have no trailing LF. The helper compiles
  its own fixed DATA-only configuration; supplied config/owner binaries refuse.
  External mode requires this directory absent, never a fallback from a bundle.

There is no `expected`, payload archive, compiler source or image supplied to the
production entry. Package images are bounded/read twice/current-metadata checked
and matched to the independently authenticated package manifest before and after
placement. Shared executables are never replaced by commissioning. A package hash
check does not qualify loader, update custody or native runtime behavior.

Only new `/var/db/aegvium`0700 and `/etc/aegvium`0755 may be created. Existing
state refuses; there is no reset, repair, import or recovery mode. The same
existing fixed `useradd` operation creates only the unique disabled-login
`_aegvium` principal and verifies its target account databases. Bundled mode
requires the separately installed package `_haproxy`604:604 identity; it does not
create or repair it. That retained numeric package expectation needs exact8.0
package/account/drop/chroot validation.

The initializer shares `commission.InitialFiles` with the deterministic payload
encoder: `inspector.pin`, `pair.snapshot`, `launch.intent`,8192-byte AEGSEC1
`security.records` and128-byte AEGOWN1 `launch.state`, all root:wheel0600.
Together with the inspector executable those are the **six** payload members.
The existing opaque role/anchor/AGBACK1 coverage and fixed frontend material/config/
AGPAIR placement are reused. Bundled mode initializes its own empty consumed/lock
namespace and160-byte AEGFRN1 C data, with the same protected modes. Those initial
bytes grant no fresh custody, runtime admission or replacement authority.

Every created file uses exclusive/no-follow writes, bounded metadata/hash readback,
file sync and parent-directory sync. Any fault retains partial state and prevents
successful handoff; no partial target or historical data is deleted. After all
owned local file/directory closure, success emits only:

```text
AGCOMMISSION1 <32-hex-generation> <64-hex-full-descriptor-sha256> <64-hex-package.images-sha256>
```

It means observed placement, **not Ready**, service enablement, physical process
retirement, target freshness, credential validity or authority to start. The caller
still owns the original commissioning/tool process and exclusive target lifetime.

## Remaining integration and evidence

Aegvium owns its production8.0 profile, package/commission composition and setup
instructions. Bootweave is an external general-purpose installer: only reusable
schemas/extension mechanisms belong there, never Aegvium-specific dispatch,
accounts or roles. The actual generic installation job still must supply the
original target lifetime; a profile cannot issue that authority. No new concrete
profile syntax is invented before the generic schema is provided. The private
`tools/commission-owner.py` / `install.site`7.9 workflow remains historical research;
none of its ISO pins, arbitrary root-hook delivery or execution authority is
promoted to production by this ABI. No new generic installer schema is defined.

Still missing are actual native package artifacts/recursive signatures and closure,
the real Boot-owned fresh-target invocation/handoff, service ordering/enable/readback,
complete required frontend audit/health, same-appliance principal/network/key/backend
isolation, strict original-wire and inspection/backend fidelity, aggregate resource
limits, crash/recovery and mandatory four-second shutdown acceptance. The source
recipe/commission body closes an internally owned implementation gap; it provides
none of that native qualification and does not activate a service.
