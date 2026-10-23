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
