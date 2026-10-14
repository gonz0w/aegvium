# Runnable owned lab proxy

This is the first executable lab composition, under [LP-01–04](../../docs/milestones/M1/LAB-COMPANION.md). It has a real reverse-proxy handler and separate process, pinned Coraza/CRS, one allowlisted host/backend, bounded request/response bodies, forwarding-header stripping, separate readiness and graceful WAF cleanup. It is research code with a fixed laboratory profile.

From the repository, after preparing the existing [reviewed native profile](../../docs/milestones/M1/NATIVE-ENGINE.md):

```sh
make verify
make research-lab-proxy
```

The target rebuilds the engine test, checker and actual lab executable, launches the owned restricted OpenBSD guest, applies verified patches/reboots, runs the ordinary suite, then starts the executable/owned backend/foreground relayd TLS path. Its verifying TLS client checks benign traffic, denials, metadata stripping, bad CA/name, backend loss/recovery and companion stop with backend alive. It tears down the entire fixture/VM and writes ignored source-bound reports under `.tools/native-runs/`. The [curated result](../native/lab-proxy-observations.json) records the admitted run. No service is installed or enabled.

`make research-labproxy-cross` separately builds `.tools/research/labproxy-openbsd-amd64`. The CLI takes no arguments and refuses root, non-OpenBSD or missing `AEGVIUM_LAB_PROXY=owned-guest`. The native harness supplies that marker and manages the required peer components. There is no product configuration file/API.

Fixed path:

- `app.test` / `app.test:18120` → guest loopback relayd TLS 18120.
- Mandatory PROXY-v1 data receiver 18084 → HTTP/1.1 inspection; separate health 18085 checked by the existing restricted checker.
- One literal loopback backend 18086; no DNS or redirect following. Only admitted requests reach its application handler.
- GET/HEAD/POST, JSON/form POST, 4096-byte body/response guards, close-only responses; no upgrades or general streaming/reuse support.

The prefix's advertised identity remains untrusted and unused. Local prefixes are not authenticated; spoofed forwarding/override metadata is stripped. Backend TLS, route/config management, supported production protocol behavior, reload/recovery and resource/security acceptance remain open. Lab connection/body/deadline controls are not performance qualification. Earlier half-close findings still apply: client response absence does not establish rejection or safe retry.
