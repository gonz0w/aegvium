# ADR 0005: Research TLS ownership behind stock relayd

Status: bounded research decision; product adoption proposed, not accepted.

The configured Caddy comparison showed that strict SNI/Host rejects a cross-authority request admitted by both permissive baselines. The existing relayd TLS termination path forwards plaintext plus PROXY v1 addresses, so the companion cannot establish the original SNI. Client headers cannot repair that trust gap.

Research stock relayd TCP passthrough into mandatory PROXY parsing, then Go TLS and Coraza. RelayD retains health-checked ingress and pool forwarding; the companion owns certificate inputs and per-request authority enforcement. This reduces relayd's TLS responsibilities and increases companion responsibilities. It does not prove that a two-process design is preferable to Caddy.

Alternatives remain TLS at relayd with a separately authenticated metadata channel or a source patch, per-name isolated listeners, or Caddy. Stock PROXY v1 supplies no SNI; the pinned OpenBSD v2 writer also supplies no TLS TLVs. A source patch adds an upstream maintenance obligation and is unnecessary for this experiment. Per-name listeners complicate certificate/route ownership and do not yet have a tested binding contract.

Follow the [scoped PRD/EDD/tests](../milestones/M1/TLS-PASSTHROUGH.md). No new third-party dependency or separate connector repository. Preserve the legacy profile and comparison failures. No certificate automation, installer schema, privilege-policy acceptance or live deployment.

References: [OpenBSD 7.9 relayd.conf](https://man.openbsd.org/OpenBSD-7.9/relayd.conf.5), [Go TLS listener](https://pkg.go.dev/crypto/tls#NewListener), [Go HTTP TLS request state](https://pkg.go.dev/net/http#Request), [pinned PROXY source study](../milestones/M1/RELAYD-IDENTITY.md).
