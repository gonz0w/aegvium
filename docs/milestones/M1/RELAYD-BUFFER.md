# Bounded buffered-request wake diagnostic

Status: authorized research follow-up to [inspection stream](RELAYD-STREAM.md). Hypothesis, not installed-source attribution or supported runtime policy.

## PRD

RB-01: retain all thirty existing expectations. Compare the existing denied/benign and benign/benign pipelines with a control that sends an extra CRLF only after consuming the first response. Add each control in direct/relayd arms, expanding connected admission to thirty-four leaves. Require unchanged two-response/status and exact backend assertions; retain every failed baseline case.

RB-02: bind the source hypothesis to the already-pinned official discovery snapshot and keep it distinct from the installed binary's unknown build lineage.

## Source hypothesis

The pinned discovery source parses a header section, emits it, resets HTTP state and re-enables reading. Its tail invokes a pending callback for buffered input only when that callback differs from the HTTP header reader. A bodyless GET remains on the header reader. This suggests that an already-buffered next GET might wait for fresh readable data rather than being drained immediately. The body-content reader has a different callback transition. This is a static control-flow inference, consistent with earlier observations; it is not proof of the installed daemon's mechanism or a finding against every relayd version. See [source fingerprint](../../../research/relayd/buffer-source.json) and its exact discovery links. No upstream source is copied into Git or changed.

## EDD

Use the same isolated VM, stock daemon/profile, inspection tap and synthetic backend. The new wake controls submit both requests in one write, consume the first response, then write CRLF before reading the second response. Successful write counts/hashes, consumed stream snapshots and backend counts remain retained. Extra CRLF is a diagnostic stimulus, not an application workaround or support policy. Direct controls may already have processed the second request; preserve any resulting write failure rather than suppressing it.

Keep the six-second exchange deadline, byte/event caps, one-/three-second baseline profiles and native cleanup. Fixed marker counts remain diagnostic only. No relayd patch, changed timeout, dependency or product configuration is introduced.

## Test Design

Direct/relayd wake denied/benign requires 403/200 and exactly one benign backend receipt; wake benign/benign requires 200/200 and exactly two. Original thirty cases keep their assertions. Current admission guards reject omission of a new wake case. Host connected skip remains; native engine admission remains twenty separate cases. Native run uses signed clean source, local verification, patched/rebooted owned guest, nonroot fixture, foreground daemon cleanup, VM teardown and source/base invariance.

## Limits and rollback

A successful wake sample supports a buffered-read hypothesis but does not establish where bytes waited, exact installed source, complete parser safety or a safe production repair. Do not relax baseline admission, publish an upstream bug report or adopt a connector from this result. TLS/identity, broader corpus, full CRS and provenance remain open. Dispose of the owned guest; no live services or networks change.
