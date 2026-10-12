# First native engine repeat

Profile/design preparation only. No Aegvium VM has been booted.

Reuse Nomvium's reviewed fixture provenance via an independent, checksum-verified private copy, never its active image or process. The image pin is inherited from Nomvium's tools/openbsd-image.json; it is an anyvm builder fixture, not official OpenBSD installation media. Preserve this distinction.

Read the [native packet](../../docs/milestones/M1/NATIVE-ENGINE.md) before implementing the supervisor. Image and temporary authentication material remain ignored. The first native repeat runs the research test binary only; native toolchain compilation, relayd and appliance implementation remain later outcomes.
