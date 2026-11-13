# Generated-output storage

This local rule adopts the optional read-only guard from Agent Temper revision
`1c9e9fb7e5e1152691dbc669d5f7222a7c0c377d`, outside the immutable method bundle.
Source, required small reproducers and compact text results are retained. Copies
of full test datasets, build archives and VM disks are not normal evidence.
Existing retained/native holds and cleanup approvals remain controlling.

## Allocation gates

`make storage-preflight` checks the actual `.tools` destination, including a cache
symlink target. Ordinary output has a 20 GB allocated budget, 2 GB expected peak
and a host free-space reserve after that peak of the smaller of 200 GB or 10%
of filesystem capacity. `make storage-image-preflight` requires explicit reviewed
`IMAGE_OUTPUT_BUDGET_BYTES` and `IMAGE_PEAK_BYTES`; it grants no VM authority.
These are decimal-byte local defaults, not universal Temper policy. A larger run
needs a reviewed explicit local budget before generation, not a retry override.
External run roots must be added with repeated `--output` to the Python command;
separate filesystems need separate checks. Account for concurrent peak demand.
A snapshot reserves no space; recheck before later substantial allocation stages.

The existing build/tool entry points listed by Makefile now call these gates.
Direct tool-bootstrap scripts also invoke the gate. Other direct scripts and
held native executors are not silently rewritten or activated.
The preflight never deletes old data to make a run fit. Unavailable measurements
or exceeded limits stop dependent generation. Keep one verified canonical OS
input per identity and protect all bases referenced by surviving overlays.

## Source and retention

`make storage-git-check` checks staged blobs and the current committed tree. It
rejects generated disk/media extensions and blobs above 10 MiB. Genuine source
asset exceptions need exact reviewed paths; ignore patterns alone are insufficient.
The normal source check entry invokes this guard. It does not inspect or rewrite
old Git history, and cannot prevent bytes already downloaded during checkout.

Every new run must own its temporary location, remove only its explicitly disposable
outputs after success/failure/interruption, and leave a small text receipt with
source/input identity, result, allocated output and free-space measurements.
Failed-run inputs needed for unresolved diagnosis remain held with an owner and
cleanup trigger. Never purge a whole cache, follow symlinks for deletion, delete
by age, remove active work or infer that an ignored file is disposable.
Existing VM cleanup paths and authority are unchanged; automatic cleanup of old
VMs is not implemented or authorized by this adoption. No native execution or
product acceptance follows from these portable source checks.
