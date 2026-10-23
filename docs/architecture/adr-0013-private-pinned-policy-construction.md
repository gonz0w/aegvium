# ADR0013: construct one private pinned request policy without raw logging

2026-10-22. Source-only under ADR0011/0012. Actual engine/policy execution and
native qualification remain paused; no constructor/adapter/entrypoint is enabled.

The transaction coordinator can own real request methods but lacked the
production constructor selecting its effective policy and writer resources.
The new private `newPinnedEngineOwner` source connects that constructor to the
existing owner. It has no caller directives, exclusions, filesystem or log paths.
It is compiled only with both `aegvium_engine_source` and supported Coraza
`no_fs_access` tags. No init or entrypoint calls it. Default tests import only
API/data packages and intercept construction without executing engine/CRS init.

One process-global private startup guard consumes its attempt before construction.
Copies alias that state; concurrent/repeated calls refuse without waiting or
constructing a replacement. Error/panic/invalid capabilities consume the attempt,
retain known partial references and leave unknown acquisition unproved. No
speculative Close/retry is attempted. The approved external S would own eventual
process reclamation; this is not that implementation or four-second proof.

The constructor binds Coraza3.8.1 to the embedded CRS4.25.0 filesystem and includes
recommended configuration, CRS setup and CRS rules in that order. Final explicit
overrides select On, request access On, body/memory4097, Reject, response access
Off, audit Off, a private no-output writer and debug0. Config also fixes access,
limits and debug Noop, with no-op matched-rule error callback. The outer4096
admission cap is unchanged: the engine's Reject comparison is exclusive at4097.
These source settings are not measured/effective policy acceptance.

Coraza initializes its selected audit writer even with audit Off. The private
stateless writer therefore makes Init/Write/Close resource-free and never reads,
formats or retains audit payload/configuration. Fixed registration happens only
inside the sole constructor attempt. `no_fs_access` suppresses Coraza's startup
temp-directory probe; it is not an OS confinement or universal no-files proof.
Embedded policy, normal body path, engine internals and resource use still need
separate actual-engine/native qualification.

The source pin hashes exact directives, both module Hash1 identities, fixed
filesystem/build flags, limits, writer/debug/error-callback choices. A prepared
owner requires equal private input policy-pin data before body/lease transfer.
Equality is not peer authentication, raw framing proof or permission to forward.
Positive diagnostic rule counts are uint32, range1..65535; that is no memory proof.

Existing inert outcomes now retain bounded request/generation/profile identities,
rule count, intended `OnUnqualified` and `NoBackendAttempt`, alongside fixed
faults. InspectionComplete and Recorded remain false. **M2-07/WAF-05 remain
open:** this no-output engine profile does not satisfy product log export,
retention/exhaustion, detection/enforcement or separate client/backend-effect
reporting. M2 EDD's basic redacted observations remain mandatory; richer audit is
M3. No raw rule message, query/header/body/address or configuration path is added.

The newly root-pinned CRS dependency is the previously selected v4.25.0, Apache2.
All386 retained source files matched the cached module archive byte-for-byte;
Hash1 matched existing research go.sum and cached ziphash:
`h1:tqFO1lfVpTiyWtlN618OXpZMfw+nnN0Q4///W5W+/HM=`. No fetch/install occurred.
Retain upstream license/notices for distribution. Fresh complete graph legal,
SBOM/advisory and effective-policy acceptance remain separate and unpassed.

| Pinned CRS source | SHA256 |
| --- | --- |
| coreruleset.go | 75b46053c532d09dabaae8d86040f263749f247134a32562096ad40266a4d104 |
| rules/@coraza.conf-recommended | 78ce259a1f37313c8eed9239c40025684d55cc04926ff6a9f7cc1f3281beb211 |
| rules/@crs-setup.conf.example | c7564e4112eb3d211cd76fe44d861278e9f4523592690dcb0e17c2e89e348f03 |

Frozen P01–P09 obligations are in [the source packet](../milestones/M2/POLICY-CONSTRUCTION.md).
Fake/intercepted source checks and actual binding compilation cannot qualify
TLS/raw framing/backend isolation, effective On/Reject/CRS processing, generation
lineage, native supervision, resources or the mandatory four-second shutdown.
