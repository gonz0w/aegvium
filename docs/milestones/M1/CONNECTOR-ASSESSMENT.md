# Consolidated connector assessment

Status: authorized bounded source/evidence research under existing #15; architecture recommendation proposed for review.

CA-01 (PRD, M1-01/03/05): compare the already pinned coraza-caddy v2.6.2 integration with measured Aegvium relayd/companion fixtures. Produce a connector/privilege recommendation and explicit native adoption gates, rather than another isolated parser experiment. No runtime adoption, new module dependency, connector repository or installer schema.

CA-02 (EDD): resolve the documented tag to its existing immutable commit; retrieve an allowlisted ten-file source subset through the upstream GitHub API, verify Git blob identity and retain SHA-256/size/function anchors. Existing LICENSE/go.mod hashes must match previous pins. Review request errors/replay, response phases/hijack/flush, transaction cleanup, identity and reload ownership. Separate declared modules from loaded/native dependencies and distinguish source claims from Aegvium measurements. Keep upstream code in ignored cache; publish fingerprints and paraphrased findings only.

CA-03 (Test Design): verify all selected blobs and function anchors, prior pin agreement and all cited local evidence hashes. Reconcile current README/architecture/research guidance so the old HTTP-first research direction is explicitly superseded by a proposed TCP-first comparison direction. Run make verify, preserve all historical native reports byte-for-byte, and verify contributor signatures/DCO from a clean candidate. No new Go/native run is claimed for documentation/source review; Caddy native build, comparative resource/phase/trust behavior and full #15 acceptance remain open.

CA-04 (decision/rollback): the proposed ADR must identify relayd's concrete role, responsibilities a custom companion assumes, alternatives and evidence needed to reject the recommendation. Adoption is withheld while critical gaps remain. Do not treat merged component studies or this proposal as acceptance of a runnable service. Rollback removes/revises the recommendation and source assessment without altering historical evidence or dependencies.
