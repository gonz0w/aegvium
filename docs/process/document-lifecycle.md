# Document lifecycle

Markdown beside code is canonical. PRD states operator outcomes; EDD defines
implementation, authority, state and failure behavior; TDD means Test Design
Document and maps stable requirement IDs to evidence. ADR records a durable
decision and its consequences. Research supplies dated primary evidence; a spike
answers a bounded question with disposable fixtures.

Milestones progress Proposed, Researching, Draft, Review, Approved, Implementing,
Validating, Released, Superseded. Record an explicit maintainer acceptance with
its date and source/PR; do not infer design approval from a request to start setup.
The user has approved research setup; runtime design acceptance and stability before personal use remain explicit gates.

Each active implementation milestone has linked approved PRD/EDD/TDD documents.
Update living docs with behavior. Superseded documents link their successors.
Use [templates](../templates/PRD_TEMPLATE.md) without treating them as approval.
