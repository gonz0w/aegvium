# Codex model routing profile

Select this optional profile when a project uses Codex subagents and benefits from
assigning different models to different tasks. It supplements the
[method](../METHOD.md) and [workflow](../docs/reference/workflow.md). It does not
require Codex for other projects or select itself merely by being copied.

## Record the local selection

Project policy must identify the selected roles, model and reasoning settings,
fallbacks, resource limits, and who may change them. Record the tested Codex client
and the evidence for role discovery and model selection in the adoption work item.
Keep local agent configuration outside the immutable framework bundle.

The following routes are starting defaults. They are project choices informed by
[OpenAI model guidance](https://learn.chatgpt.com/docs/model-selection), not measured
Agent Temper performance results. Check availability in the actual client/account.

| Role | Appropriate assignment | Model | Effort |
| --- | --- | --- | --- |
| `temper_workflow` | Bounded inspection, issue summaries, evidence collection | `gpt-6-luna` | `medium` |
| `temper_product` | Documentation, visual inspection, bounded browser tasks, small specified UI fixes | `gpt-6.1-terra` | `medium` |
| `temper_implementer` | Accepted implementation, tests, ordinary debugging | `gpt-6.1-sol` | `high` |
| `temper_analyst` | Ambiguous requirements, architecture, difficult debugging or review | `gpt-6-astra` | `high` |
| `temper_reviewer` | Separate examination of the final change and evidence | `gpt-6.1-sol` | `high` |

Route by difficulty and consequence. A routine summary can use the workflow role;
scope, permission, acceptance, and release decisions remain with the authorized
lead or owner. A stronger model does not grant decision authority. A complex review
can use an analyst who did not author the change, with the same review requirements.

The product role supplements the existing routes. Use it for accepted product-facing
work with supplied facts, clear requirements, and observable acceptance. Keep
substantial implementation with the implementer and ambiguous design with the
analyst. Product work still needs the project's separate final review. If Terra
or its required tools are unavailable, the lead may assign the bounded task to
`temper_implementer` with Sol/high under the same permissions and resource limits.
Record the fallback explicitly; setting a spawn model does not override a named
role file. The product role does not change models or delegate its own fallback.

Check Terra access in the intended client/account. OpenAI documents Codex CLI
0.159.0 or newer for Terra; desktop support depends on the client and workspace.
See [current client guidance](https://learn.chatgpt.com/docs/models). Model access
does not install tools or grant browser, desktop, or external-write permissions.

The lead coordinates work, checks returned evidence, and owns integration. This
profile does not select the primary chat's model. The project may use its current
lead model or record a different choice through its normal configuration process.

## Delegate bounded work

Delegate when an independent task or specialist examination justifies the handoff
cost. Keep tiny or tightly coupled work with the lead. Do not require every role
on every issue. One lead assigns nonoverlapping write ownership or isolated copies.

Each assignment must supply:

- The work item and relevant discussion, purpose, scope, and non-goals.
- Applicable policy and profile paths, relevant files or source revision, and facts
  the agent needs when it does not inherit conversation history.
- Acceptance, expected output, checks, allowed edits, and ownership boundaries.
- The chosen role and settings, stop/escalation conditions, and any task budget.

The agent returns concrete findings or changes, evidence references, actual check
outcomes, and unresolved limits. It must distinguish observation from inference.
It reports to the lead; tracker updates and integration stay with the lead unless
explicitly delegated. A reviewer must not review its own implementation as the
required separate review. An agent review is not independent human assurance.

## Escalate deliberately

If the task exceeds its brief, required policy conflicts, or evidence is insufficient,
the agent returns the gap to the lead. For ambiguous design or repeated failed
attempts, the lead should narrow the question or assign the analyst before spending
another attempt on the same approach. Preserve failed evidence and the original
acceptance. Do not raise effort, change models, or spawn recursive helpers without
the project's delegated authority and resource limits.

If a model or role is unavailable, record that outcome and use a recorded suitable
fallback. Without one, the lead may do the bounded work itself only if its current
model and permissions meet project requirements and resource limits. Otherwise,
resolve the missing choice with the authorized decision maker. Never silently
substitute a model or claim that a requested model actually ran.

## Apply Codex settings without changing authority

For local Codex clients, place project roles in `.codex/agents/` as standalone TOML
files with `name`, `description`, and `developer_instructions`. Set both `model`
and `model_reasoning_effort`. A role file's explicit settings take precedence over
spawn settings, agent defaults, and inherited values. See the
[Codex subagent contract](https://learn.chatgpt.com/docs/agent-configuration/subagents).

Keep routing instructions in the agent entry point and role configuration in the
local TOML files. Instructions guide role selection; their presence does not prove
that a role was invoked. Observe the actual spawn/configuration evidence.

Roles inherit the parent's sandbox, approval settings, provider, and MCP servers.
Instructions to avoid edits do not create a separate read-only sandbox. No role
may bypass project checks, review, access controls, or owner decisions. Model
routing does not authorize spending, release, deployment, or external communication.

Client and account support can differ. If a runtime exposes explicit spawn model
settings but cannot load project roles, record an equivalent local mapping before
using it. If a history-preserving spawn cannot override the model, use a fresh
agent with the complete brief when supported, or follow the fallback policy. Do
not assume these configuration files control hosted chat or every agent backend.

## Verify use and evaluate benefit

Check configuration syntax, then exercise the selected roles on bounded work in
the intended client. Record requested role/model/effort separately from observed
runtime settings. Use client metadata when available; an agent's self-description
is not proof. If metadata is unavailable, report model selection as unverified.
Do not mistake a TOML parse or a successful answer for runtime routing verification.

Before claiming savings, compare representative completed work against the
project's previous approach. Include lead and subagent usage, elapsed time,
failed attempts, review corrections, and acceptance quality. Mark unavailable
cost or usage data explicitly. Smaller models and parallel work can reduce some
costs while extra context, retries, and coordination increase others. Keep the
lightest arrangement that meets the project's evidence and quality requirements.

Recheck the selected settings when updating the client, changing models, or
adopting an upstream revision. Follow the
[composition and update rules](../docs/reference/extensions.md); a new upstream
model recommendation never silently replaces local policy.
