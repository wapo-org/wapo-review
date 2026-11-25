# Hatchet Orchestration

## Scope and run contract

Package: `internal/orchestrator/`. Replace a polling-thread and SQLite delivery queue with a durable Hatchet v1 workflow. Keep review logic behind package interfaces so implementations can be migrated incrementally. A workflow input is versioned and contains `runId`, `tenantId`, `repo` (`owner/name`), `prNumber`, trigger, optional `beforeSha`, installation reference, and requested UI-check flag. Resolve credentials at task execution through a host Infisical adapter. Never put secret values in workflow input, task output, logs, or run metadata.

## PR review workflow DAG

Workflow name `pr_review`. Dependencies are explicit; all task outputs are bounded, versioned JSON records and bulky artifacts live in the private shared run workspace (`workspace/runs/<runId>`).

```text
prepare_pr
  ├── sandbox_gates ───────────┐
  └── graph_and_static ────────┼──> consolidate ──┬──> publish_review
       (may overlap checkout)  │                  │
  review_shard[0..N-1] ────────┘                  └──> browser_qa -> visual_review
```

1. `prepare_pr` fetches GitHub PR metadata and changed-file patches, computes the incremental/full diff index and base-branch gate configuration, checks merged/closed and fork policy, skips an already-reviewed head where appropriate, creates the run manifest, and starts or updates the progress comment. It resolves the current head SHA and records the exact immutable revision used by all downstream tasks. For merged PRs use the base SHA as the gate base.
2. `sandbox_gates` checks out that head in a credential-free Podman sandbox, installs dependencies with bounded retries and diagnostic capture, and runs each applicable deterministic repository gate independently. Install or one gate failure is a structured result and does not suppress other gates or review.
3. `graph_and_static` runs after checkout is available and may overlap gates. Update the incremental `go-tree-sitter` `CodebaseIndex`, derive semantic chunks and graph context, run deterministic analyzers and the deterministic quality gate, and persist index/analyzer artifacts. Deterministic findings use the same validated finding envelope as model findings.
4. `review_shard` runs once per stable shard ID. `prepare_pr` or a planning task computes affinity-based shard inputs, then spawns N child workflow runs in bulk using the Go SDK (`Context.SpawnWorkflows` or workflow `RunMany`). Bound N and per-tenant active shards. Each child writes only its shard-owned findings/notes to the shared run workspace, with atomic/locked appends and a manifest coverage record. Inputs carry paths, complete assigned diffs, context references, and workspace/run IDs, not repository credentials.
5. `consolidate` waits for all shard children and `graph_and_static`. It validates complete required coverage, reads shard findings, leads, deterministic findings, graph context, and gate results, then runs the Consolidator Agent. It deduplicates and ranks findings, validates anchors, caps inline comments at 25, and puts remaining verified findings in a collapsible review-body overflow section. Incomplete Tier-1 coverage fails closed as an incomplete review.
6. `browser_qa` and then `visual_review` run only when UI checks are requested and the PR is eligible for a browser target. QA executes structured Playwright scenarios, optionally using Stagehand for bounded discovery, and records assertions, console/network errors, screenshots, and video. Visual review builds a bounded ffmpeg contact sheet and obtains a structured visual score/issues result. Browser unavailability is recorded as a QA result and does not erase code-review findings. These tasks may run alongside consolidation after their prerequisites; publication waits for both when requested.
7. `publish_review` creates or updates one GitHub Check Run keyed by repository, PR, and head SHA; it publishes the final conclusion and summary plus inline comments and overflow. Make publication idempotent by persisting the Check Run ID and a stable review marker before/with comment submission, then reconcile partial GitHub writes on retry. Finish the progress comment and persist the run record, task references, status, artifacts, and terminal error.

## Concurrency and fairness

Configure two workflow concurrency policies using Hatchet CEL `ConcurrencyStrategy` values. `max_runs` is 1 for the PR key and a configured worker-capacity limit for tenant groups.

```go
ConcurrencyStrategy{
    Expression: `input.repo + ":" + string(input.prNumber)`,
    MaxRuns:    1,
    Strategy:   "CANCEL_IN_PROGRESS",
}
ConcurrencyStrategy{
    Expression: `input.tenantId`,
    MaxRuns:    TenantActiveRunLimit,
    Strategy:   "GROUP_ROUND_ROBIN",
}
```

The first policy makes a newer delivery cancel the active run for that PR and supersedes both enqueue-time and claim-time SQLite push coalescing. Cancellation must propagate through `context.Context` to HTTP calls, model calls, Podman, browser processes, and artifact writers; cleanup runs before task exit. The second groups queued work by tenant and dispatches groups round-robin under the configured cap, preventing a noisy organization from occupying every available run slot. Apply a separate bounded global worker/shard capacity so fair grouping cannot exceed host resources. Keep explicit user-triggered reruns distinct through their run identity while retaining per-PR latest-head semantics.

## Retry, replay, rollback, and isolation

Use task retries with capped exponential backoff and jitter for transient GitHub 5xx/429/network errors, transient LLM provider errors, and Vercel preview/API 5xx/429/network errors. Suggested default is 3 retries, starting at 2 seconds and capped at 60 seconds, with task-specific execution timeouts. Respect `Retry-After`. Do not retry malformed payloads, missing/invalid authorization, unsupported input/schema, policy-denied fork PRs, merged/closed skips, deterministic gate failures, or validation failures. Treat expired installation credentials as one refresh followed by a non-retryable auth failure. Retry only idempotent stage boundaries; external writes use stable idempotency keys and reconcile before repeating.

Hatchet persists completed task outputs and run state. Keep each stage's inputs/outputs immutable and artifact references stable so operators can replay `consolidate` or `publish_review` from recorded upstream outputs without rerunning successful `review_shard` children or spending their LLM calls again. A failed shard can be retried independently; do not mark coverage complete until its atomic shard result is committed. On cancellation/failure, terminate sandboxes and browser processes, close temporary worktrees, and leave a manifest status that permits recovery. Keep completed artifacts private and immutable; stage retries write to temporary artifacts then atomically publish them.

Define the runtime boundary in Go:

```go
type WorkflowRunner interface {
    Start(context.Context, ReviewInput) (RunRef, error)
    Wait(context.Context, RunRef) (ReviewResult, error)
    Replay(context.Context, RunRef, ...string) error
    Cancel(context.Context, RunRef) error
}
```

`HatchetRunner` adapts the v1 client. `InProcessRunner` invokes the same typed stage handlers in dependency order with an injectable scheduler, clock, GitHub/LLM/Vercel clients, filesystem workspace, and cancellation context. Unit/eval tests then run without Postgres or Hatchet while exercising retry classification, stage contracts, replay boundaries, and cancellation. Do not mock the business stage implementations.

## Self-hosted deployment and queue migration

Run Hatchet Lite on `linux/arm64` under Podman Compose with a pinned, multi-architecture `postgres:16-alpine` image, `ghcr.io/hatchet-dev/hatchet/hatchet-lite`, and the Go worker. Persist PostgreSQL data on a private volume with health checks and backups. Expose UI/API port `8888` only behind the authenticated internal reverse proxy; expose gRPC `7077` only on the private worker network. Store Hatchet, GitHub App, LLM, Vercel, and Infisical bootstrap credentials in Infisical `vault`; inject them at process startup through the secrets adapter. Never use Hatchet Lite development mode or baked-in default credentials in production.

Budget an initial single-node allowance of 2 vCPU and 4 GiB RAM for Postgres, Hatchet Lite, and one worker, with 8 GiB recommended when concurrent sandboxes/browser tasks share the host. Resource limits and worker slots must be measured under representative shard and browser load before production sizing. Keep the Hatchet database separate from run artifacts and indexes.

Migrate without dropping queued work: deploy Hatchet and the worker first, then route new webhooks to durable workflow starts using a stable delivery idempotency key. During a bounded compatibility window, continue consuming existing SQLite rows and submit each to Hatchet with that same key; mark a row transferred only after Hatchet acknowledges the run reference. Reconcile SQLite `queued`/`running` rows and Hatchet runs by delivery ID on restart, preserving the existing three-attempt ceiling for legacy interrupted rows. Keep the old consumer available until queued/running rows reach zero and run records reconcile, then disable it and retain SQLite read-only for audit/rollback. Rollback routes new deliveries back to SQLite and leaves already-started Hatchet runs to finish or be explicitly canceled; never enqueue both paths without shared idempotency.
