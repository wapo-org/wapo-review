# Sandbox, Browser, and Rollback Design

## 1. Host-Owned LLM Loop and Credential-Free Sandbox

### Boundary

`internal/agent` owns the model client, prompt construction, turn state, tool policy, and termination decision. `internal/sandbox` owns a short-lived Podman workspace and deterministic tool execution. The sandbox receives only the checked-out source, bounded tool inputs, and no model or service credentials. Model requests and tool RPCs are separate host-side operations. The sandbox cannot call the model directly.

This removes Codex CLI from the container execution path. It therefore removes the root/node artifact-directory `EACCES` failure under `--cap-drop=all`, removes the need to mount `codex-key` or configure Codex inside the container, and prevents untrusted repository code from co-existing with LLM keys. The host retains credentials and sends only narrowly scoped results to the model. Never pass credentials as container environment variables, files, command arguments, or inherited process environment.

### Sandbox API

Expose a typed request/response interface with a fixed tool enum and validated arguments. Initial tools are `read_file(path, range?)`, `grep(query, paths?, limit)`, `list_files(path?, depth?, limit)`, `git_diff(base?, path?)`, `git_show(revision, path?)`, `run_gate(gate_id)`, and `run_browser_check(scenario_id)`. Resolve paths under the checkout root, reject traversal and symlink escapes, cap result counts and bytes, and return structured status, exit code, duration, stdout, stderr, and truncation metadata. Tool output is untrusted input to the LLM.

Run Podman operations through `exec.CommandContext` with a deadline derived from the caller's `context.Context`. Drain stdout and stderr concurrently into independently bounded tail buffers so a full pipe cannot deadlock execution. Return an explicit timeout/cancel status, terminate the process group, then force-remove the container. Register each created container before any fallible post-create step and defer cleanup immediately. Cleanup must run on ordinary return, panic, cancellation, SIGINT, and SIGTERM; signal handling cancels the root context and waits for cleanup with a bounded grace period. A process-wide startup reaper handles containers left by host termination. Cleanup errors are logged without credentials and do not replace the original tool result.

### Gates and Diagnostics

Represent each language/toolchain gate as data with an id, command, applicable-file predicate, timeout, and output cap. Detect applicable ecosystems from manifests and lockfiles, then execute each gate independently. A dependency-install or lockfile-consistency failure is a normal failed gate result. It must not prevent static analysis, source review, or other independent gates. Normalize known package-manager usage boilerplate, including `npm error Usage:` blocks, while retaining the actionable lockfile diagnostic and bounded output tail. Distinguish missing runtime, install failure, command failure, timeout, and cancellation in machine-readable results. Do not convert a failed gate into a failed agent turn.

## 2. Turn Checkpoints and Rollback

Model each agent turn as a transaction over a versioned workspace. Before a mutating tool or browser action, record the last clean checkpoint id, workspace revision, browser state reference, and completed-step journal. A checkpoint is committed only after the tool result passes structural validation and the agent loop accepts the resulting state. Repeated identical action failures or exhausted per-tool/turn budgets stop that branch and restore the last clean checkpoint; they must not trigger an unbounded retry loop.

Use a Git worktree or filesystem overlay as the primary source checkpoint. Worktrees provide clear diffs and cheap branchable states where Git is available. An overlay/snapshot fallback is needed for untracked or non-Git workspaces. File-by-file copies are a recovery/export format, not the primary transactional mechanism, because partial restoration and symlink handling are harder to make atomic. Restore by switching to a recorded immutable revision or atomically replacing the overlay; never replay inverse edits guessed from tool output.

Browser checkpoints pair the workspace checkpoint with a Playwright `storageState` snapshot, current URL, viewport, and a stable landing-DOM summary. Save state after successful navigation or a validated action boundary. Since storage state does not capture in-memory application state, rollback recreates the browser context from storage state and navigates to the recorded URL, then verifies a small set of DOM anchors before resuming. If verification fails, return to the most recent earlier browser checkpoint or restart the scenario from its declared entry point.

Treat Stagehand `observe()` as read-only planning evidence, `act()` as a mutation requiring a pre-action checkpoint and post-action verification, and `extract()` as a bounded observation. Persist a step journal containing action intent, observed target, result, URL, checkpoint id, and artifact references. For a failed or ambiguous action, restore before trying a different action. Limit retries per action and total recovery attempts. Browser rollback cannot undo external side effects such as sent messages or third-party writes; scenarios must use disposable/test accounts and idempotent actions, and report an irreversible side effect as a terminal scenario failure.

## 3. Browser and Visual QA

### Driver and Runner

Use a structured Playwright runner (`review-check` v2 contract) as the default for PR previews and locally booted apps. It provides deterministic scenario code, explicit assertions, stable step labels, structured console/page/request errors, storage-state isolation, and predictable screenshots/video. Stagehand is useful as an optional agent-assisted discovery layer when selectors or workflows are unknown. Constrain it to the same tool budget, checkpoint protocol, and Playwright context; convert discovered flows into structured scenarios before treating them as repeatable QA. Do not make autonomous Stagehand actions the sole completion evidence.

Support two targets behind one `run_browser_check` interface: an authorized PR preview and an isolated local app boot. The local app receives only an allowlisted application configuration and test credentials, runs in a restricted network/container, and has no access to host or model credentials. The browser harness has only the credentials required for its scenario. Start inspection at the landing DOM: capture URL, title, visible headings, primary controls, and a bounded accessibility/DOM summary before following a task flow. This gives a useful result even when scenario-specific selectors fail.

### Completion and Blockers

Enforce `hands_on` in the Go loop as a completion invariant. The loop cannot return a completed review until `run_browser_check` has been invoked at least once and produced a structured result. A missing browser runtime, inaccessible preview, or unavailable test account is recorded as the check's result and may make the check incomplete, but must not silently satisfy the invariant. Permit one configured alternate-consumer fallback, such as local boot after preview access failure or preview after local boot failure, and record which target ran. Do not retry the same unavailable target indefinitely.

Blocker presentation is server-owned. Suppress false `browser_runtime`, `development_preview`, and `test_account` blockers when Chromium actually started or a valid contact sheet exists, even if a model-generated payload claims access was blocked. Preserve real blockers when neither condition is true. Derive this from runner telemetry and validated artifacts, never from LLM text alone.

### Secrets, Memory, and Artifacts

Expose a scoped, read-only `vault` tool through a host `SecretsAdapter` backed by Infisical. The model may list permitted names and request a value only by approved key; it must not enumerate unrestricted secret stores or write secrets. Apply a hard denylist for administrator, infrastructure, signing, deployment, source-control, database, and service-token keys after any allow-prefix check. Build per-run aliases for `secrets.fill(locator, alias)` so scenario code receives a value only at the input boundary. Redact all known secret values from tool output, logs, traces, screenshots metadata, model-visible errors, and final findings before persistence or display. Redaction is mandatory and tested with exact, encoded, and multiline values. Do not claim 100% redaction for data that was never registered as secret; fail closed when a registered secret cannot be redacted.

Keep repository memory isolated by repository identity and version it separately from source changes. Memory may guide navigation and conventions but cannot override system/tool policy, credential rules, or the completion invariant. Validate memory as untrusted input, cap its size, and record provenance. Store model/provider selection as explicit per-repository configuration and test that concurrent repositories cannot share or overwrite it.

Generate a 4x3 contact sheet from at most twelve labeled browser checkpoints, using `ffmpeg` with fixed scaling and pixel/byte limits. Send the sheet to a vision model for a bounded score and concise visual issues; keep browser assertions as the source of functional pass/fail. Retain screenshots, video, contact sheets, and traces under a private run directory created `0700`, with files `0600`; reject symlinks and public export unless explicitly configured. Enforce size and retention limits, redact textual metadata, and delete expired artifacts.

Optionally run base and head through the same isolated browser scenario and compare matching steps, console/page errors, failed requests, accessibility results, and selected performance metrics. Keep this sequential when memory or shared test data requires it. Optional OTLP or AppMap capture may associate route/handler call paths with scenario step labels. Bound trace bytes and span count, redact attributes before retention, and treat missing instrumentation as unavailable evidence rather than a failed review.

## 4. Go Package Contracts

- `internal/sandbox` owns Podman lifecycle, path-safe file/Git tools, bounded command execution, and cleanup.
- `internal/gates` owns ecosystem detection, independent gate scheduling, normalized diagnostics, and structured gate results.
- `internal/agent` owns host-side model turns, tool dispatch, retry budgets, checkpoint selection, and the `hands_on` completion invariant.
- `internal/browser` owns Playwright contexts, preview/local target adapters, landing-DOM inspection, storage-state checkpoints, structured scenario reports, and alternate-target policy.
- `internal/visual` owns contact-sheet generation, vision scoring schemas, private artifact retention, optional base/head diffs, and trace capture.
- `internal/secrets` owns the read-only Infisical adapter, key policy, aliases, and centralized redaction. No sandbox package imports or receives this package's credentials.

All cross-package results are versioned structs with bounded strings/arrays and explicit status enums. Tests should cover cancellation and signal cleanup, panic cleanup, pipe saturation, traversal/symlink rejection, out-of-sync lockfiles with continued static analysis, checkpoint restoration after failed browser actions, false-blocker suppression, secret denylist/redaction, and private artifact modes.
