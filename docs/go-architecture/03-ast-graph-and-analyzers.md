# AST, Code Graph, Retrieval, and Deterministic Analysis

## Scope and package boundaries

Implement parsing, indexing, retrieval, deterministic analysis, and gate evaluation as independent Go packages. Parsing emits immutable per-file artifacts. `internal/graph` consumes those artifacts and owns repository-wide relationships. `internal/semantic` selects source chunks for model context. `internal/memory` supplies bounded, scoped repository notes. `internal/analyzer` produces deterministic findings and metrics. `internal/gate` evaluates base-branch policy and publishes one completed check result. No package executes repository code.

## AST runtime and grammar registry

Use `github.com/tree-sitter/go-tree-sitter` with CGO for production. It is the upstream Go binding, provides the current Tree-sitter API, and uses generated language binding modules, avoiding a forked runtime and a monolithic grammar bundle. This host is `aarch64` (`linux/arm64`); neither `gcc` nor `clang` is installed or discoverable on `PATH`. The build/deploy image must therefore install an ARM64 C toolchain (GCC is sufficient), set `CGO_ENABLED=1`, and compile the pinned grammars for the target architecture. Add an ARM64 CI build and a startup/build diagnostic that reports the missing compiler clearly.

`github.com/smacker/go-tree-sitter` is a viable fallback when a single module with bundled grammars is operationally preferred. It also depends on C/CGO, and its bundled runtime and grammar release cadence make API and grammar version updates less modular. Do not use it as a second production parser. Pure-Go/WASM approaches remove the C compiler requirement but add a runtime/grammar ABI and packaging boundary. The available `github.com/malivvan/tree-sitter` + wazero implementation is explicitly pre-release. WASM can be retained as an isolated portability experiment, not the default for low-latency indexing until it meets the same corpus, incremental-parse, memory, and latency tests.

Pin upstream grammar Go modules in `go.mod` and expose them only through `internal/ast`'s registry:

| Language | Grammar module | Extensions |
| --- | --- | --- |
| JavaScript | `github.com/tree-sitter/tree-sitter-javascript/bindings/go` | `.js`, `.jsx`, `.mjs`, `.cjs` |
| TypeScript | `github.com/tree-sitter/tree-sitter-typescript` TypeScript grammar | `.ts` |
| TSX | `github.com/tree-sitter/tree-sitter-typescript` TSX grammar | `.tsx` |
| Python | `github.com/tree-sitter/tree-sitter-python/bindings/go` | `.py`, `.pyi` |
| Go | `github.com/tree-sitter/tree-sitter-go` Go grammar | `.go` |
| Rust | `github.com/tree-sitter/tree-sitter-rust/bindings/go` | `.rs` |
| Java | `github.com/tree-sitter/tree-sitter-java/bindings/go` | `.java` |

Keep one parser per worker, not one shared mutable parser. A file artifact contains the grammar/version identifier, source digest, parse error ranges, byte/row ranges, extracted declarations/imports/calls, and serialized syntax-independent facts. Use byte offsets internally and convert to one-based line/column only at API boundaries. Unsupported extensions and parse errors are non-fatal and observable. Exclude generated/vendor files before parsing using existing repository exclusion policy. Grammar upgrades must pass checked-in cross-language fixtures before updating pins.

## Incremental codebase graph (`internal/graph`)

Build a `CodebaseIndex` from a sorted file list and per-file AST artifacts. Index stems once as `stem -> []path`, then resolve each parsed import against that map and language-specific path rules. Candidate expansion is proportional to indexed stems plus import tokens and matching candidates, not every source/import pair. Never scan every repository file with a regex for each import. Retain unresolved external imports as module identifiers rather than fabricating file edges.

Maintain adjacency/reverse-adjacency maps for imports and calls, symbol-name and qualified-symbol maps, file-to-symbol lists, test-to-target and target-to-test maps, strongly connected import components, and bounded co-change counts. Resolve call edges by lexical scope and symbol identity when unambiguous; record unresolved callee names separately. Detect cycles with Tarjan or Kosaraju in `O(V+E)`. Detect tests via language/framework naming conventions and AST references, with an explicit uncertain/unmapped state. Co-change statistics are advisory, based on capped commit file sets, and never determine correctness.

Parse only changed files against the closest cached base index. Seed PR head from the exact `base_sha` index when available; otherwise load the nearest retained ancestor or build the base snapshot once. Apply additions, replacements, and deletions before recomputing only affected import/name reverse edges and affected SCC regions where practical. Start with full linear graph finalization after incremental parsing if simpler; it remains bounded and avoids re-reading/re-parsing unchanged blobs. Target under one second for a warm-cache PR with a small diff on a 2,000-file repository. Benchmark cold parse separately, report file count, bytes, cache hit, parse duration, graph duration, and query latency.

Persist versioned index artifacts by `(tenant_id, repo_id, commit_sha)` under a private state directory. Include schema version, grammar versions, and content digests in cache validation. Key isolation must be enforced in storage paths and query authorization. Write to a same-directory temporary file, fsync, then atomic rename. Use per-key singleflight plus a process-safe lock around cache publication; readers see either the old complete artifact or the new complete artifact. Bound retention per repository (initial default 20 SHAs) and by total bytes, evict least-recently-used unpinned entries, and preserve active base/head SHAs. Corrupt or stale entries are cache misses.

Expose a host-side, concurrent-safe `query_graph` service to Go agents, not a whole-index JSON dump in each container. Requests name a tenant/repo/commit plus a query kind (`symbols`, `callers`, `callees`, `imports`, `importers`, `tests`, `cycles`, `neighbors`, `cochange`) and bounded arguments (`name`, `path`, `depth`, `limit`). Return a typed, schema-versioned response with truncation metadata. Enforce identity scope, request/result size caps, context cancellation, read-only access, and per-index `RWMutex` protection. Cache immutable snapshots so queries avoid holding locks while serializing. Agent tools should request targeted slices and never receive source text unless a separate authorized retrieval request asks for it.

## Semantic retrieval and repository memory

`internal/semantic` chunks source at AST function, method, class, interface, and module boundaries. Preserve exact source ranges and a small declaration/import preamble for standalone context. Oversized chunks split at nested declaration or statement boundaries with stable parent/part identifiers. Attach path, language, symbol name/signature, exported status, changed-line overlap, and graph identifiers. Fall back to bounded line chunks only when parsing fails.

Rank retrieval using a deterministic weighted combination of BM25 over identifiers, comments, and path tokens; exact symbol and signature matches; graph neighborhood (imports, callers/callees, tests, bounded depth); and changed-file/changed-line proximity. Deduplicate overlapping chunks and enforce caller-supplied token/character budgets, returning scores and reason codes. Keep lexical and graph retrieval fully available without network access. When configured, an OpenAI-compatible embeddings adapter may add semantic similarity: configure endpoint/model/credential outside repository data, batch and rate-limit requests, cache vectors by provider/model/content digest, and fall back cleanly on timeout or provider error. Never send repository code to an embedding provider unless deployment configuration explicitly enables it.

`internal/memory` stores tenant/repository-scoped notes with stable IDs, scope, source, timestamps, and redacted text. Match relevant notes by scope and lexical relevance to the PR/query, then cap both note count and total context budget. Preserve operator-authored notes over inferred notes; support deduplication and bounded retention. Memory is advisory context and cannot suppress deterministic findings or alter gate policy.

## Deterministic analyzers (`internal/analyzer`)

All analyzers consume AST facts and base/head snapshots and produce stable findings with rule ID, severity, message, evidence range, fingerprint, and confidence/provenance. Findings must be deterministic for identical source and analyzer versions. Apply generated/vendor exclusions before analysis. A rule may emit a blocking finding only when its AST conditions establish the claimed behavior; uncertain cases are omitted or emitted as non-blocking informational diagnostics.

**Cognitive Complexity.** Implement the Sonar Cognitive Complexity specification over AST nodes, per function, including nesting increments for structural flow, boolean-operator sequence changes, recursion, language-specific constructs, and exclusion of nested function bodies from their parent's score. Track language-specific function boundaries and qualified names. Compare base/head functions by stable symbol identity and structural matching, then report added/modified/renamed/unchanged deltas. Compatibility acceptance is `r >= 0.98` against the pinned SonarCloud comparison corpus and exact `76 == 76` on `snapshot.ts`. Keep the corpus and expected values versioned, and reject grammar/analyzer updates that miss either threshold.

**Logic checks.** Remove regex-based source-wide conclusions. Use AST structure and scoped bindings for nullability, guards, bounds, resource use, error handling, concurrency, and security checks. Recognize short-circuit path guards and negation chains. In particular, `!!user && !user.deleting` guards the dereference, and `row && !row.deleted` guards `row.deleted`; neither may produce a null-dereference or dead-branch finding. Traverse nested type ASTs so `{cursor?: string | undefined}` is treated as an optional property type, not confused with a nullable runtime value. For destructured default parameters, model the bound parameter as defaulted/non-undefined at function entry, while tracking nullable fields within the destructured object separately. Emit null-dereference findings only where the same binding is proven nullable and a path to the dereference lacks a dominating guard. Add the PR #66 examples and variants as permanent regression fixtures.

Additional deterministic scanners are separate rule families:

- Secrets scan changed and relevant existing files with high-precision token/credential patterns, entropy checks, allowlists, and redacted evidence. Never include secret values in findings, logs, caches, or check annotations.
- Supply-chain and manifest-diff analysis parses recognized manifests and lockfiles, classifies dependency additions/upgrades/removals, scripts, sources, and integrity changes. Do not equate a lockfile-only formatting change with a dependency change.
- CI/IaC analysis parses supported workflow, container, and infrastructure formats and checks explicit dangerous permissions, unpinned actions/images, exposed secrets, and unsafe deployment settings.
- Dead-code analysis uses language-aware reachability and exported/public entry-point rules. Report only provably unreachable local declarations or branches; avoid whole-repository name-only unused-symbol claims.
- Duplicate/clone detection tokenizes normalized ASTs, excludes generated/vendor material, and reports new-code clone pairs with ranges and a configurable minimum size.
- Contract/schema scanning parses supported API, database, serialization, and schema definitions, compares base/head compatibility, and reports concrete breaking changes with both locations.

## Quality gate and Check Run (`internal/gate`)

Load `.wapo-review.yml` from the base branch as the authoritative policy for the PR, with schema validation, bounded size, safe defaults, and explicit setup-error behavior. Never allow head-branch config changes to weaken the gate evaluating that same PR. Resolve the base snapshot from the merge base when the event before-SHA is unavailable or not an ancestor. Reuse existing new-code semantics: evaluate new findings, coverage/duplication when configured and available, deterministic gate outcomes, and complexity regressions. Report missing optional metrics as skipped/error according to base policy; infrastructure/setup failures follow configured policy and default to neutral/non-blocking. Keep issue severity and policy evaluation separate from agent/model claims.

Assemble one immutable report, redact sensitive data, then publish or complete the Check Run atomically from the caller's perspective. Use a stable external ID derived from repository, head SHA, and check name for idempotency. Publish one conclusion (`success`, `failure`, or `neutral`), concise condition summary, and bounded annotations. Retry transient API errors with idempotency protection; never publish a partial report as complete. If publishing fails, persist a redacted retry record and return an operational error without changing the analyzed gate result.

## Required acceptance checks

- ARM64 CGO build and parser smoke tests succeed in the production image with the installed compiler; absence of compiler is detected before deployment.
- Fixture tests cover all seven language/grammar modes, malformed syntax, byte/line mapping, declarations, imports, and calls.
- Import graph construction has no per-import scan over all files. Benchmarks cover 2,000-file cold and warm PR snapshots, graph queries, and incremental changed/deleted files.
- Concurrent readers and cache writers observe complete versioned snapshots; tenant/repository keys cannot cross-read; eviction respects pinned base/head entries.
- Retrieval tests verify chunk boundaries, hybrid ranking, graph neighbors, hard context budgets, deterministic no-embedding fallback, and provider timeout fallback.
- Analyzer corpus enforces Sonar parity and exact `snapshot.ts` score; Logic Checks includes the stated PR #66 cases, nested object types, and destructured defaults.
- Gate tests prove base-branch config selection, merge-base fallback, redaction, idempotent atomic publication, and configured setup/metric failure semantics.
