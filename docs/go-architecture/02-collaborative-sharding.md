# Collaborative Review Sharding

## Goal and operating constraints

Replace size-only batching and post-hoc finding rejection with parallel, auditable review. Every changed production file must receive full Tier-1 review, each finding must be verified while the agent can still repair it, and a single consolidator must own final comment selection and deduplication.

The live baseline on the 267-file stacked PR #66 is the acceptance case: 10–14-file shards skimmed files at roughly 2–3 seconds per file and found 5 LLM issues versus CodeRabbit's 41, including 23 major issues. Size-only sorting separated `webhook.ts`, `webhookRoute.ts`, and `http.ts` into `shard_1`, `shard_8`, and `shard_14`, resulting in three comments for one root bug. Post-hoc validation silently dropped real findings whose line/evidence did not match verbatim. The design below addresses all three failures.

## 1. Subsystem-affinity sharder

Package: `internal/sharder/`.

1. Build a graph over changed production files. Add weighted edges for same-directory proximity, import/dependency relationships, shared exported/imported symbols, and statically detected call edges. Partition connected/high-affinity groups first. Directory membership is a prior, not a hard boundary: import/call edges can join directories. Thus the `webhook.ts` -> `webhookRoute.ts` -> `http.ts` call chain remains one affinity group and one shard.
2. Pack whole affinity groups into shards, splitting a group only when its combined diff exceeds the configured context/token budget. Prefer 4–6 production files per shard; never split a directly connected call-chain group merely to satisfy the preferred count. A single oversized file remains its own shard and receives the full-file read path.
3. Give each production file its complete line-numbered diff and Tier-1 review instructions. Do not silently truncate a production diff. If context limits prevent a complete shard, subdivide by affinity and explicitly record the coverage exception for orchestration to retry. Tier-2 files are assigned after Tier-1 grouping and do not displace production coverage. Tier-3 files follow configured deterministic checks.
4. For PRs with at most six changed files, use a single-shard fast path with the same line-numbered diffs, checklist, and verification tools. Do not omit Tier-1 checks because the PR is small.
5. The shard loop gets only its assigned files and read-only repository/graph access. It must call `mark_file_reviewed(file, summary)` once per assigned production file. The server accepts the call only for a file assigned to that shard and records the summary atomically. A shard is complete only when every assigned Tier-1 file is marked reviewed and its review summary is non-empty. Missing files trigger another focused pass or a failed/incomplete run, never a successful partial review.

```go
type Shard struct {
    ID          string
    Files       []string // stable, sorted paths
    DiffByFile  map[string]string // complete line-numbered diff
    Checklist   map[string]*FileReview
    AffinityIDs []string
}

type FileReview struct {
    Assigned bool
    Reviewed bool
    Summary  string
    ReviewedAt time.Time
}

type ShardPlan struct {
    RunID string
    Shards []Shard
    FastPath bool
    Coverage map[string]string // path -> shard ID
}
```

The sharder is deterministic for the same input graph and configuration. Stable path ordering and stable shard IDs make retries and artifact comparison reproducible.

## 2. Live `submit_finding` verification

The agent submits each candidate as a tool call rather than returning a findings array for later filtering. JSON Schema for the tool input:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["rule_id", "file", "line", "evidence", "failure_scenario", "suggestion", "confidence", "linear_issue", "linear_quote"],
  "properties": {
    "rule_id": {"type": "string", "minLength": 1},
    "file": {"type": "string", "minLength": 1},
    "line": {"type": "integer", "minimum": 1},
    "evidence": {"type": "string", "minLength": 10, "maxLength": 600},
    "failure_scenario": {"type": "string", "minLength": 20, "maxLength": 500},
    "suggestion": {"type": ["string", "null"], "maxLength": 300},
    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    "linear_issue": {"type": ["string", "null"]},
    "linear_quote": {"type": ["string", "null"], "maxLength": 1000}
  }
}
```

Inside the agent loop, verification is synchronous and ordered: (1) `rule_id` is known and permitted for this review; (2) normalized `file` is in this run's `DiffIndex` and assigned to this shard; (3) `line` exists on the diff's new side; (4) `evidence` matches the indexed line or consecutive lines using whitespace-normalized matching; if the evidence matches elsewhere in the same file, return the nearest valid line as a correction; (5) `confidence` is `high` or `medium` for acceptance; `low` remains a correctable rejection; (6) if a rule or issue claim requires Linear evidence, `linear_issue` is a valid issue identifier and `linear_quote` matches fetched issue text after Markdown/whitespace normalization. Enforce per-shard and per-run caps after verification, and deduplicate accepted candidates by canonical rule, path, and anchored line.

Accepted calls append the canonical finding and return `{"accepted":true,"finding_id":"...","file":"...","line":43}`. Rejections return structured tool content immediately, for example `{"accepted":false,"reason":"evidence_not_found","hint":"Line 43 in diff is: verifyWebhook(request)"}`. Stable reason codes include `unknown_rule`, `file_not_in_shard`, `line_not_in_diff`, `evidence_not_found`, `low_confidence`, `linear_quote_unverified`, `duplicate`, and `over_cap`. For a line mismatch, the response includes the nearest evidence-matching line when available. The agent must correct and resubmit while its source context is active. Rejections are visible in run telemetry and never silently erase an otherwise substantive candidate.

## 3. Shared workspace and leads

Package: `internal/workspace/`. One isolated root per review run, shared read/write by shard goroutines and read by the consolidator:

```text
workspace/runs/<run_id>/
  manifest.json
  findings/<shard_id>.jsonl
  leads.jsonl
  notes/<shard_id>.md
  deterministic.jsonl
```

`manifest.json` records run/PR identifiers, base and head revisions, shard assignments, expected Tier-1 coverage, and artifact schema version. Each accepted finding is one JSON object per line in that shard's file. Deterministic findings use the same canonical finding envelope and include their rule/source identifier. Notes are append-only per shard and contain concise context, not candidate findings.

Tool input schema for both `post_lead` and a lead returned by `read_leads`:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["from_shard", "target_files", "related_symbols", "hypothesis", "severity_hint", "evidence_ref"],
  "properties": {
    "from_shard": {"type": "string", "minLength": 1},
    "target_files": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}},
    "related_symbols": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
    "hypothesis": {"type": "string", "minLength": 12, "maxLength": 1000},
    "severity_hint": {"type": "string", "enum": ["critical", "high", "medium", "low", "unknown"]},
    "evidence_ref": {"type": "object", "additionalProperties": false, "required": ["file", "line", "finding_id"], "properties": {"file": {"type": "string"}, "line": {"type": "integer", "minimum": 1}, "finding_id": {"type": ["string", "null"]}}}
  }
}
```

`post_lead` verifies the source shard, evidence path and line against the run's diff index, assigns an immutable lead ID and timestamp, then appends atomically. `read_leads` returns leads visible to the caller, optionally filtered by target path or unresolved status; shard agents may only read and follow up, while the consolidator may mark a lead resolved with a finding reference or a dismissal reason. A concrete hypothesis can be: “Check whether caller in `http.ts` enforces body size before calling `verifyWebhook`.” Leads carry a hypothesis, not an asserted finding.

## 4. Dedicated consolidator

Package: `internal/consolidator/`. It starts after all shard workers terminate or are explicitly timed out. It reads every shard finding stream, every lead, every deterministic finding, and the coverage/validation telemetry from the manifest. It fails the run as incomplete if expected production coverage is missing.

The consolidator groups semantically equivalent findings across files and shards, checks related call-chain files and high-priority open leads using read-only repository and graph tools, and verifies any newly emitted finding through the same `DiffIndex` checks. A merged root-cause comment has one authoritative changed-line anchor and names all affected files/lines in its body. It drops duplicates, unsupported claims, low-value style observations, and leads that do not resolve to actionable evidence. It ranks remaining comments by severity, reachability/exploitability or user impact, confidence, and changed-line relevance, with stable tie-breaking.

Emit at most 25 GitHub inline comments. If more verified actionable items remain, place the overflow in one collapsible `<details>` block in the review body, including each item's file and line. Preserve finding markers and metadata needed for idempotent posting. The limit applies to inline comments, not to hiding verified overflow.

## 5. Data model and concurrency

Canonical Go types shared by the packages:

```go
type Finding struct {
    ID string `json:"id"`
    RunID string `json:"run_id"`
    ShardID string `json:"shard_id"`
    RuleID string `json:"rule_id"`
    File string `json:"file"`
    Line int `json:"line"`
    Evidence string `json:"evidence"`
    FailureScenario string `json:"failure_scenario"`
    Suggestion *string `json:"suggestion"`
    Confidence string `json:"confidence"`
    LinearIssue *string `json:"linear_issue"`
    LinearQuote *string `json:"linear_quote"`
    Source string `json:"source"` // model or deterministic rule ID
    CreatedAt time.Time `json:"created_at"`
}

type EvidenceRef struct {
    File string `json:"file"`
    Line int `json:"line"`
    FindingID *string `json:"finding_id"`
}

type Lead struct {
    ID string `json:"id"`
    FromShard string `json:"from_shard"`
    TargetFiles []string `json:"target_files"`
    RelatedSymbols []string `json:"related_symbols"`
    Hypothesis string `json:"hypothesis"`
    SeverityHint string `json:"severity_hint"`
    EvidenceRef EvidenceRef `json:"evidence_ref"`
    Status string `json:"status"` // open, resolved, dismissed
    ResolutionRef *string `json:"resolution_ref"`
    CreatedAt time.Time `json:"created_at"`
}

type Workspace struct {
    Root string
    mu sync.Mutex
    fileLocks map[string]*sync.Mutex
}
```

Each shard owns one findings file and one notes file; `leads.jsonl` is the only multiply-appended artifact. `Workspace.AppendFinding` serializes writes under the per-file mutex, encodes one complete JSON object plus newline, and writes it in one locked operation. `post_lead` takes the workspace mutex across ID allocation and append so IDs and records cannot race. Use a temporary file plus atomic rename for manifest/status snapshots. Never share mutable maps or slices between goroutines; pass immutable shard inputs and return results by value. Build the final consolidated set only after `WaitGroup.Wait`. Protect lead status updates with the workspace mutex and rewrite through temp-file/rename, or store lead state in a transactional embedded database if concurrent resolution is introduced. Initialize locks before starting workers. Propagate cancellation through `context.Context`; a canceled shard cannot mark coverage complete.

The required race test runs multiple shard goroutines appending findings and leads, then validates JSONL record counts, unique IDs, complete records, and coverage state under `go test -race`.
