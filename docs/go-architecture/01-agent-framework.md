# ADR 01: Go Agent Framework

- Status: Accepted for GO-02 implementation
- Date: 2026-11-23

## Decision

Adopt CloudWeGo Eino (`github.com/cloudwego/eino`) with selected Eino extensions (`github.com/cloudwego/eino-ext`) as the model/tool orchestration layer. Use its classic `model.BaseChatModel` / `model.ToolCallingChatModel` interfaces, `compose.ToolsNode`, component callbacks, and provider-specific model packages. Implement the review loop, completion invariants, normalized ledger, secret boundary, and skill policy in `internal/agent/`. Do not use Eino ADK's autonomous agent as the review policy authority.

Eino is the best fit because it supplies a common Go component model with OpenAI and Claude chat model extensions, tool routing, streaming, callbacks, and an MCP tool extension while leaving deterministic control with the caller. It does not make provider behavior magically uniform. GO-02 must verify retries, usage fields, prompt-cache controls, reasoning settings, custom endpoint support, and tool schemas for each chosen extension and pin tested versions. Where a provider extension lacks required controls, use its supported HTTP-client/config hooks or a narrow adapter around that extension, not a second agent framework.

| Option | Assessment |
| --- | --- |
| Eino + eino-ext | Selected. Good Go-native component interfaces and composable model, tool, callback, and MCP components. OpenAI and Claude extensions give a shared `ChatModel` surface. Extension behavior varies, so integration tests must prove required endpoint and provider features. |
| `github.com/nlpodyssey/openai-agents-go` | Has a ready agent loop, tools, tracing/usage, and MCP examples, but its OpenAI Agents SDK lineage centers OpenAI Responses semantics and its provider-agnostic support does not establish parity for Anthropic-compatible routers, cache controls, or arbitrary compatible APIs. It couples policy more tightly to a general agent runner than this review loop needs. |
| Firebase Genkit Go | Offers flows, plugins, and model abstractions, but its product surface centers Genkit flows/developer tooling. It does not provide as direct a fit for a custom hard-invariant loop plus Eino's ToolNode/MCP component integration. |
| Thin official SDKs (`github.com/openai/openai-go/v3`, `github.com/anthropics/anthropic-sdk-go`, `github.com/modelcontextprotocol/go-sdk`) | Strong protocol/client foundations, configurable clients, and streaming. They are not an integrated model/tool framework. Choosing them alone leaves orchestration, normalized usage, retry policy, caching policy, and MCP-to-tool mapping to this codebase, violating the requirement not to recreate plumbing. They remain suitable only behind a specific adapter if Eino extension coverage proves inadequate. |

## Current Failure Modes

The existing Codex session path invokes `codex exec`, reads an output file, and parses the result after process exit. An empty output is possible even when the CLI exits successfully, and the session parser can represent it as an empty findings list. Process output and provider event logs are not a reliable structured usage contract. The separate harness attempts to scrape token counts from text/JSONL and estimates cost from a local rate table, so missing fields remain unknown and provider/model aliases can be mispriced. Prompts and skills are rendered into each standalone run without an explicit provider cache policy or stable cached-prefix contract. Tool grants are rendered as prompt text; there is no authoritative tool-call event ledger proving a required tool actually ran. Codex authentication files are copied into per-session homes in the sandbox, and provider secrets are supplied in the execution environment. Container isolation limits exposure but still puts credentials in the same trust domain as model-controlled execution.

The Go implementation must treat a valid empty findings list as a legitimate answer only after structured output validation and all configured completion guards pass. It must not infer tool execution from a model request, prompt claim, or transcript text.

## Package Layout and Contracts

Keep provider and review policy types in `internal/agent`; isolate framework/provider translation in `internal/agent/eino`. Avoid leaking Eino schema types beyond the adapter boundary except where an interface explicitly wraps the framework.

```text
internal/agent/
  config.go       ProviderConfig, Protocol, RetryPolicy, PromptCache
  model.go        ModelFactory and Eino adapter construction
  loop.go         ReviewLoop, turn/tool limits, streaming, cancellation
  guards.go       CompletionGuard implementations and evidence ledger
  usage.go        TokenUsage, CostEstimate, UsageLedger
  tools.go        ToolRouter, tool grants, execution records
  mcp.go          MCP registry and server lifecycle/security boundary
  skills.go       SKILL.md loader and scoped prefix rendering
  output.go       structured result decoding and validation
  eino/           Eino model/tool/callback conversions
```

```go
type Protocol string
const (
    ProtocolOpenAI Protocol = "openai"
    ProtocolAnthropic Protocol = "anthropic"
)

type ProviderConfig struct {
    Name string
    Protocol Protocol
    BaseURL string
    APIKeyRef string // reference resolved by trusted host-side secret provider
    Model string
    ReasoningEffort string
    PromptCache PromptCache
    Retry RetryPolicy
    ExtraHeaders map[string]string
}

type PromptCache struct {
    Enabled bool
    // StablePrefix identifies system/developer content eligible for provider caching.
    StablePrefix bool
}

type RetryPolicy struct {
    MaxAttempts int
    InitialBackoff time.Duration
    MaxBackoff time.Duration
    RetryableStatusCodes []int
}

type ReviewLoop struct {
    Model model.ToolCallingChatModel
    Tools *compose.ToolsNode
    Router ToolRouter
    Guards []CompletionGuard
    Ledger *UsageLedger
    MaxTurns int
}

type CompletionGuard interface {
    Check(context.Context, ReviewEvidence) error
}

func RequireAllFilesInspected(paths []string) CompletionGuard
func RequireToolCalled(name string) CompletionGuard

type TokenUsage struct {
    Input, Output, CachedInput, Reasoning int64
    Provenance UsageProvenance
}
type CostEstimate struct {
    USD decimal.Decimal
    PriceTableVersion string
    Provenance UsageProvenance
}
```

`ModelFactory` resolves `APIKeyRef` through a trusted secret resolver and constructs the protocol-specific Eino extension with `BaseURL`, headers, model, effort, retry configuration, and an HTTP client whose proxy/TLS/timeout policy is explicit. Reject unknown protocols and malformed config at startup. Do not log resolved credentials or put them in model-visible tool environments. Cost is an estimate unless the provider supplies authoritative billed cost; retain raw provider usage and provenance alongside normalized counts. Count cached input as a subset of input exactly once when computing cost, and do not add reasoning tokens again if the provider includes them in output tokens.

`ReviewLoop.Run(ctx, request) (Result, error)` owns a deterministic bounded loop: call the model, append assistant messages, execute only registered/authorized tool calls through `ToolsNode`/`ToolRouter`, record successful executions, and continue until a valid final result or a hard error/limit. Check `ctx.Err()` between model and tool operations and pass the same context to both. Stream deltas through a caller callback or stream reader; cancellation must close readers and stop tool execution. Validate final structured output and run every guard before returning success. The `RequireToolCalled` guard checks a successful execution record keyed by canonical tool name, not an advertised or requested call. `RequireAllFilesInspected` checks host-produced evidence from the file-inspection tool, not model assertions.

Register tools from trusted host code with explicit schemas and per-tool grants. For MCP, prefer `github.com/cloudwego/eino-ext/components/tool/mcp` and its supported transport/client configuration. If the required server transport or lifecycle is not supported by the pinned extension, use `github.com/modelcontextprotocol/go-sdk` as the MCP client and wrap each discovered tool as an Eino `tool.InvokableTool`. Support stdio and the SDK/extension's verified streamable HTTP or SSE transport; do not assume all transports share the same API. MCP server processes receive only narrowly scoped per-tool credentials injected by a trusted broker at invocation time. They never inherit the runner environment, provider API key, host filesystem, or unrelated secrets. Treat tool descriptions and results as untrusted input, enforce egress and filesystem policy outside the model, and record server identity, tool name, arguments hash, result status, and duration without recording secret values.

Load skills from trusted `SKILL.md` files into a typed `Skill` with ID, scope, body, and source digest. Validate size and allowed scope, then render deterministic system-message segments. Keep the stable policy and selected skill prefix byte-stable and ahead of variable PR/repository content so provider-side cache prefix matching can work. Put provider-specific cache markers/breakpoints in the Eino adapter, since OpenAI-compatible and Anthropic-compatible APIs express caching differently. Do not claim caching from local prompt reuse. Record provider cache-read/cache-write usage when reported and leave it unknown otherwise.

## GO-02 Implementation Constraints

1. Use exact module paths: `github.com/cloudwego/eino`, `github.com/cloudwego/eino-ext/components/model/openai`, `github.com/cloudwego/eino-ext/components/model/claude`, and `github.com/cloudwego/eino-ext/components/tool/mcp`. Pin compatible versions in `go.mod` and `go.sum`; `eino-ext` is a collection of separately versioned components, not one importable root API. Inspect the pinned package's exported config before relying on fields described in moving documentation.
2. Keep protocol differences explicit. OpenAI strict JSON-schema mode requires a supported strict subset, including required properties and `additionalProperties: false` constraints. Anthropic tool schemas and structured-output capabilities differ. Validate schemas locally and translate or reject unsupported schema constructs before requests. Do not silently weaken a completion schema.
3. Set retry behavior in one layer. Avoid multiplying SDK retries by framework retries. Retry connection failures, 408, 409, 429, and selected 5xx with bounded exponential backoff and jitter; do not retry authentication/permission errors, invalid requests/schema errors, or deterministic tool failures. Honor `Retry-After`, cap attempts and total deadline, and never retry a non-idempotent tool side effect automatically.
4. Treat prompt caching as provider-specific and prefix-based. Place stable system policy and skill text before changing task content; cache breakpoints must follow provider constraints and request shape. Verify actual cached-token usage with integration tests against each configured endpoint. `PromptCache.Enabled` expresses intent, not guaranteed support.
5. Normalize streamed tool-call fragments before dispatch. Calls can arrive in chunks, with arguments split across deltas. Preserve provider call IDs when unique, synthesize a deterministic per-turn ID only when absent, and maintain an explicit provider-ID-to-canonical-ID map. Tool result messages must reference the canonical ID expected by the originating protocol. Never dispatch a call until its arguments are complete and schema-valid.
6. Normalize usage from provider response metadata/callbacks, not rendered text. Track input, output, cached input, and reasoning token values independently with reported/estimated/unknown provenance. Extension callbacks may omit usage for some providers or stream modes, so test both `Generate` and `Stream` and retain provider raw metadata for adapter fixes.
7. Test every configured provider with a local mock compatible endpoint: custom `BaseURL`, auth header, extra headers, reasoning option, retry classification, streamed tool calls, cancellation, structured output, prompt cache metadata, reported usage, and malformed/partial response behavior. Add a live provider/tool integration test proving the required tool is actually executed before a guarded empty result can succeed.

## Consequences

Eino provides the framework plumbing and shared abstractions, while application code retains hard review invariants and a testable security boundary. Provider parity is an explicit adapter contract backed by pinned integration tests. Some extension gaps may require small provider adapters, but the project does not own generic retries, streaming, MCP protocol, or prompt-cache protocol implementations.
