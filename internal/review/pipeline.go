package review

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/analyzer"
	"github.com/wapo-org/wapo-review/internal/browser"
	"github.com/wapo-org/wapo-review/internal/config"
	"github.com/wapo-org/wapo-review/internal/consolidator"
	"github.com/wapo-org/wapo-review/internal/gate"
	"github.com/wapo-org/wapo-review/internal/githubapp"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
	"github.com/wapo-org/wapo-review/internal/redact"
	"github.com/wapo-org/wapo-review/internal/sandbox"
	"github.com/wapo-org/wapo-review/internal/secrets"
	"github.com/wapo-org/wapo-review/internal/semantic"
	"github.com/wapo-org/wapo-review/internal/sharder"
	"github.com/wapo-org/wapo-review/internal/verifier"
	"github.com/wapo-org/wapo-review/internal/visual"
	"github.com/wapo-org/wapo-review/internal/workspace"
	"golang.org/x/sync/errgroup"
)

type ContainerFactory func(context.Context) (sandbox.Container, error)
type BrowserContainerFactory func(ctx context.Context, hostRepoDir, hostScreenshotDir string) (sandbox.Container, string, error)
type ModelFactory func(context.Context) (model.ToolCallingChatModel, error)

type Pipeline struct {
	Client                  *githubapp.Client
	TokenResolver           githubapp.TokenResolver
	LegacyToken             string
	RemoteURLOverride       string // optional override (e.g. file:// bare repo in tests)
	ContainerFactory        ContainerFactory
	BrowserContainerFactory BrowserContainerFactory
	ActiveRegistry          *sandbox.ActiveRegistry
	ProfilerCache           *graph.ProfilerCache
	Memory                  *memory.Store
	Secrets                 secrets.Adapter
	QAProfile               *secrets.QAProfile
	BrowserExecutor         browser.BrowserExecutor
	PreviewBaseURL          string
	DisableLocalBoot        bool // optional test override; false = pull PR code and boot locally by default
	DisableSpecialist       bool // optional override to skip targeted specialist second pass
	DisableSkeptic          bool // optional override to skip adversarial skeptic gate
	GateSpecs               []sandbox.GateSpec
	SkipDepInstall          bool
	Config                  config.Config
	Redactor                *redact.Redactor
	Logger                  any
	ModelFactory            ModelFactory
	VisionModelFactory      ModelFactory
	MaxShardConcurrency     int

	mu            sync.Mutex
	runs          map[string]*runState
	publishedSHAs map[string]string
}

type runState struct {
	mu                sync.Mutex
	generation        uint64
	publishedSHA      string
	publishedCheckSHA string
	publishedCheckID  int64
	in                orchestrator.ReviewInput
	pr                githubapp.PullRequest
	diffBase          string
	files             []githubapp.File
	container         sandbox.Container
	ws                *workspace.SharedWorkspace
	workRoot          string
	cfg               analyzer.RepoConfig
	head              map[string][]byte
	baseFiles         map[string][]byte
	idx               *graph.CodebaseIndex
	retriever         *semantic.Retriever
	ver               *verifier.Verifier
	specialist        specialistSummary
	sandboxPass       map[string]bool
	statics           []analyzer.Finding
	complex           []analyzer.FunctionComplexity
	gate              gate.Result
	final             consolidator.ConsolidatedResult
}

func safePRPath(workspaceDir, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || strings.Contains(filepath.ToSlash(name), "../") || name == ".." {
		return "", fmt.Errorf("unsafe PR filename %q", name)
	}
	root, err := filepath.Abs(workspaceDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err == nil {
		rel, relErr := filepath.Rel(root, resolved)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("PR filename escapes workspace")
		}
		path = resolved
	} else {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr == nil {
			rel, relErr := filepath.Rel(root, parent)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("PR filename escapes workspace")
			}
		}
	}
	return path, nil
}

var _ orchestrator.ReviewStages = (*Pipeline)(nil)

func (p *Pipeline) state(id string) *runState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runs == nil {
		p.runs = map[string]*runState{}
	}
	if p.runs[id] == nil {
		p.runs[id] = &runState{sandboxPass: map[string]bool{}}
	}
	return p.runs[id]
}

func (p *Pipeline) client(ctx context.Context, in orchestrator.ReviewInput) (*githubapp.Client, error) {
	if p.Client == nil {
		return nil, fmt.Errorf("GitHub client is required")
	}
	token, err := githubapp.ResolveToken(ctx, p.Config.GitHubAppID != "", in.InstallationID, []string{in.Repo}, p.TokenResolver, p.LegacyToken)
	if err != nil {
		return nil, err
	}
	c := *p.Client
	c.Token = token
	return &c, nil
}

func (p *Pipeline) logInfo(msg string, args ...any) {
	if l, ok := p.Logger.(interface{ Info(string, ...any) }); ok && l != nil {
		l.Info(msg, args...)
	}
}

func (p *Pipeline) PreparePR(ctx context.Context, in orchestrator.ReviewInput) (orchestrator.StageResult, error) {
	p.mu.Lock()
	old := p.runs[in.RunID]
	p.mu.Unlock()
	if old != nil {
		old.mu.Lock()
		oldContainer, oldRoot := old.container, old.workRoot
		old.container, old.workRoot = nil, ""
		old.mu.Unlock()
		if oldContainer != nil {
			_ = oldContainer.Close(context.Background())
		}
		if oldRoot != "" {
			_ = os.RemoveAll(oldRoot)
		}
	}
	s := p.state(in.RunID)
	s.mu.Lock()
	s.generation++
	generation := s.generation
	s.mu.Unlock()
	p.logInfo("stage_start", "stage", "prepare_pr", "run_id", in.RunID, "repo", in.Repo, "pr", in.PRNumber)
	c, err := p.client(ctx, in)
	if err != nil {
		return orchestrator.StageResult{}, err
	}
	pr, base, err := c.GetPullRequest(ctx, in.Repo, in.PRNumber)
	if err != nil {
		return orchestrator.StageResult{}, err
	}
	files, err := c.ListPullRequestFiles(ctx, in.Repo, in.PRNumber)
	if err != nil {
		return orchestrator.StageResult{}, err
	}

	root, err := os.MkdirTemp("", "wapo-review-")
	if err != nil {
		return orchestrator.StageResult{}, err
	}
	var container sandbox.Container = &sandbox.LocalContainer{Root: filepath.Join(root, "repo")}
	cleanup := true
	defer func() {
		if cleanup {
			if container != nil {
				_ = container.Close(context.Background())
			}
			_ = os.RemoveAll(root)
		}
	}()
	if p.ContainerFactory != nil {
		container, err = p.ContainerFactory(ctx)
		if err != nil {
			return orchestrator.StageResult{}, err
		}
	}

	// Checkout via sandbox.CheckoutRepo (ephemeral HTTP header auth, never leaks
	// token into .git/config, supports refs/pull/<n>/head fallback & merged BaseSHA).
	coRes, err := sandbox.CheckoutRepo(ctx, container, sandbox.CheckoutSpec{
		Repository: in.Repo,
		RemoteURL:  p.RemoteURLOverride,
		BaseRef:    pr.Base.Ref,
		BaseSHA:    pr.Base.SHA,
		HeadSHA:    pr.Head.SHA,
		PRNumber:   in.PRNumber,
		Merged:     pr.Merged,
		Closed:     pr.State != "open",
		Token:      c.Token,
	})
	if err != nil {
		return orchestrator.StageResult{}, err
	}
	diffBase := coRes.DiffBase
	if diffBase == "" {
		diffBase = base
	}

	// SECURITY: Load .wapo-review.yml and .gitattributes strictly from trusted
	// base branch revision via `git show`, never trusting untrusted PR head policy.
	var baseYAML, attrs []byte
	if show, err := sandbox.GitShow(ctx, container, diffBase, ".wapo-review.yml"); err == nil && show.ExitCode == 0 {
		baseYAML = []byte(show.Stdout)
	} else if show, err := sandbox.GitShow(ctx, container, diffBase, ".wapo-review.yaml"); err == nil && show.ExitCode == 0 {
		baseYAML = []byte(show.Stdout)
	}
	if show, err := sandbox.GitShow(ctx, container, diffBase, ".gitattributes"); err == nil && show.ExitCode == 0 {
		attrs = []byte(show.Stdout)
	}
	repoCfg, err := analyzer.LoadRepoConfig(baseYAML, attrs)
	if err != nil {
		repoCfg = analyzer.RepoConfig{Rules: map[string]analyzer.RuleConfig{}, Complexity: analyzer.ComplexityConfig{High: 15}}
	}

	headBytes := map[string][]byte{}
	baseBytes := map[string][]byte{}
	for i := range files {
		f := &files[i]
		path, pathErr := safePRPath(container.WorkspaceDir(), f.Filename)
		if pathErr != nil {
			// A GitHub filename can name a symlink in the checkout. Do not let a
			// symlink target outside the checkout enter the host-side PR context.
			p.logInfo("skip_unsafe_pr_file", "run_id", in.RunID, "file", f.Filename, "error", pathErr.Error())
			continue
		}
		if repoCfg.Excluded(f.Filename) {
			continue
		}
		// GitHub omits `patch` on large files or massive PRs; backfill from local git diff
		// so every shard gets exact line-numbered diffs and OnDiffLine accuracy.
		if strings.TrimSpace(f.Patch) == "" && f.Status != "removed" {
			if gd, e := sandbox.GitDiff(ctx, container, diffBase, []string{f.Filename}); e == nil && gd.ExitCode == 0 && strings.TrimSpace(gd.Stdout) != "" {
				f.Patch = gd.Stdout
			}
		}
		if info, e := os.Stat(path); e == nil && info.Mode().IsRegular() && info.Size() <= 2<<20 {
			if b, e := os.ReadFile(path); e == nil {
				headBytes[f.Filename] = b
			}
		}
		if show, e := sandbox.GitShow(ctx, container, diffBase, f.Filename); e == nil && show.ExitCode == 0 {
			baseBytes[f.Filename] = []byte(show.Stdout)
		}
	}

	ws, err := workspace.New(filepath.Join(root, "workspace"))
	if err != nil {
		return orchestrator.StageResult{}, err
	}

	s.mu.Lock()
	if s.generation != generation {
		s.mu.Unlock()
		return orchestrator.StageResult{}, fmt.Errorf("review run superseded")
	}
	s.in = in
	s.pr = pr
	s.diffBase = diffBase
	s.files = files
	s.container = container
	s.ws = ws
	s.workRoot = root
	s.cfg = repoCfg
	s.head = headBytes
	s.baseFiles = baseBytes
	s.mu.Unlock()
	cleanup = false

	p.logInfo("stage_done", "stage", "prepare_pr", "run_id", in.RunID, "files", len(files), "diff_base", diffBase)
	return orchestrator.StageResult{
		Version: 1,
		Status:  "prepared",
		Data: map[string]any{
			"head_sha":   coRes.HeadSHA,
			"diff_base":  diffBase,
			"workspace":  ws.Root,
			"file_count": len(files),
		},
	}, nil
}

func (p *Pipeline) SandboxGates(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult) (orchestrator.StageResult, error) {
	s := p.state(in.RunID)
	s.mu.Lock()
	container := s.container
	generation := s.generation
	s.mu.Unlock()
	if container == nil {
		return orchestrator.StageResult{}, fmt.Errorf("PR is not prepared")
	}

	res := map[string]any{}
	passed := map[string]bool{}
	if !p.SkipDepInstall {
		install, err := sandbox.InstallDependencies(ctx, container)
		if err != nil {
			res["install_error"] = err.Error()
			passed["install_dependencies"] = false
		} else if install != nil {
			res["install"] = install
			passed[install.ID] = install.Status == "passed"
		} else {
			passed["install_dependencies"] = true
		}
	}

	gateResults := sandbox.RunGates(ctx, container, p.GateSpecs)
	res["gates"] = gateResults
	for _, g := range gateResults {
		passed[g.ID] = g.Status == "passed"
	}

	s.mu.Lock()
	if s.generation == generation {
		s.sandboxPass = passed
	}
	s.mu.Unlock()

	return orchestrator.StageResult{Version: 1, Status: "completed", Data: res}, nil
}

func (p *Pipeline) GraphAndStatic(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult) (orchestrator.StageResult, error) {
	if err := ctx.Err(); err != nil {
		return orchestrator.StageResult{}, err
	}
	s := p.state(in.RunID)
	s.mu.Lock()
	container := s.container
	generation := s.generation
	pr := s.pr
	files := s.files
	cfg := s.cfg
	head := s.head
	baseFiles := s.baseFiles
	s.mu.Unlock()

	diff := analyzer.Diff{Files: map[string][]analyzer.LineRange{}, ChangedLines: map[string]map[int]bool{}}
	for _, f := range files {
		patchText := f.Patch
		if patchText != "" && !strings.Contains(patchText, "+++ b/") {
			patchText = "+++ b/" + f.Filename + "\n" + patchText
		}
		parsed := analyzer.ParseUnifiedDiff(patchText)
		for path, lines := range parsed.ChangedLines {
			diff.ChangedLines[path] = lines
		}
		for path, ranges := range parsed.Files {
			diff.Files[path] = ranges
		}
	}

	all := map[string][]byte{}
	_ = filepath.WalkDir(container.WorkspaceDir(), func(path string, d os.DirEntry, e error) error {
		if e != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == ".venv") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(container.WorkspaceDir(), path)
		rel = filepath.ToSlash(rel)
		if b, x := os.ReadFile(path); x == nil && len(b) < 2<<20 {
			all[rel] = b
		}
		return nil
	})

	var idx *graph.CodebaseIndex
	if p.ProfilerCache != nil {
		if _, baseIdx, err := p.ProfilerCache.SeedBase(in.TenantID, in.Repo, pr.Head.SHA); err == nil && baseIdx != nil {
			var deleted []string
			for _, f := range files {
				if f.Status == "removed" {
					deleted = append(deleted, f.Filename)
				}
			}
			idx = baseIdx.IncrementalCopy(in.TenantID, in.Repo, pr.Head.SHA, head, deleted)
		}
	}
	if idx == nil {
		idx = graph.NewCodebaseIndex(all, in.TenantID, in.Repo, pr.Head.SHA)
	}
	if p.ProfilerCache != nil {
		_ = p.ProfilerCache.Save(idx, pr.Base.SHA)
	}

	ret := &semantic.Retriever{Index: idx}
	ret.IndexFiles(all)

	statics := analyzer.RunAll(ctx, analyzer.RunInput{
		Files:     head,
		BaseFiles: baseFiles,
		Diff:      diff,
		Config:    cfg,
	})
	var complexities []analyzer.FunctionComplexity
	for path, src := range head {
		fns, _ := analyzer.ComputeComplexityFindings(path, src, baseFiles[path], cfg.Complexity, diff)
		complexities = append(complexities, fns...)
	}

	s.mu.Lock()
	if s.generation == generation {
		s.idx = idx
		s.retriever = ret
		s.statics = statics
		s.complex = complexities
	}
	s.mu.Unlock()

	p.logInfo("stage_done", "stage", "graph_and_static", "run_id", in.RunID, "parsed_files", idx.ParsedFilesCount, "static_findings", len(statics))
	return orchestrator.StageResult{
		Version: 1,
		Status:  "completed",
		Data: map[string]any{
			"finding_count": len(statics),
			"parsed_files":  idx.ParsedFilesCount,
		},
	}, nil
}

func (p *Pipeline) ReviewShards(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult) ([]orchestrator.StageResult, error) {
	s := p.state(in.RunID)
	s.mu.Lock()
	files := s.files
	idx := s.idx
	ret := s.retriever
	ws := s.ws
	container := s.container
	s.mu.Unlock()

	prs := make([]sharder.PRFile, 0, len(files))
	patches := make(map[string]string, len(files))
	prPaths := make([]string, 0, len(files))
	for _, f := range files {
		lower := strings.ToLower(f.Filename)
		isTest := strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") || strings.HasSuffix(lower, "_test.go") || strings.Contains(lower, "/tests/")
		prs = append(prs, sharder.PRFile{Path: f.Filename, Status: f.Status, Patch: f.Patch, IsTest: isTest})
		patches[f.Filename] = f.Patch
		prPaths = append(prPaths, f.Filename)
	}
	shards := sharder.ShardFiles(prs, idx, 12000)
	// On very large PRs (>10 production shards), focus LLM review turns on shards
	// containing production code rather than spending turns on pure test-only shards.
	var prodShards []sharder.Shard
	var omittedTestShards []string
	for _, sh := range shards {
		hasProd := false
		for _, f := range sh.Files {
			if !f.IsTest {
				hasProd = true
				break
			}
		}
		if hasProd {
			prodShards = append(prodShards, sh)
		} else {
			omittedTestShards = append(omittedTestShards, sh.ID)
		}
	}
	if len(prodShards) > 10 {
		shards = prodShards
	} else {
		omittedTestShards = nil
	}
	p.logInfo("stage_start",
		"stage", "review_shards",
		"run_id", in.RunID,
		"shards", len(shards),
		"omitted_test_shards", len(omittedTestShards),
	)
	if len(shards) == 0 {
		return nil, nil
	}

	out := make([]orchestrator.StageResult, len(shards))
	if p.ModelFactory == nil {
		for i, sh := range shards {
			out[i] = orchestrator.StageResult{Version: 1, Status: "skipped", Data: map[string]any{"shard": sh.ID, "files": sh.Checklist}}
		}
		return out, nil
	}

	var memNotes []memory.Note
	if p.Memory != nil {
		memNotes, _ = p.Memory.Load(in.Repo)
	}
	ver := verifier.New(container.WorkspaceDir(), prPaths, patches)
	s.mu.Lock()
	s.ver = ver
	s.mu.Unlock()

	// Seed high-signal cross-shard invariant links (shared tables / paired modules)
	// as structured leads so split invariants survive sharding into consolidation.
	if ws != nil {
		seenPairs := map[string]bool{}
		seeded := 0
		for _, sh := range shards {
			for _, link := range sh.CrossShardLinks {
				if seeded >= 10 {
					break
				}
				if link.Reason != "shared_table" && link.Reason != "paired_module" && link.Reason != "shared_status" {
					continue
				}
				a, b := link.FromFile, link.ToFile
				if a > b {
					a, b = b, a
				}
				key := a + "\x00" + b + "\x00" + link.Reason
				if seenPairs[key] {
					continue
				}
				seenPairs[key] = true
				invType := "state_machine"
				question := fmt.Sprintf("Both %s and %s were modified in this PR and share a DB table/state boundary across separate shards. Verify atomic state transitions, writer fencing, and compaction/cleanup invariants across both files.", link.FromFile, link.ToFile)
				if link.Reason == "paired_module" {
					invType = "parity"
					question = fmt.Sprintf("Both %s and %s are parallel modules modified in this PR in separate shards. Verify encoding/crypto/auth/contract parity between them.", link.FromFile, link.ToFile)
				}
				_ = ws.AppendLead(workspace.Lead{
					FromShard:     sh.ID,
					TargetFile:    link.ToFile,
					TargetSymbol:  filepath.Base(link.FromFile),
					Question:      question,
					SeverityHint:  "medium",
					InvariantType: invType,
					Evidence:      fmt.Sprintf("split_edge(%s): %s <-> %s", link.Reason, link.FromFile, link.ToFile),
				})
				seeded++
			}
		}
	}

	limit := p.MaxShardConcurrency
	if limit < 1 {
		limit = 8
	}

	runOneShard := func(runCtx context.Context, sh sharder.Shard) orchestrator.StageResult {
		m, err := p.ModelFactory(runCtx)
		if err != nil || m == nil {
			missing := make([]string, 0, len(sh.Files))
			for _, file := range sh.Files {
				missing = append(missing, file.Path)
			}
			return orchestrator.StageResult{Version: 1, Status: "skipped", Data: map[string]any{"shard": sh.ID, "error": fmt.Sprint(err), "missing_files": missing}}
		}
		reviewed := map[string]bool{}
		var revMu sync.Mutex
		acceptedFindings := 0
		rejectedFindings := 0
		var rejectedReasons []string
		tools := []tool.InvokableTool{
			verifier.NewSubmitFindingTool(ver, ws, sh.ID),
			verifier.NewMarkFileReviewedDetailedTool(func(f, _ string, _ int) {
				revMu.Lock()
				reviewed[f] = true
				revMu.Unlock()
			}),
			workspace.NewPostLeadTool(ws, sh.ID),
			workspace.NewReadLeadsTool(ws),
			workspace.NewReadSharedFindingsTool(ws),
			newSandboxReadFileTool(container),
			newSandboxGrepTool(container),
		}

		var sys strings.Builder
		sys.WriteString("You are a principal software engineer conducting a thorough, hunk-by-hunk, high-signal code review of one PR shard. ")
		sys.WriteString("Use read_file and grep to inspect full surrounding functions, sibling modules, and callers whenever a diff touches persistence, state machines, retries, auth, crypto, billing/quotas, or scheduled jobs. ")
		sys.WriteString("Systematically inspect EVERY changed hunk in EVERY checklist file for:\n")
		sys.WriteString("1. Concurrency & state-machine races (overlapping deliveries, non-atomic read-modify-write, missing revision/CAS checks, lease/slot accounting bugs on errors/refused boot, paused/cancelling/approval transitions, binding start keys to terminal/cancelling runs).\n")
		sys.WriteString("2. Retries & idempotency (replaying non-idempotent POST/mutations on 5xx or across credentials, binding invalidation/idempotency keys to wrong slice/attempt, replay protection across compaction).\n")
		sys.WriteString("3. Backwards compatibility & rollout migrations (breaking existing stored encodings, keyring/envelope parity across services, namespaces, schemas, or required env vars).\n")
		sys.WriteString("4. Platform/runtime limits & resource leaks (unbounded buffering before size checks, byte-bounded purge/compaction batches, pre-deletion upload blobs, missing cron sweeps, UTF-16/Unicode surrogate slicing).\n")
		sys.WriteString("5. Security, auth & crypto (wrong auth source on destructive actions, raw secret used instead of hashed key ID, bypassable consent/validation, injection).\n")
		sys.WriteString("Anchor architecture and implementation bugs to the actual source code file (.go, .ts, .py, etc.), not docs/*.md, unless the documentation itself contains a broken command, secret, or factual error.\n")
		sys.WriteString("IMPORTANT — Do NOT stop early after finding one bug in a file: before calling mark_file_reviewed, explicitly inspect EVERY remaining changed hunk in that file for any second distinct bug. ")
		sys.WriteString("For EVERY real, verifiable bug you find, call submit_finding with exact file, start_line, end_line, severity (critical|high|medium|low), category, concise title, concrete failure scenario + fix in body, and exact evidence_quote from the file. ")
		sys.WriteString("If you spot an invariant or parity question spanning a file outside your shard, call post_lead with target_file, invariant_type, evidence, and question. ")
		sys.WriteString("Call mark_file_reviewed for each checklist file with a brief 1-line summary of the hunks/invariants checked and hunks_checked count (batch multiple tool calls per turn).")
		if memCtx := memory.FormatContext(memNotes, "code_review", strings.Join(sh.Checklist, " "), 3000); memCtx != "" {
			sys.WriteString("\n\nRepository memory:\n")
			sys.WriteString(memCtx)
		}

		var prompt strings.Builder
		fmt.Fprintf(&prompt, "Shard %s (subsystem: %s, hunks: %d)\nChecklist files: %s\n\n", sh.ID, sh.Subsystem, sh.Hunks, strings.Join(sh.Checklist, ", "))
		if len(sh.CrossShardLinks) > 0 {
			prompt.WriteString("## Related PR files in other shards (inspect via read_file or post_lead if invariants span these files)\n")
			for _, l := range sh.CrossShardLinks {
				fmt.Fprintf(&prompt, "- %s <-> %s (%s)\n", l.FromFile, l.ToFile, l.Reason)
			}
			prompt.WriteString("\n")
		}
		if idx != nil {
			if gm := idx.FormatGraphContext(sh.Checklist, 3500); gm != "" {
				fmt.Fprintf(&prompt, "## Repo map\n%s\n\n", gm)
			}
		}
		if ret != nil {
			if sc, err := ret.RetrieveContext(runCtx, sh.Checklist, 4000); err == nil && sc != "" {
				fmt.Fprintf(&prompt, "## Related context\n%s\n\n", sc)
			}
		}
		fmt.Fprintf(&prompt, "## Line-numbered diff\n%s\n", sh.LineNumberedDiff)

		loop := &agent.ReviewLoop{
			Model:        m,
			SystemPrompt: sys.String(),
			Tools:        tools,
			Guards:       []agent.CompletionGuard{agent.RequireAllItemsCompleted(sh.Checklist)},
			MaxTurns:     30,
			MaxNudges:    2,
			Redactor:     p.Redactor,
			OnToolResult: func(rec agent.ToolRecord, ev *agent.ReviewEvidence) {
				revMu.Lock()
				if rec.Name == "submit_finding" {
					if strings.Contains(rec.Result, `"accepted":true`) {
						acceptedFindings++
					} else if strings.Contains(rec.Result, `"accepted":false`) {
						rejectedFindings++
						var vr verifier.VerifyResponse
						if json.Unmarshal([]byte(rec.Result), &vr) == nil && len(vr.Errors) > 0 {
							rejectedReasons = append(rejectedReasons, strings.Join(vr.Errors, "; "))
						}
					}
				}
				for f := range reviewed {
					ev.CompletedItems[f] = true
				}
				revMu.Unlock()
			},
		}
		res, runErr := loop.Run(runCtx, prompt.String())
		if res.Output != "" && ws != nil {
			_ = ws.WriteNote(sh.ID, res.Output)
		}
		var missingFiles []string
		revMu.Lock()
		for _, f := range sh.Checklist {
			if !reviewed[f] {
				missingFiles = append(missingFiles, f)
			}
		}
		completedCount := len(sh.Checklist) - len(missingFiles)
		revMu.Unlock()
		status := "completed"
		errStr := ""
		data := map[string]any{
			"shard":           sh.ID,
			"files":           sh.Checklist,
			"hunks":           sh.Hunks,
			"turns":           len(res.Turns),
			"findings":        acceptedFindings,
			"rejected":        rejectedFindings,
			"completed_files": completedCount,
			"missing_files":   missingFiles,
			"tokens_in":       res.Usage.InputTokens,
			"tokens_out":      res.Usage.OutputTokens,
		}
		if runErr != nil {
			status = "partial"
			errStr = runErr.Error()
			data["error"] = errStr
		}
		p.logInfo("shard_done",
			"run_id", in.RunID,
			"shard", sh.ID,
			"status", status,
			"error", errStr,
			"turns", len(res.Turns),
			"findings", acceptedFindings,
			"rejected", rejectedFindings,
			"rejected_reasons", rejectedReasons,
			"files", len(sh.Checklist),
			"hunks", sh.Hunks,
			"completed_files", completedCount,
			"missing_files", len(missingFiles),
			"tokens_in", res.Usage.InputTokens,
			"tokens_out", res.Usage.OutputTokens,
		)
		return orchestrator.StageResult{Version: 1, Status: status, Data: data}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for i, sh := range shards {
		i, sh := i, sh
		g.Go(func() error {
			out[i] = runOneShard(gctx, sh)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Automatic 1-shot recovery for any files left unreviewed by partial shards
	// (e.g., transient LLM errors or max-nudge exits) so critical files like
	// account-deletion.ts are never silently dropped.
	var recoveryMissing []string
	prByPath := make(map[string]sharder.PRFile, len(prs))
	for _, pf := range prs {
		prByPath[pf.Path] = pf
	}
	seenMissing := map[string]bool{}
	for _, r := range out {
		if mf, ok := r.Data["missing_files"].([]string); ok {
			for _, f := range mf {
				if !seenMissing[f] {
					seenMissing[f] = true
					recoveryMissing = append(recoveryMissing, f)
				}
			}
		}
	}
	stillMissing := map[string]bool{}
	if len(recoveryMissing) > 0 {
		p.logInfo("partial_shard_recovery_start", "run_id", in.RunID, "files", recoveryMissing)
		var recShards []sharder.Shard
		for start := 0; start < len(recoveryMissing); start += 2 {
			end := start + 2
			if end > len(recoveryMissing) {
				end = len(recoveryMissing)
			}
			chunk := recoveryMissing[start:end]
			var recFiles []sharder.PRFile
			var diffBuf strings.Builder
			totalHunks := 0
			for _, pth := range chunk {
				if pf, ok := prByPath[pth]; ok {
					recFiles = append(recFiles, pf)
					totalHunks += sharder.CountHunks(pf.Patch)
					if formatted := sharder.FormatLineNumberedDiff(pf.Path, pf.Patch); formatted != "" {
						fmt.Fprintf(&diffBuf, "=== %s ===\n%s\n", pf.Path, formatted)
					}
				}
			}
			if len(recFiles) == 0 {
				continue
			}
			recShards = append(recShards, sharder.Shard{
				ID:               fmt.Sprintf("recovery-%d", len(recShards)+1),
				Name:             fmt.Sprintf("recovery-%d", len(recShards)+1),
				Subsystem:        filepath.Dir(recFiles[0].Path),
				Files:            recFiles,
				Checklist:        chunk,
				LineNumberedDiff: strings.TrimRight(diffBuf.String(), "\n"),
				Hunks:            totalHunks,
			})
		}
		recOut := make([]orchestrator.StageResult, len(recShards))
		rg, rgctx := errgroup.WithContext(ctx)
		rg.SetLimit(limit)
		for i, rsh := range recShards {
			i, rsh := i, rsh
			rg.Go(func() error {
				recOut[i] = runOneShard(rgctx, rsh)
				return nil
			})
		}
		_ = rg.Wait()
		for _, r := range recOut {
			if mf, ok := r.Data["missing_files"].([]string); ok {
				for _, f := range mf {
					stillMissing[f] = true
				}
			}
		}
		out = append(out, recOut...)
		p.logInfo("partial_shard_recovery_done", "run_id", in.RunID, "recovery_shards", len(recShards), "still_missing", len(stillMissing))
	}

	var specSum specialistSummary
	if !p.DisableSpecialist {
		s.mu.Lock()
		complexities := s.complex
		s.mu.Unlock()
		fb := SpecialistFeedback{
			Complexities:    complexities,
			FindingsByFile:  map[string]int{},
			TurnsPerHunk:    map[string]float64{},
			CrossShardFiles: map[string][]string{},
			LeadTargets:     map[string]int{},
		}
		for f := range stillMissing {
			fb.TurnsPerHunk[f] = 0.01
			fb.CrossShardFiles[f] = append(fb.CrossShardFiles[f], "partial_shard_missed")
		}
		if ws != nil {
			if existing, err := ws.ReadAllFindings(); err == nil {
				fb.ExistingFindings = existing
				for _, f := range existing {
					fb.FindingsByFile[f.File]++
					boundaryText := strings.ToLower(f.Category + " " + f.Title + " " + f.Body)
					for _, signal := range []string{"boundary", "filesystem", "symlink", "exec", "redact", "resource", "http", "protocol", "redirect", "ssrf", "secret", "cookie", "auth"} {
						if strings.Contains(boundaryText, signal) {
							fb.LeadTargets[f.File]++
							break
						}
					}
				}
			}
			if leads, err := ws.ReadAllLeads(); err == nil {
				for _, l := range leads {
					if l.TargetFile != "" {
						fb.LeadTargets[l.TargetFile]++
					}
				}
			}
		}
		for i, sh := range shards {
			for _, link := range sh.CrossShardLinks {
				fb.CrossShardFiles[link.FromFile] = append(fb.CrossShardFiles[link.FromFile], link.Reason+":"+link.ToFile)
				fb.CrossShardFiles[link.ToFile] = append(fb.CrossShardFiles[link.ToFile], link.Reason+":"+link.FromFile)
			}
			if i < len(out) {
				if turns, ok := out[i].Data["turns"].(int); ok && sh.Hunks > 0 {
					ratio := float64(turns) / float64(sh.Hunks)
					for _, f := range sh.Checklist {
						fb.TurnsPerHunk[f] = ratio
					}
				}
			}
		}
		specSum = p.runSpecialistPassWithFeedback(ctx, in, prs, idx, ret, ws, ver, container, memNotes, fb)
		s.mu.Lock()
		s.specialist = specSum
		s.mu.Unlock()
	}
	p.logInfo("stage_done",
		"stage", "review_shards",
		"run_id", in.RunID,
		"shards", len(shards),
		"specialist_batches", specSum.Batches,
		"specialist_files", specSum.Files,
		"specialist_findings", specSum.Findings,
		"specialist_rejected", specSum.Rejected,
		"specialist_turns", specSum.Turns,
		"specialist_by_focus", specSum.ByFocus,
	)
	return out, nil
}

func (p *Pipeline) Consolidate(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult, _ orchestrator.StageResult, shards []orchestrator.StageResult) (orchestrator.StageResult, error) {
	s := p.state(in.RunID)
	s.mu.Lock()
	ws := s.ws
	statics := s.statics
	complexities := s.complex
	files := s.files
	sandboxPass := s.sandboxPass
	cfg := s.cfg
	container := s.container
	ver := s.ver
	idx := s.idx
	specSum := s.specialist
	s.mu.Unlock()

	var shardFindings []workspace.VerifiedFinding
	var leads []workspace.Lead
	if ws != nil {
		shardFindings, _ = ws.ReadAllFindings()
		leads, _ = ws.ReadAllLeads()
	}

	var result consolidator.ConsolidatedResult
	if p.ModelFactory != nil && len(leads) > 0 {
		if m, err := p.ModelFactory(ctx); err == nil && m != nil {
			opts := consolidator.ConsolidateAgentOptions{
				Verifier: ver,
				MaxTurns: 14,
			}
			if container != nil {
				opts.ExtraTools = []tool.InvokableTool{
					newSandboxReadFileTool(container),
					newSandboxGrepTool(container),
				}
			}
			if idx != nil {
				seenTargets := map[string]bool{}
				var targets []string
				for _, l := range leads {
					if l.TargetFile != "" && !seenTargets[l.TargetFile] {
						seenTargets[l.TargetFile] = true
						targets = append(targets, l.TargetFile)
					}
				}
				if len(targets) > 0 {
					opts.GraphContext = idx.FormatGraphContext(targets, 2500)
				}
			}
			result, _ = consolidator.ConsolidateWithAgentWithOptions(ctx, m, ws, statics, leads, opts)
		} else {
			result = consolidator.Consolidate(shardFindings, statics, leads)
		}
	} else {
		result = consolidator.Consolidate(shardFindings, statics, leads)
	}
	result.ExecutableCode = hasTestableCodeChanges(files)

	// Run fail-open adversarial failure-scenario skeptic gate on LLM findings
	// to eliminate garbled, speculative, or code-contradicted submissions while
	// keeping static analyzer findings untouched.
	var skepticDropped int
	if p.ModelFactory != nil && !p.DisableSkeptic && ws != nil {
		if allLLM, err := ws.ReadAllFindings(); err == nil && len(allLLM) > 0 {
			var extraTools []tool.InvokableTool
			repoRoot := ""
			if container != nil {
				repoRoot = container.WorkspaceDir()
				extraTools = []tool.InvokableTool{
					newSandboxReadFileTool(container),
					newSandboxGrepTool(container),
				}
			}
			skRep := verifier.RunAdversarialGate(ctx, p.ModelFactory, repoRoot, extraTools, allLLM, p.MaxShardConcurrency, p.Redactor)
			if len(skRep.Dropped) > 0 {
				droppedIDs := make(map[string]bool, len(skRep.Dropped))
				droppedDetails := make([]string, 0, len(skRep.Dropped))
				for _, d := range skRep.Dropped {
					droppedIDs[d.FindingID] = true
					droppedDetails = append(droppedDetails, fmt.Sprintf("%s (%s): %s", d.File, d.Title, d.Reason))
				}
				kept := make([]consolidator.ConsolidatedFinding, 0, len(result.Findings))
				for _, f := range result.Findings {
					if droppedIDs[f.ID] {
						continue
					}
					kept = append(kept, f)
				}
				result.Findings = kept
				skepticDropped = len(skRep.Dropped)
				p.logInfo("skeptic_done",
					"run_id", in.RunID,
					"batches", skRep.Batches,
					"kept", len(skRep.Kept),
					"dropped", skepticDropped,
					"dropped_details", droppedDetails,
					"turns", skRep.Turns,
					"tokens_in", skRep.TokensIn,
					"tokens_out", skRep.TokensOut,
				)
			} else {
				p.logInfo("skeptic_done",
					"run_id", in.RunID,
					"batches", skRep.Batches,
					"kept", len(skRep.Kept),
					"dropped", 0,
					"turns", skRep.Turns,
					"tokens_in", skRep.TokensIn,
					"tokens_out", skRep.TokensOut,
				)
			}
		}
	}

	// Combine static findings + sandbox gates + complexity into final Quality Gate.
	gateRes := gate.Evaluate(gate.Input{
		Findings:             statics,
		Complexities:         complexities,
		MaxCritical:          cfg.QualityGate.MaxCritical,
		MaxHigh:              cfg.QualityGate.MaxHigh,
		MaxNewCognitive:      cfg.QualityGate.MaxNewCognitive,
		Sandbox:              sandboxPass,
		RequiredSandboxGates: cfg.QualityGate.RequiredSandboxGates,
	})

	result.QualityGate = gateRes.Decision
	result.QualityGateSummary = gateRes.Summary
	if specSum.Batches > 0 {
		result.ShardCoverage = fmt.Sprintf("%d shards + %d specialist batches, %d verified findings, %d static findings, %d leads", len(shards), specSum.Batches, len(shardFindings), len(statics), len(leads))
	} else {
		result.ShardCoverage = fmt.Sprintf("%d shards, %d verified shard findings, %d static findings, %d leads", len(shards), len(shardFindings), len(statics), len(leads))
	}

	p.logInfo("stage_done",
		"stage", "consolidate",
		"run_id", in.RunID,
		"shard_findings", len(shardFindings),
		"final_findings", len(result.Findings),
		"static_findings", len(statics),
		"leads", len(leads),
		"skeptic_dropped", skepticDropped,
	)

	s.mu.Lock()
	s.gate = gateRes
	s.final = result
	s.mu.Unlock()

	b, _ := json.Marshal(result)
	return orchestrator.StageResult{Version: 1, Status: "completed", Data: map[string]any{"result": string(b)}}, nil
}

func hasTestableCodeChanges(files []githubapp.File) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		p := strings.ToLower(filepath.ToSlash(f.Filename))
		ext := filepath.Ext(p)
		switch ext {
		case ".md", ".txt", ".rst", ".adoc", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".lock":
			continue
		}
		if strings.HasPrefix(p, "docs/") || strings.HasPrefix(p, ".github/") {
			continue
		}
		return true
	}
	return false
}

func buildBrowserIntegrationPrompt(previewURL string, in orchestrator.ReviewInput, pr githubapp.PullRequest, files []githubapp.File, findings []consolidator.ConsolidatedFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Run change-targeted end-to-end integration tests in a real browser against %s for PR #%d in %s.\n", previewURL, in.PRNumber, in.Repo)
	if pr.Title != "" {
		fmt.Fprintf(&b, "PR title: %s\n", pr.Title)
	}
	if body := strings.TrimSpace(pr.Body); body != "" {
		if len(body) > 800 {
			body = body[:800] + "..."
		}
		fmt.Fprintf(&b, "PR description:\n%s\n", body)
	}
	b.WriteString("\nChanged code files (target user-facing flows affected by these UI, API, backend, auth, webhook, or workflow changes):\n")
	shown := 0
	for _, f := range files {
		if shown >= 40 {
			fmt.Fprintf(&b, "- ... (+%d more files)\n", len(files)-shown)
			break
		}
		fmt.Fprintf(&b, "- %s (%s)\n", f.Filename, f.Status)
		shown++
	}
	if len(findings) > 0 {
		b.WriteString("\nSuspected code-review issues to verify end-to-end if reachable from the UI:\n")
		for i, f := range findings {
			if i >= 6 {
				break
			}
			fmt.Fprintf(&b, "- [%s] %s:%d %s\n", f.Severity, f.File, f.StartLine, f.Title)
		}
	}
	b.WriteString("\nInstructions:\n")
	b.WriteString("1. Treat this as a targeted end-to-end integration test: even when the diff is backend/API-heavy, exercise the UI pages and user interactions backed by the changed endpoints/functions to confirm nothing broke and end-user behavior reflects the changes.\n")
	b.WriteString("2. Use `run_browser_check` to navigate, interact (click/fill/assert_text/assert_visible), capture screenshots at key states, and verify zero uncaught page errors, console errors, or HTTP 5xx API failures.\n")
	b.WriteString("3. Summarize which user flows you tested, what passed, and any concrete UI/API regressions observed.\n")
	return b.String()
}

func (p *Pipeline) BrowserAndVisualQA(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult) (orchestrator.StageResult, error) {
	s := p.state(in.RunID)
	s.mu.Lock()
	files := s.files
	pr := s.pr
	container := s.container
	workRoot := s.workRoot
	existingFindings := append([]consolidator.ConsolidatedFinding(nil), s.final.Findings...)
	s.mu.Unlock()

	setBrowserSummary := func(summary, visualSummary, report string) {
		s.mu.Lock()
		s.final.BrowserSummary = summary
		if visualSummary != "" {
			s.final.VisualSummary = visualSummary
		}
		if report != "" {
			s.final.BrowserReport = report
		}
		s.mu.Unlock()
	}

	if !in.UIChecks && !hasTestableCodeChanges(files) {
		msg := "skipped: docs/config-only PR (no testable application or API code changes)"
		setBrowserSummary(msg, "", "")
		p.logInfo("stage_done", "stage", "browser_qa", "run_id", in.RunID, "status", "skipped", "reason", "no_code_changes")
		return orchestrator.StageResult{Version: 1, Status: "skipped", Data: map[string]any{"summary": msg}}, nil
	}
	if p.BrowserExecutor == nil || p.ModelFactory == nil {
		msg := "unavailable: browser QA executor or model not configured"
		setBrowserSummary(msg, "", "")
		return orchestrator.StageResult{Version: 1, Status: "unavailable", Data: map[string]any{"summary": msg}}, nil
	}

	hostRepoDir := ""
	if container != nil {
		hostRepoDir = container.WorkspaceDir()
	}
	hostScreenshotDir := ""
	if workRoot != "" {
		hostScreenshotDir = filepath.Join(workRoot, "screenshots")
		_ = os.MkdirAll(hostScreenshotDir, 0o700)
	}

	browserContainer := container
	containerScreenshotDir := hostScreenshotDir
	if p.BrowserContainerFactory != nil && hostRepoDir != "" && hostScreenshotDir != "" {
		if bc, scDir, err := p.BrowserContainerFactory(ctx, hostRepoDir, hostScreenshotDir); err == nil && bc != nil {
			browserContainer = bc
			if scDir != "" {
				containerScreenshotDir = scDir
			}
			defer func() { _ = bc.Close(context.Background()) }()
		} else if err != nil {
			p.logInfo("browser_container_fallback", "run_id", in.RunID, "error", err.Error())
		}
	}

	var previewURL string
	var modeDesc string
	var defaultHeaders map[string]string
	var pinnedHostIP map[string]string
	var localBootErr error

	// DEFAULT: pull PR code (already checked out in hostRepoDir) and boot it locally inside the sandbox.
	if !p.DisableLocalBoot && browserContainer != nil && hostRepoDir != "" {
		if handle, err := browser.BootLocalApp(ctx, browserContainer, hostRepoDir); err == nil && handle != nil {
			previewURL = handle.URL
			modeDesc = "local(" + strings.Join(handle.Services, "+") + ")"
			if handle.Cleanup != nil {
				defer handle.Cleanup(context.Background())
			}
			p.logInfo("browser_local_boot_ready", "run_id", in.RunID, "url", previewURL, "services", strings.Join(handle.Services, ","))
		} else {
			localBootErr = err
			p.logInfo("browser_local_boot_fallback", "run_id", in.RunID, "error", fmt.Sprint(err))
		}
	}

	// Fallback: remote preview deployment (Vercel API -> GitHub statuses/deployments/comments -> PreviewBaseURL).
	var vercelErr error
	if previewURL == "" && p.QAProfile != nil && pr.Head.SHA != "" {
		if vURL, hdrs, err := browser.ResolveVercelPreview(ctx, p.QAProfile, pr.Head.SHA); err == nil {
			if validatedURL, ip, verr := browser.ResolvePreviewTarget(nil, nil, nil, vURL); verr == nil {
				previewURL = validatedURL
				modeDesc = "remote-preview"
				defaultHeaders = hdrs
				if u, perr := url.Parse(validatedURL); perr == nil && u.Hostname() != "" && ip != "" {
					pinnedHostIP = map[string]string{u.Hostname(): ip}
				}
			} else {
				vercelErr = verr
			}
		} else {
			vercelErr = err
		}
	}
	if previewURL == "" {
		var statuses, deployments, comments []string
		if c, err := p.client(ctx, in); err == nil && c != nil {
			statuses, deployments, comments = c.ListPreviewCandidateURLs(ctx, in.Repo, pr.Head.SHA, in.PRNumber)
		}
		resolved, ip, err := browser.ResolvePreviewTarget(statuses, deployments, comments, p.PreviewBaseURL)
		if err != nil {
			var reasons []string
			if localBootErr != nil {
				reasons = append(reasons, "local boot: "+localBootErr.Error())
			}
			if vercelErr != nil {
				reasons = append(reasons, "vercel: "+vercelErr.Error())
			} else {
				reasons = append(reasons, "remote preview: "+err.Error())
			}
			msg := "unavailable (" + strings.Join(reasons, "; ") + ")"
			setBrowserSummary(msg, "", "")
			p.logInfo("stage_done", "stage", "browser_qa", "run_id", in.RunID, "status", "unavailable", "reason", msg)
			return orchestrator.StageResult{Version: 1, Status: "unavailable", Data: map[string]any{"summary": msg}}, nil
		}
		previewURL = resolved
		modeDesc = "remote-preview"
		if u, perr := url.Parse(resolved); perr == nil && u.Hostname() != "" && ip != "" {
			pinnedHostIP = map[string]string{u.Hostname(): ip}
		}
		if p.QAProfile != nil && isVercelPreviewHost(resolved, p.QAProfile) {
			if bypass := strings.TrimSpace(p.QAProfile.Vercel["web_bypass_secret"]); bypass != "" {
				defaultHeaders = map[string]string{"x-vercel-protection-bypass": bypass}
			}
		}
	}

	var authorizedOrigin string
	if u, perr := url.Parse(previewURL); perr == nil && u.Scheme != "" && u.Host != "" {
		authorizedOrigin = u.Scheme + "://" + u.Host
	}

	m, err := p.ModelFactory(ctx)
	if err != nil {
		msg := "unavailable: " + err.Error()
		setBrowserSummary(msg, "", "")
		return orchestrator.StageResult{Version: 1, Status: "unavailable", Data: map[string]any{"summary": msg}}, nil
	}
	var memNotes []memory.Note
	if p.Memory != nil {
		memNotes, _ = p.Memory.Load(in.Repo)
	}
	cm := sandbox.NewCheckpointManager(browserContainer)
	runner := &browser.HandsOnRunner{
		Loop:             &agent.ReviewLoop{Model: m, MaxTurns: 12, MaxNudges: 2, Redactor: p.Redactor},
		Executor:         p.BrowserExecutor,
		Container:        &browserContainer,
		Checkpoint:       cm,
		Profile:          p.QAProfile,
		Memory:           memNotes,
		DefaultHeaders:   defaultHeaders,
		AuthorizedOrigin: authorizedOrigin,
		PinnedHostIP:     pinnedHostIP,
		ScreenshotDir:    containerScreenshotDir,
	}
	prompt := buildBrowserIntegrationPrompt(previewURL+" ["+modeDesc+"]", in, pr, files, existingFindings)
	res, runErr := runner.Run(ctx, prompt)

	failedSteps, consoleErrs, pageErrs, failedReqs := 0, 0, 0, 0
	var consoleList, pageList, reqList, stepErrList []string
	seenErr := map[string]bool{}
	addUnique := func(dst *[]string, s string, limit int) {
		s = strings.TrimSpace(s)
		if s == "" || seenErr[s] || len(*dst) >= limit {
			return
		}
		seenErr[s] = true
		if len(s) > 300 {
			s = s[:300] + "..."
		}
		*dst = append(*dst, s)
	}
	for _, rep := range runner.Reports {
		consoleErrs += len(rep.ConsoleErrors)
		pageErrs += len(rep.PageErrors)
		failedReqs += len(rep.FailedRequests)
		for _, e := range rep.ConsoleErrors {
			addUnique(&consoleList, e, 8)
		}
		for _, e := range rep.PageErrors {
			addUnique(&pageList, e, 8)
		}
		for _, e := range rep.FailedRequests {
			addUnique(&reqList, e, 8)
		}
		for _, sr := range rep.StepResults {
			if !sr.Passed {
				failedSteps++
				addUnique(&stepErrList, fmt.Sprintf("%s(%s): %s", sr.Step.Action, sr.Step.Target, sr.Error), 8)
			}
		}
	}
	browserSummary := fmt.Sprintf("mode=%s target=%s checks=%d screenshots=%d failed_steps=%d console_errors=%d page_errors=%d failed_requests=%d",
		modeDesc, previewURL, runner.Telemetry.BrowserCheckExecutions, runner.Telemetry.ScreenshotsCaptured, failedSteps, consoleErrs, pageErrs, failedReqs)
	if runErr != nil {
		browserSummary += " (partial: " + runErr.Error() + ")"
	}

	var reportBuf strings.Builder
	if out := strings.TrimSpace(res.Output); out != "" {
		if len(out) > 3500 {
			out = out[:3500] + "\n...(truncated)"
		}
		reportBuf.WriteString(out)
		reportBuf.WriteString("\n")
	}
	if len(pageList) > 0 {
		reportBuf.WriteString("\n**Captured page errors:**\n")
		for _, e := range pageList {
			fmt.Fprintf(&reportBuf, "- `%s`\n", e)
		}
	}
	if len(consoleList) > 0 {
		reportBuf.WriteString("\n**Captured console errors:**\n")
		for _, e := range consoleList {
			fmt.Fprintf(&reportBuf, "- `%s`\n", e)
		}
	}
	if len(reqList) > 0 {
		reportBuf.WriteString("\n**Captured failed/5xx requests:**\n")
		for _, e := range reqList {
			fmt.Fprintf(&reportBuf, "- `%s`\n", e)
		}
	}
	if len(stepErrList) > 0 {
		reportBuf.WriteString("\n**Failed browser steps:**\n")
		for _, e := range stepErrList {
			fmt.Fprintf(&reportBuf, "- `%s`\n", e)
		}
	}

	visualSummary := ""
	if p.VisionModelFactory != nil && hostScreenshotDir != "" {
		if vm, err := p.VisionModelFactory(ctx); err == nil && vm != nil {
			frames, _ := filepath.Glob(filepath.Join(hostScreenshotDir, "*.png"))
			if len(frames) > 0 {
				sheetPath := filepath.Join(workRoot, "contact-sheet.png")
				cols := min(3, len(frames))
				rows := (len(frames) + cols - 1) / cols
				if err := visual.BuildContactSheet(ctx, frames, sheetPath, cols, rows); err == nil {
					runner.Telemetry.ContactSheetCaptured = true
					vs, err := (visual.VisualScorer{Model: vm}).Score(ctx, visual.VisualScoreRequest{
						ContactSheetPath: sheetPath,
						PRSummary:        fmt.Sprintf("%s#%d: %s", in.Repo, in.PRNumber, pr.Title),
						ConsoleErrors:    consoleList,
						FailedRequests:   reqList,
					})
					if err == nil {
						visualSummary = fmt.Sprintf("score=%d/100 verdict=%s (%s)", vs.Score, vs.Verdict, vs.Summary)
					} else {
						p.logInfo("visual_score_error", "run_id", in.RunID, "error", err.Error())
						visualSummary = "unavailable (" + err.Error() + ")"
					}
				} else {
					p.logInfo("contact_sheet_error", "run_id", in.RunID, "error", err.Error())
				}
			}
		}
	}

	kept, suppressed := browser.SuppressFalseBlockers(nil, runner.Telemetry)
	setBrowserSummary(browserSummary, visualSummary, reportBuf.String())

	p.logInfo("stage_done", "stage", "browser_qa", "run_id", in.RunID, "summary", browserSummary)
	return orchestrator.StageResult{
		Version: 1,
		Status:  "completed",
		Data: map[string]any{
			"summary":            browserSummary,
			"visual_summary":     visualSummary,
			"output":             res.Output,
			"kept_blockers":      len(kept),
			"suppressed_blocker": len(suppressed),
		},
	}, nil
}

func isVercelPreviewHost(rawURL string, profile *secrets.QAProfile) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return false
	}
	if profile != nil {
		for _, key := range []string{"web_domain", "project_domain", "preview_domain"} {
			dom := strings.ToLower(strings.TrimSpace(profile.Vercel[key]))
			if dom != "" && (host == dom || strings.HasSuffix(host, "."+dom)) {
				return true
			}
		}
	}
	return false
}

func (p *Pipeline) PublishReview(ctx context.Context, in orchestrator.ReviewInput, _ orchestrator.StageResult, _ orchestrator.StageResult) (orchestrator.StageResult, error) {
	p.mu.Lock()
	if publishedSHA := p.publishedSHAs[in.RunID]; publishedSHA != "" {
		p.mu.Unlock()
		return orchestrator.StageResult{Version: 1, Status: "published", Data: map[string]any{"head_sha": publishedSHA, "idempotent": true}}, nil
	}
	p.mu.Unlock()
	s := p.state(in.RunID)
	s.mu.Lock()
	generation := s.generation
	pr := s.pr
	gateRes := s.gate
	final := s.final
	container := s.container
	workRoot := s.workRoot
	existingCheckID := s.publishedCheckID
	existingCheckSHA := s.publishedCheckSHA
	if pr.Head.SHA == "" {
		s.mu.Unlock()
		return orchestrator.StageResult{}, fmt.Errorf("publish review: missing prepared run state for run %q", in.RunID)
	}
	if s.publishedSHA != "" && s.publishedSHA == pr.Head.SHA {
		s.mu.Unlock()
		return orchestrator.StageResult{Version: 1, Status: "published", Data: map[string]any{"head_sha": pr.Head.SHA, "idempotent": true}}, nil
	}
	s.mu.Unlock()

	published := false
	cleanup := func() {
		if container != nil {
			_ = container.Close(context.Background())
		}
		if workRoot != "" {
			_ = os.RemoveAll(workRoot)
		}
		p.mu.Lock()
		if p.runs[in.RunID] == s {
			s.mu.Lock()
			if s.generation == generation {
				delete(p.runs, in.RunID)
			}
			s.mu.Unlock()
		}
		p.mu.Unlock()
	}
	defer func() {
		if !published {
			return
		}
		cleanup()
	}()
	defer func() {
		if ctx.Err() != nil {
			cleanup()
		}
	}()

	c, err := p.client(ctx, in)
	if err != nil {
		if !isRetryablePublishError(err) {
			cleanup()
		}
		return orchestrator.StageResult{}, err
	}
	checkID := existingCheckID
	if existingCheckSHA != pr.Head.SHA || checkID == 0 {
		checkID, err = gate.PublishGateCheckRun(ctx, c, in.Repo, pr.Head.SHA, gateRes)
		if err != nil {
			if !isRetryablePublishError(err) {
				cleanup()
			}
			return orchestrator.StageResult{}, err
		}
		s.mu.Lock()
		if s.generation == generation {
			s.publishedCheckID = checkID
			s.publishedCheckSHA = pr.Head.SHA
		}
		s.mu.Unlock()
	}
	formatted := consolidator.FormatPRReview(final, 25)
	if err := c.SubmitReview(ctx, in.Repo, in.PRNumber, pr.Head.SHA, formatted.Event, formatted.Body, formatted.Comments); err != nil {
		if !isRetryablePublishError(err) {
			cleanup()
		}
		return orchestrator.StageResult{}, err
	}
	s.mu.Lock()
	if s.generation == generation {
		s.publishedSHA = pr.Head.SHA
	}
	s.mu.Unlock()
	p.mu.Lock()
	if p.publishedSHAs == nil {
		p.publishedSHAs = make(map[string]string)
	}
	p.publishedSHAs[in.RunID] = pr.Head.SHA
	if len(p.publishedSHAs) > 1024 {
		for id := range p.publishedSHAs {
			if id != in.RunID {
				delete(p.publishedSHAs, id)
				break
			}
		}
	}
	p.mu.Unlock()
	published = true
	p.logInfo("stage_done", "stage", "publish_review", "run_id", in.RunID, "check_run_id", checkID, "event", formatted.Event, "inline_comments", len(formatted.Comments), "total_findings", len(final.Findings))
	return orchestrator.StageResult{
		Version: 1,
		Status:  "published",
		Data: map[string]any{
			"check_run_id":    checkID,
			"review_event":    formatted.Event,
			"inline_comments": len(formatted.Comments),
		},
	}, nil
}

func isRetryablePublishError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, status := range []string{" 400", " 401", " 403", " 404", " 409", " 422"} {
		if strings.Contains(message, "GitHub API") && strings.Contains(message, status) {
			return false
		}
	}
	return true
}

func HandleReviewCommentReply(ctx context.Context, c *githubapp.Client, store *memory.Store, e githubapp.WebhookEvent) error {
	if c == nil || store == nil {
		return fmt.Errorf("client and memory store are required")
	}
	isBotThread := e.Comment.InReplyTo > 0
	if isBotThread {
		if parent, err := c.GetPullReviewComment(ctx, e.Repository.FullName, e.Comment.InReplyTo); err == nil && parent != nil {
			if !githubapp.IsBotCommentAuthor(parent, "") {
				// Still allow explicit /remember commands on any review thread.
				if _, _, explicit := memory.ParseRememberCommand(e.Comment.Body); !explicit {
					return nil
				}
			}
		}
	}
	scope, note, ok := memory.ExtractMemoryFromReply(e.Comment.Body, isBotThread)
	if !ok {
		return nil
	}
	repo := e.Repository.FullName
	if _, err := store.Add(repo, note, scope, "github_review_reply"); err != nil {
		return err
	}
	prNum := e.PullRequest.Number
	if prNum == 0 {
		prNum = e.Issue.Number
	}
	if prNum > 0 && e.Comment.ID > 0 {
		return c.ReplyToPullReviewComment(ctx, repo, prNum, e.Comment.ID, "Noted for future reviews: "+note)
	}
	return nil
}

type readFileArgs struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type grepArgs struct {
	Pattern    string `json:"pattern"`
	Glob       string `json:"glob,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"`
}

type funcTool struct {
	name   string
	desc   string
	schema any
	fn     func(context.Context, string) (string, error)
}

func (t funcTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        t.name,
		Desc:        t.desc,
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(jsonschema.Reflect(t.schema)),
	}, nil
}

func (t funcTool) InvokableRun(ctx context.Context, raw string, _ ...tool.Option) (string, error) {
	return t.fn(ctx, raw)
}

func newSandboxReadFileTool(c sandbox.Container) tool.InvokableTool {
	return funcTool{
		name:   "read_file",
		desc:   "Read a bounded line range from a file inside the repository workspace",
		schema: readFileArgs{},
		fn: func(ctx context.Context, raw string) (string, error) {
			var in readFileArgs
			if err := json.Unmarshal([]byte(raw), &in); err != nil {
				return "", err
			}
			return sandbox.ReadFile(ctx, c, in.Path, in.StartLine, in.EndLine)
		},
	}
}

func newSandboxGrepTool(c sandbox.Container) tool.InvokableTool {
	return funcTool{
		name:   "grep",
		desc:   "Search repository files for a regex pattern",
		schema: grepArgs{},
		fn: func(ctx context.Context, raw string) (string, error) {
			var in grepArgs
			if err := json.Unmarshal([]byte(raw), &in); err != nil {
				return "", err
			}
			r, err := sandbox.Grep(ctx, c, in.Pattern, in.Glob, in.MaxMatches)
			if err != nil {
				return "", err
			}
			return r.Stdout, nil
		},
	}
}
