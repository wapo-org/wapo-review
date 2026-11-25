package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/hatchet-dev/hatchet/sdks/go"
	"github.com/wapo-org/wapo-review/internal/agent"
	"github.com/wapo-org/wapo-review/internal/branding"
	"github.com/wapo-org/wapo-review/internal/browser"
	"github.com/wapo-org/wapo-review/internal/config"
	"github.com/wapo-org/wapo-review/internal/githubapp"
	"github.com/wapo-org/wapo-review/internal/graph"
	"github.com/wapo-org/wapo-review/internal/logging"
	"github.com/wapo-org/wapo-review/internal/memory"
	"github.com/wapo-org/wapo-review/internal/orchestrator"
	"github.com/wapo-org/wapo-review/internal/redact"
	"github.com/wapo-org/wapo-review/internal/review"
	"github.com/wapo-org/wapo-review/internal/sandbox"
	"github.com/wapo-org/wapo-review/internal/secrets"
	_ "modernc.org/sqlite"
)

var (
	version    = "v2-go"
	runnerName = "local"
)

func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": branding.ProductName,
			"version": version,
			"runner":  runnerName,
		})
	})
}

type ServerConfig struct {
	WebhookSecret  string
	WebhookSecrets []string
	AppMode        bool
	BotLogin       string
	Runner         orchestrator.WorkflowRunner
	Client         *githubapp.Client
	TokenResolver  githubapp.TokenResolver
	LegacyToken    string
	Memory         *memory.Store
	OAuth          *githubapp.OAuthHandler
}

func NewServer(c ServerConfig) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", healthHandler())
	mux.Handle("GET /health", healthHandler())

	webhook := githubapp.WebhookHandler{
		Secret:   c.WebhookSecret,
		Secrets:  c.WebhookSecrets,
		AppMode:  c.AppMode,
		BotLogin: c.BotLogin,
		HandleError: func(e githubapp.WebhookEvent) error {
			switch e.Name {
			case "pull_request":
				switch e.Action {
				case "opened", "reopened", "synchronize", "ready_for_review":
				default:
					return nil
				}
				n := e.PullRequest.Number
				if n < 1 || c.Runner == nil {
					return nil
				}
				// Coalesce by repo:pr so a newer push cancels an in-flight stale run.
				rid := fmt.Sprintf("%s:%d", e.Repository.FullName, n)
				tenant := strings.Split(e.Repository.FullName, "/")[0]
				if tenant == "" {
					tenant = "default"
				}
				_, err := c.Runner.Start(context.Background(), orchestrator.ReviewInput{
					Version:        1,
					RunID:          rid,
					TenantID:       tenant,
					Repo:           e.Repository.FullName,
					PRNumber:       n,
					Trigger:        "pull_request:" + e.Action,
					InstallationID: e.Installation.ID,
				})
				if err != nil {
					log.Printf("start review for %s#%d: %v", e.Repository.FullName, n, err)
				}
				return err
			case "issue_comment":
				if e.Action != "created" {
					return nil
				}
				n := e.Issue.Number
				if n < 1 || c.Runner == nil {
					return nil
				}
				rid := fmt.Sprintf("%s:%d", e.Repository.FullName, n)
				tenant := strings.Split(e.Repository.FullName, "/")[0]
				if tenant == "" {
					tenant = "default"
				}
				_, err := c.Runner.Start(context.Background(), orchestrator.ReviewInput{
					Version:        1,
					RunID:          rid,
					TenantID:       tenant,
					Repo:           e.Repository.FullName,
					PRNumber:       n,
					Trigger:        "issue_comment",
					InstallationID: e.Installation.ID,
					UIChecks:       strings.Contains(strings.ToLower(e.Comment.Body), " ui"),
				})
				if err != nil {
					log.Printf("start review for %s#%d: %v", e.Repository.FullName, n, err)
				}
				return err
			case "pull_request_review_comment":
				if e.Action != "created" || c.Client == nil || c.Memory == nil {
					return nil
				}
				cli := *c.Client
				if tok, err := githubapp.ResolveToken(context.Background(), c.AppMode, e.Installation.ID, []string{e.Repository.FullName}, c.TokenResolver, c.LegacyToken); err == nil && tok != "" {
					cli.Token = tok
				}
				return review.HandleReviewCommentReply(context.Background(), &cli, c.Memory, e)
			}
			return nil
		},
	}

	mux.Handle("POST /github", webhook)
	mux.Handle("POST /webhook", webhook)
	mux.Handle("POST /webhooks/github", webhook)
	if c.OAuth != nil {
		mux.Handle("GET /auth/github/login", c.OAuth)
		mux.Handle("GET /auth/github/callback", c.OAuth)
		mux.Handle("GET /auth/me", c.OAuth)
		mux.Handle("POST /auth/logout", c.OAuth)
	}
	return mux
}

func parseRSAPrivateKeyBytes(pemBytes []byte) (*rsa.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, nil
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := anyKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

func loadGitHubAppPrivateKey(cfg config.Config) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(cfg.GitHubPrivateKeyPEM) != "" {
		normalized := strings.ReplaceAll(cfg.GitHubPrivateKeyPEM, `\n`, "\n")
		return parseRSAPrivateKeyBytes([]byte(normalized))
	}
	if strings.TrimSpace(cfg.GitHubPrivateKeyPath) != "" {
		b, err := os.ReadFile(cfg.GitHubPrivateKeyPath)
		if err != nil {
			return nil, err
		}
		return parseRSAPrivateKeyBytes(b)
	}
	return nil, nil
}

func overlayVaultSecrets(ctx context.Context, cfg *config.Config) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("WAPO_REVIEW_SECRETS_ADAPTER")))
	fallback := os.Getenv("WAPO_REVIEW_VAULT_FALLBACK") == "1"
	if mode != "vault" && !fallback {
		return
	}
	vaultBin := os.Getenv("WAPO_REVIEW_VAULT_BIN")
	if vaultBin == "" {
		vaultBin = "vault"
	}
	adapter := secrets.VaultCLIAdapter{Binary: vaultBin}
	fill := func(dst *string, key string) {
		if strings.TrimSpace(*dst) != "" {
			return
		}
		if v, err := adapter.Get(ctx, key); err == nil && strings.TrimSpace(v) != "" {
			*dst = strings.TrimSpace(v)
		}
	}
	fill(&cfg.GitHubAppID, "GITHUB_APP_ID")
	fill(&cfg.GitHubPrivateKeyPEM, "GITHUB_APP_PRIVATE_KEY_PEM")
	fill(&cfg.GitHubAppWebhookSecret, "GITHUB_APP_WEBHOOK_SECRET")
	fill(&cfg.GitHubWebhookSecret, "GITHUB_WEBHOOK_SECRET")
	fill(&cfg.GitHubAppClientID, "GITHUB_APP_CLIENT_ID")
	fill(&cfg.GitHubAppClientSecret, "GITHUB_APP_CLIENT_SECRET")
	fill(&cfg.GitHubAppCallbackURL, "GITHUB_APP_CALLBACK_URL")
	fill(&cfg.GitHubAppSessionSecret, "GITHUB_APP_SESSION_SIGNING_SECRET")
	fill(&cfg.GitHubAppBotSlug, "GITHUB_APP_BOT_SLUG")
	fill(&cfg.HatchetClientToken, "HATCHET_CLIENT_TOKEN")
}

func defaultModelFactory(cfg config.Config) (review.ModelFactory, string) {
	if len(cfg.Providers) == 0 {
		return nil, "none"
	}
	names := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	chosen := cfg.Providers[names[0]]
	if p, ok := cfg.Providers["default"]; ok {
		chosen = p
	}
	desc := fmt.Sprintf("%s/%s@%s", chosen.Protocol, chosen.Model, chosen.BaseURL)
	return func(ctx context.Context) (model.ToolCallingChatModel, error) {
		return agent.NewModel(ctx, agent.ProviderConfig{
			Protocol:        chosen.Protocol,
			BaseURL:         chosen.BaseURL,
			APIKey:          chosen.APIKey,
			Model:           chosen.Model,
			ReasoningEffort: chosen.ReasoningEffort,
			PromptCache:     chosen.PromptCache,
			Timeout:         chosen.Timeout,
		})
	}, desc
}

func run(args []string) error {
	flags := flag.NewFlagSet("wapo-review", flag.ContinueOnError)
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("%s\n", version)
		return nil
	}
	command := "serve"
	if flags.NArg() > 0 {
		command = flags.Arg(0)
	}
	switch command {
	case "health":
		return http.ListenAndServe(":8080", healthHandler())
	case "serve", "review":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		credPath := os.Getenv("WAPO_REVIEW_CREDENTIALS_PATH")
		cfg, err := config.LoadUnvalidated(os.LookupEnv, credPath)
		if err != nil {
			return err
		}
		overlayVaultSecrets(ctx, &cfg)
		if err := cfg.Validate(); err != nil {
			return err
		}

		stateDir := cfg.StateDir
		if stateDir == "" {
			stateDir = ".wapo-review"
		}
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return err
		}
		indexDir := cfg.IndexDir
		if indexDir == "" {
			indexDir = filepath.Join(stateDir, "indexes")
		}
		memDir := cfg.MemoryDir
		if memDir == "" {
			memDir = filepath.Join(stateDir, "memory")
		}

		db, err := sql.Open("sqlite", filepath.Join(stateDir, "queue.sqlite"))
		if err != nil {
			return err
		}
		defer db.Close()

		red := redact.New()
		red.Register(
			cfg.GitHubToken,
			cfg.GitHubWebhookSecret,
			cfg.GitHubAppWebhookSecret,
			cfg.GitHubPrivateKeyPEM,
			cfg.GitHubAppClientSecret,
			cfg.GitHubAppSessionSecret,
			cfg.HatchetClientToken,
		)
		for _, p := range cfg.Providers {
			red.Register(p.APIKey)
		}
		logger := logging.New(os.Stderr, "info", red)

		var tokenResolver githubapp.TokenResolver
		if cfg.GitHubAppID != "" {
			rsaKey, err := loadGitHubAppPrivateKey(cfg)
			if err != nil {
				return fmt.Errorf("load GitHub App private key: %w", err)
			}
			if rsaKey != nil {
				tokenResolver = githubapp.NewInstallationTokenCache(cfg.GitHubAppID, rsaKey, "", nil)
			}
		}

		var oauthHandler *githubapp.OAuthHandler
		if cfg.GitHubAppClientID != "" && cfg.GitHubAppClientSecret != "" && cfg.GitHubAppCallbackURL != "" && cfg.GitHubAppSessionSecret != "" {
			oauthHandler = &githubapp.OAuthHandler{
				Config: githubapp.AppConfig{
					ClientID:      cfg.GitHubAppClientID,
					ClientSecret:  cfg.GitHubAppClientSecret,
					CallbackURL:   cfg.GitHubAppCallbackURL,
					SessionSecret: cfg.GitHubAppSessionSecret,
				},
			}
		}

		registry := sandbox.NewActiveRegistry()
		memStore := memory.NewStore(memDir)
		client := &githubapp.Client{}
		modelFactory, providerDesc := defaultModelFactory(cfg)

		var qaProfile *secrets.QAProfile
		if credPath != "" {
			legacyEnv := map[string]string{}
			if b, err := os.ReadFile(credPath); err == nil {
				var raw map[string]any
				if json.Unmarshal(b, &raw) == nil {
					for k, v := range raw {
						if s, ok := v.(string); ok && s != "" {
							legacyEnv[k] = s
						}
					}
				}
			}
			for _, kv := range os.Environ() {
				if k, v, ok := strings.Cut(kv, "="); ok {
					legacyEnv[k] = v
				}
			}
			if p, err := secrets.LoadQAProfile(filepath.Join(filepath.Dir(credPath), "qa-profile.json"), legacyEnv); err == nil {
				qaProfile = p
				for _, secretVal := range p.KnownValues() {
					red.Register(secretVal)
				}
			}
		}

		var browserContainerFactory review.BrowserContainerFactory
		sandboxImage := strings.TrimSpace(os.Getenv("WAPO_REVIEW_SANDBOX_IMAGE"))
		if sandboxImage == "" {
			for _, cand := range []string{"localhost/wapo-review-sandbox:sol-ui-4", "localhost/wapo-review-sandbox:latest"} {
				if exec.Command("podman", "--cgroup-manager=cgroupfs", "image", "exists", cand).Run() == nil {
					sandboxImage = cand
					break
				}
			}
		}
		if sandboxImage != "" {
			img := sandboxImage
			browserContainerFactory = func(bctx context.Context, hostRepoDir, hostScreenshotDir string) (sandbox.Container, string, error) {
				pc, err := sandbox.NewPodmanContainerWithConfig(bctx, sandbox.PodmanConfig{
					Image:         img,
					CgroupManager: "cgroupfs",
					Network:       "slirp4netns:allow_host_loopback=false",
					Memory:        "6g",
					CPUs:          "4",
					PidsLimit:     1024,
					User:          "root",
					WorkspaceDir:  "/workspace/repo",
					Volumes: []string{
						hostRepoDir + ":/workspace/repo",
						hostScreenshotDir + ":/tmp/wapo-screenshots",
					},
					Labels: map[string]string{"app": "wapo-review-browser-qa"},
				}, registry)
				if err != nil {
					return nil, "", err
				}
				return pc, "/tmp/wapo-screenshots", nil
			}
		}

		pipe := &review.Pipeline{
			Client:                  client,
			TokenResolver:           tokenResolver,
			LegacyToken:             cfg.GitHubToken,
			BrowserContainerFactory: browserContainerFactory,
			ActiveRegistry:          registry,
			ProfilerCache:           graph.NewProfilerCache(indexDir),
			Memory:                  memStore,
			QAProfile:               qaProfile,
			BrowserExecutor:         &browser.SandboxPlaywrightExecutor{StagehandAdapter: true},
			PreviewBaseURL:          os.Getenv("WAPO_REVIEW_PREVIEW_URL"),
			Config:                  cfg,
			Redactor:                red,
			Logger:                  logger,
			ModelFactory:            modelFactory,
			VisionModelFactory:      modelFactory,
			MaxShardConcurrency:     8,
		}

		var runner orchestrator.WorkflowRunner
		var stopHatchetWorker func() error
		if cfg.OrchestratorMode == "hatchet" && cfg.HatchetClientToken != "" {
			hc, err := hatchet.NewClient(hatchet.WithToken(cfg.HatchetClientToken))
			if err != nil {
				return fmt.Errorf("init Hatchet client: %w", err)
			}
			hr, err := orchestrator.RegisterHatchet(hc, pipe, 4)
			if err != nil {
				return fmt.Errorf("register Hatchet workflow: %w", err)
			}
			if command == "serve" {
				stopFn, err := hr.StartWorker("wapo-review-worker", 16)
				if err != nil {
					return fmt.Errorf("start Hatchet worker: %w", err)
				}
				stopHatchetWorker = stopFn
			}
			runner = hr
			runnerName = "hatchet"
		} else {
			runner = orchestrator.NewLocalRunner(pipe, 4, 2, db)
			runnerName = "local"
		}

		if command == "review" {
			rf := flag.NewFlagSet("review", flag.ContinueOnError)
			repo := rf.String("repo", "", "owner/repo")
			prNum := rf.Int("pr", 0, "PR number")
			installID := rf.Int64("installation-id", 0, "GitHub App installation ID")
			uiChecks := rf.Bool("ui", false, "run browser/visual UI checks")
			if err := rf.Parse(flags.Args()[1:]); err != nil {
				return err
			}
			if *repo == "" || *prNum < 1 {
				return fmt.Errorf("review requires --repo owner/repo and --pr N")
			}
			ref, err := runner.Start(ctx, orchestrator.ReviewInput{
				Version:        1,
				RunID:          fmt.Sprintf("%s:%d", *repo, *prNum),
				TenantID:       strings.Split(*repo, "/")[0],
				Repo:           *repo,
				PRNumber:       *prNum,
				Trigger:        "cli",
				InstallationID: *installID,
				UIChecks:       *uiChecks,
			})
			if err != nil {
				return err
			}
			_, err = runner.Wait(ctx, ref)
			return err
		}

		addr := os.Getenv("WAPO_REVIEW_ADDR")
		if addr == "" {
			port := os.Getenv("PORT")
			if _, err := strconv.Atoi(port); err == nil && port != "" {
				addr = ":" + port
			} else {
				addr = ":8080"
			}
		}

		botLogin := os.Getenv("WAPO_REVIEW_BOT_LOGIN")
		if botLogin == "" {
			slug := cfg.GitHubAppBotSlug
			if slug == "" {
				slug = branding.BotSlug
			}
			botLogin = strings.TrimSuffix(slug, "[bot]") + "[bot]"
		}

		logger.Info("starting wapo-review",
			"version", version,
			"addr", addr,
			"runner", runnerName,
			"provider", providerDesc,
			"github_app", tokenResolver != nil,
			"oauth", oauthHandler != nil,
			"webhook_secrets", len(cfg.WebhookSecrets()),
		)

		server := &http.Server{
			Addr: addr,
			Handler: NewServer(ServerConfig{
				WebhookSecrets: cfg.WebhookSecrets(),
				AppMode:        cfg.GitHubAppID != "" && tokenResolver != nil,
				BotLogin:       botLogin,
				Runner:         runner,
				Client:         client,
				TokenResolver:  tokenResolver,
				LegacyToken:    cfg.GitHubToken,
				Memory:         memStore,
				OAuth:          oauthHandler,
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}

		shutdownDone := make(chan struct{})
		go func() {
			defer close(shutdownDone)
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = server.Shutdown(shutdown)
			cancel()
			if stopHatchetWorker != nil {
				_ = stopHatchetWorker()
			}
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			if err := registry.Cleanup(cleanup); err != nil {
				log.Printf("cleanup active containers: %v", err)
			}
		}()

		err = server.ListenAndServe()
		if err == http.ErrServerClosed {
			<-shutdownDone
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
