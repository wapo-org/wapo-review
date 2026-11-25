package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino-ext/components/model/claude"
	"github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type ProviderConfig struct {
	Protocol        string
	BaseURL         string
	APIKey          string
	Model           string
	ReasoningEffort string
	ExtraHeaders    map[string]string
	PromptCache     bool
	MaxTokens       int
	Timeout         time.Duration
	Retry           RetryPolicy
	HTTPClient      *http.Client
}

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

func httpClientWithHeaders(base *http.Client, headers map[string]string, timeout time.Duration) *http.Client {
	if base == nil && len(headers) == 0 {
		return nil
	}
	var c http.Client
	if base != nil {
		c = *base
	}
	previousRedirect := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
			return http.ErrUseLastResponse
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	if timeout > 0 && c.Timeout == 0 {
		c.Timeout = timeout
	}
	if len(headers) > 0 {
		copied := make(map[string]string, len(headers))
		for k, v := range headers {
			copied[k] = v
		}
		c.Transport = &headerTransport{base: c.Transport, headers: copied}
	}
	return &c
}

func anthropicThinkingBudget(effort string) int {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "low":
		return 1024
	case "medium":
		return 4096
	case "high", "xhigh", "max":
		return 8192
	default:
		return 0
	}
}

func openAIReasoningEffort(effort string) openai.ReasoningEffortLevel {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "low":
		return openai.ReasoningEffortLevelLow
	case "medium":
		return openai.ReasoningEffortLevelMedium
	case "high", "xhigh", "max":
		return openai.ReasoningEffortLevelHigh
	default:
		return ""
	}
}

func NewModel(ctx context.Context, cfg ProviderConfig) (model.ToolCallingChatModel, error) {
	if strings.TrimSpace(cfg.APIKey) == "" || strings.TrimSpace(cfg.Model) == "" {
		return nil, errors.New("provider requires api key and model")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Protocol)) {
	case "openai-responses", "responses":
		if strings.TrimSpace(cfg.BaseURL) == "" {
			cfg.BaseURL = "https://api.openai.com/v1"
		}
		return &RetryModel{Model: newResponsesChatModel(cfg), Policy: cfg.Retry}, nil

	case "openai", "openai-compatible":
		oc := &openai.ChatModelConfig{
			APIKey:     cfg.APIKey,
			Model:      cfg.Model,
			BaseURL:    cfg.BaseURL,
			Timeout:    cfg.Timeout,
			HTTPClient: httpClientWithHeaders(cfg.HTTPClient, cfg.ExtraHeaders, cfg.Timeout),
		}
		if cfg.MaxTokens > 0 {
			mt := cfg.MaxTokens
			oc.MaxCompletionTokens = &mt
		}
		if eff := openAIReasoningEffort(cfg.ReasoningEffort); eff != "" {
			oc.ReasoningEffort = eff
		}
		m, err := openai.NewChatModel(ctx, oc)
		if err != nil {
			return nil, err
		}
		return &RetryModel{Model: m, Policy: cfg.Retry}, nil

	case "anthropic", "anthropic-compatible":
		var url *string
		if cfg.BaseURL != "" {
			u := cfg.BaseURL
			url = &u
		}
		maxToks := cfg.MaxTokens
		if maxToks <= 0 {
			maxToks = 4096
		}
		c := &claude.Config{
			APIKey:                 cfg.APIKey,
			Model:                  cfg.Model,
			BaseURL:                url,
			MaxTokens:              maxToks,
			RequestTimeout:         cfg.Timeout,
			AdditionalHeaderFields: cfg.ExtraHeaders,
			HTTPClient:             cfg.HTTPClient,
		}
		if cfg.PromptCache {
			c.AutoCacheControl = &claude.CacheControl{}
		}
		if budget := anthropicThinkingBudget(cfg.ReasoningEffort); budget > 0 {
			if c.MaxTokens <= budget {
				c.MaxTokens = budget + 2048
			}
			c.Thinking = &claude.Thinking{Enable: true, BudgetTokens: budget}
		}
		m, err := claude.NewChatModel(ctx, c)
		if err != nil {
			return nil, err
		}
		return &RetryModel{Model: m, Policy: cfg.Retry}, nil

	default:
		return nil, fmt.Errorf("unsupported provider protocol %q", cfg.Protocol)
	}
}

type RetryModel struct {
	Model  model.ToolCallingChatModel
	Policy RetryPolicy
}

func (m *RetryModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	bound, err := m.Model.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &RetryModel{Model: bound, Policy: m.Policy}, nil
}

func (m *RetryModel) Generate(ctx context.Context, msgs []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	var out *schema.Message
	err := retry(ctx, m.Policy, func() error {
		var e error
		out, e = m.Model.Generate(ctx, msgs, opts...)
		return e
	})
	return out, err
}

func (m *RetryModel) Stream(ctx context.Context, msgs []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	var out *schema.StreamReader[*schema.Message]
	err := retry(ctx, m.Policy, func() error {
		var e error
		out, e = m.Model.Stream(ctx, msgs, opts...)
		return e
	})
	return out, err
}

func retry(ctx context.Context, p RetryPolicy, call func() error) error {
	maxAttempts := p.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 3
	}
	delay := p.InitialBackoff
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}
	capDelay := p.MaxBackoff
	if capDelay <= 0 {
		capDelay = 2 * time.Second
	}
	for i := 0; ; i++ {
		err := call()
		if err == nil {
			return nil
		}
		if i+1 >= maxAttempts || !retryable(err) {
			return err
		}
		jitter := time.Duration(rand.Int63n(int64(delay/2 + 1)))
		timer := time.NewTimer(delay/2 + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay *= 2
		if delay > capDelay {
			delay = capDelay
		}
	}
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, v := range []string{
		"429", "500", "502", "503", "504",
		"rate limit", "overloaded", "connection reset",
		"timeout", "temporarily unavailable", "eof",
	} {
		if strings.Contains(s, v) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne)
}

type Usage struct {
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	ReasoningTokens   int64
	TotalTokens       int64
	EstimatedUSD      float64
	TurnCount         int
	Duration          time.Duration
}

type CostLedger struct {
	mu    sync.Mutex
	Usage Usage
}

func (c *CostLedger) RecordMessage(msg *schema.Message, dur time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Usage.TurnCount++
	c.Usage.Duration += dur
	if msg == nil || msg.ResponseMeta == nil || msg.ResponseMeta.Usage == nil {
		return
	}
	u := msg.ResponseMeta.Usage
	c.Usage.InputTokens += int64(u.PromptTokens)
	c.Usage.CachedInputTokens += int64(u.PromptTokenDetails.CachedTokens)
	c.Usage.OutputTokens += int64(u.CompletionTokens)
	c.Usage.ReasoningTokens += int64(u.CompletionTokensDetails.ReasoningTokens)
	c.Usage.TotalTokens += int64(u.TotalTokens)
}

func (c *CostLedger) Snapshot() Usage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Usage
}
