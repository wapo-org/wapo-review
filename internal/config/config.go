package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ProviderConfig struct {
	Protocol        string        `json:"protocol"`
	BaseURL         string        `json:"base_url"`
	APIKey          string        `json:"api_key"`
	Model           string        `json:"model"`
	ReasoningEffort string        `json:"reasoning_effort"`
	PromptCache     bool          `json:"prompt_cache"`
	Timeout         time.Duration `json:"-"`
}

type Config struct {
	Providers              map[string]ProviderConfig `json:"providers"`
	GitHubAppID            string                    `json:"github_app_id"`
	GitHubPrivateKeyPath   string                    `json:"github_private_key_path"`
	GitHubPrivateKeyPEM    string                    `json:"github_app_private_key_pem"`
	GitHubWebhookSecret    string                    `json:"github_webhook_secret"`
	GitHubAppWebhookSecret string                    `json:"github_app_webhook_secret"`
	GitHubToken            string                    `json:"github_token"`
	GitHubAppClientID      string                    `json:"github_app_client_id"`
	GitHubAppClientSecret  string                    `json:"github_app_client_secret"`
	GitHubAppCallbackURL   string                    `json:"github_app_callback_url"`
	GitHubAppSessionSecret string                    `json:"github_app_session_signing_secret"`
	GitHubAppBotSlug       string                    `json:"github_app_bot_slug"`
	HatchetClientToken     string                    `json:"hatchet_client_token"`
	OrchestratorMode       string                    `json:"orchestrator_mode"`
	InfisicalClientID      string                    `json:"infisical_client_id"`
	InfisicalClientSecret  string                    `json:"infisical_client_secret"`
	InfisicalProjectID     string                    `json:"infisical_project_id"`
	InfisicalEnvironment   string                    `json:"infisical_environment"`
	StateDir               string                    `json:"state_dir"`
	IndexDir               string                    `json:"index_dir"`
	MemoryDir              string                    `json:"memory_dir"`
	ArtifactsDir           string                    `json:"artifacts_dir"`
}

type Lookup func(string) (string, bool)

func Load(envLookup Lookup, credPath string) (Config, error) {
	c, err := LoadUnvalidated(envLookup, credPath)
	if err != nil {
		return c, err
	}
	return c, c.Validate()
}

func LoadUnvalidated(envLookup Lookup, credPath string) (Config, error) {
	c := Config{Providers: map[string]ProviderConfig{}, OrchestratorMode: "local", StateDir: ".wapo-review"}
	var solModel, solEffort string
	if credPath != "" {
		b, err := os.ReadFile(credPath)
		if err != nil {
			return c, fmt.Errorf("read credentials: %w", err)
		}
		if err := json.Unmarshal(b, &c); err != nil {
			var raw map[string]any
			if json.Unmarshal(b, &raw) != nil {
				return c, fmt.Errorf("decode credentials: %w", err)
			}
			if id, ok := raw["GITHUB_APP_ID"].(float64); ok {
				raw["GITHUB_APP_ID"] = strconv.FormatInt(int64(id), 10)
			}
			fixed, marshalErr := json.Marshal(raw)
			if marshalErr != nil || json.Unmarshal(fixed, &c) != nil {
				return c, fmt.Errorf("decode credentials: %w", err)
			}
		}
		if c.Providers == nil {
			c.Providers = map[string]ProviderConfig{}
		}
		// Backward-compatible uppercase key support from legacy credentials.json.
		var raw map[string]any
		if json.Unmarshal(b, &raw) == nil {
			getStr := func(k string) string {
				if v, ok := raw[k]; ok {
					switch x := v.(type) {
					case string:
						return strings.TrimSpace(x)
					case float64:
						return strconv.FormatInt(int64(x), 10)
					}
				}
				return ""
			}
			fill := func(dst *string, keys ...string) {
				if *dst != "" {
					return
				}
				for _, k := range keys {
					if v := getStr(k); v != "" {
						*dst = v
						return
					}
				}
			}
			fill(&c.GitHubAppID, "GITHUB_APP_ID")
			fill(&c.GitHubPrivateKeyPath, "GITHUB_PRIVATE_KEY_PATH", "GITHUB_APP_PRIVATE_KEY_PATH")
			fill(&c.GitHubPrivateKeyPEM, "GITHUB_APP_PRIVATE_KEY_PEM")
			fill(&c.GitHubWebhookSecret, "GITHUB_WEBHOOK_SECRET")
			fill(&c.GitHubAppWebhookSecret, "GITHUB_APP_WEBHOOK_SECRET")
			fill(&c.GitHubToken, "GITHUB_TOKEN")
			fill(&c.GitHubAppClientID, "GITHUB_APP_CLIENT_ID")
			fill(&c.GitHubAppClientSecret, "GITHUB_APP_CLIENT_SECRET")
			fill(&c.GitHubAppCallbackURL, "GITHUB_APP_CALLBACK_URL")
			fill(&c.GitHubAppSessionSecret, "GITHUB_APP_SESSION_SIGNING_SECRET")
			fill(&c.GitHubAppBotSlug, "GITHUB_APP_BOT_SLUG")
			fill(&c.HatchetClientToken, "HATCHET_CLIENT_TOKEN")
			fill(&solModel, "SOL_MODEL")
			fill(&solEffort, "SOL_REASONING_EFFORT")
		}
	}
	if envLookup == nil {
		envLookup = os.LookupEnv
	}
	set := func(key string, dst *string) {
		if v, ok := envLookup(key); ok && v != "" {
			*dst = v
		}
	}
	set("GITHUB_APP_ID", &c.GitHubAppID)
	set("GITHUB_PRIVATE_KEY_PATH", &c.GitHubPrivateKeyPath)
	set("GITHUB_APP_PRIVATE_KEY_PEM", &c.GitHubPrivateKeyPEM)
	set("GITHUB_WEBHOOK_SECRET", &c.GitHubWebhookSecret)
	set("GITHUB_APP_WEBHOOK_SECRET", &c.GitHubAppWebhookSecret)
	set("GITHUB_TOKEN", &c.GitHubToken)
	set("GITHUB_APP_CLIENT_ID", &c.GitHubAppClientID)
	set("GITHUB_APP_CLIENT_SECRET", &c.GitHubAppClientSecret)
	set("GITHUB_APP_CALLBACK_URL", &c.GitHubAppCallbackURL)
	set("GITHUB_APP_SESSION_SIGNING_SECRET", &c.GitHubAppSessionSecret)
	set("GITHUB_APP_BOT_SLUG", &c.GitHubAppBotSlug)
	set("SOL_MODEL", &solModel)
	set("SOL_REASONING_EFFORT", &solEffort)
	set("HATCHET_CLIENT_TOKEN", &c.HatchetClientToken)
	set("ORCHESTRATOR_MODE", &c.OrchestratorMode)
	set("INFISICAL_CLIENT_ID", &c.InfisicalClientID)
	set("INFISICAL_CLIENT_SECRET", &c.InfisicalClientSecret)
	set("INFISICAL_PROJECT_ID", &c.InfisicalProjectID)
	set("INFISICAL_ENVIRONMENT", &c.InfisicalEnvironment)
	set("WAPO_REVIEW_STATE_DIR", &c.StateDir)
	set("WAPO_REVIEW_INDEX_DIR", &c.IndexDir)
	set("WAPO_REVIEW_MEMORY_DIR", &c.MemoryDir)
	set("WAPO_REVIEW_ARTIFACTS_DIR", &c.ArtifactsDir)

	if names, ok := envLookup("LLM_PROVIDERS"); ok {
		for _, name := range strings.Split(names, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				if _, exists := c.Providers[name]; !exists {
					c.Providers[name] = ProviderConfig{}
				}
			}
		}
	}
	for name, p := range c.Providers {
		prefix := "LLM_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
		set(prefix+"PROTOCOL", &p.Protocol)
		set(prefix+"BASE_URL", &p.BaseURL)
		set(prefix+"API_KEY", &p.APIKey)
		set(prefix+"MODEL", &p.Model)
		set(prefix+"REASONING_EFFORT", &p.ReasoningEffort)
		if v, ok := envLookup(prefix + "PROMPT_CACHE"); ok {
			parsed, err := strconv.ParseBool(v)
			if err != nil {
				return c, fmt.Errorf("%s: %w", prefix+"PROMPT_CACHE", err)
			}
			p.PromptCache = parsed
		}
		if v, ok := envLookup(prefix + "TIMEOUT"); ok {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return c, fmt.Errorf("%s: %w", prefix+"TIMEOUT", err)
			}
			p.Timeout = parsed
		}
		c.Providers[name] = p
	}

	// Auto-discover custom OpenAI-compatible proxy config from `<StateDir>/codex-key/{config.toml,auth.json}`
	// when no explicit LLM provider was configured.
	if len(c.Providers) == 0 && c.StateDir != "" {
		if p, ok := LoadCodexKeyProvider(filepath.Join(c.StateDir, "codex-key"), solModel, solEffort, envLookup); ok {
			c.Providers["default"] = p
		}
	}

	return c, nil
}

var tomlKVRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"`)
var tomlSectionRe = regexp.MustCompile(`^\s*\[([^\]]+)\]`)

// LoadCodexKeyProvider reads a Codex-format `config.toml` + `auth.json` pair
// (custom OpenAI-compatible proxy URL, wire_api, model, and API key) into a
// Go ProviderConfig so the Go v2 host loop uses the exact same proxy endpoint.
func LoadCodexKeyProvider(dir, fallbackModel, fallbackEffort string, envLookup Lookup) (ProviderConfig, bool) {
	cfgBytes, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		return ProviderConfig{}, false
	}
	var providerName, modelName, effort string
	providers := map[string]map[string]string{}
	section := ""
	for _, rawLine := range strings.Split(string(cfgBytes), "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		if m := tomlSectionRe.FindStringSubmatch(line); m != nil {
			section = strings.TrimSpace(m[1])
			continue
		}
		if m := tomlKVRe.FindStringSubmatch(line); m != nil {
			k, v := m[1], m[2]
			if section == "" {
				switch k {
				case "model_provider":
					providerName = v
				case "model":
					modelName = v
				case "model_reasoning_effort":
					effort = v
				}
			} else if strings.HasPrefix(section, "model_providers.") {
				pname := strings.TrimPrefix(section, "model_providers.")
				if providers[pname] == nil {
					providers[pname] = map[string]string{}
				}
				providers[pname][k] = v
			}
		}
	}

	var psec map[string]string
	if providerName != "" {
		psec = providers[providerName]
	} else {
		for _, v := range providers {
			psec = v
			break
		}
	}
	baseURL := ""
	wireAPI := ""
	envKey := "OPENAI_API_KEY"
	if psec != nil {
		baseURL = strings.TrimSpace(psec["base_url"])
		wireAPI = strings.ToLower(strings.TrimSpace(psec["wire_api"]))
		if ek := strings.TrimSpace(psec["env_key"]); ek != "" {
			envKey = ek
		}
	}
	if baseURL == "" {
		return ProviderConfig{}, false
	}

	apiKey := ""
	if authBytes, err := os.ReadFile(filepath.Join(dir, "auth.json")); err == nil {
		var authMap map[string]any
		if json.Unmarshal(authBytes, &authMap) == nil {
			for _, k := range []string{envKey, "OPENAI_API_KEY", "api_key", "token"} {
				if v, ok := authMap[k].(string); ok && strings.TrimSpace(v) != "" {
					apiKey = strings.TrimSpace(v)
					break
				}
			}
		}
	}
	if apiKey == "" && envLookup != nil {
		if v, ok := envLookup(envKey); ok && strings.TrimSpace(v) != "" {
			apiKey = strings.TrimSpace(v)
		}
	}
	if apiKey == "" {
		return ProviderConfig{}, false
	}

	if fallbackModel != "" {
		modelName = fallbackModel
	}
	if modelName == "" {
		modelName = "gpt-6.2-sol"
	}
	if fallbackEffort != "" {
		effort = fallbackEffort
	}
	if effort == "" {
		effort = "high"
	}
	proto := "openai"
	if wireAPI == "responses" {
		proto = "openai-responses"
	}
	return ProviderConfig{
		Protocol:        proto,
		BaseURL:         baseURL,
		APIKey:          apiKey,
		Model:           modelName,
		ReasoningEffort: effort,
		PromptCache:     true,
		Timeout:         3 * time.Minute,
	}, true
}

func (c Config) WebhookSecrets() []string {
	var out []string
	for _, s := range []string{c.GitHubAppWebhookSecret, c.GitHubWebhookSecret} {
		if s != "" {
			dup := false
			for _, existing := range out {
				if existing == s {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, s)
			}
		}
	}
	return out
}

func (c Config) Validate() error {
	if c.OrchestratorMode != "local" && c.OrchestratorMode != "hatchet" {
		return errors.New("orchestrator_mode must be local or hatchet")
	}
	if c.OrchestratorMode == "hatchet" && c.HatchetClientToken == "" {
		return errors.New("hatchet mode requires HATCHET_CLIENT_TOKEN")
	}
	for name, p := range c.Providers {
		if p.Protocol != "openai" && p.Protocol != "openai-responses" && p.Protocol != "anthropic" {
			return fmt.Errorf("provider %q protocol must be openai, openai-responses, or anthropic", name)
		}
		if p.BaseURL == "" || p.APIKey == "" || p.Model == "" {
			return fmt.Errorf("provider %q requires base_url, api_key, and model", name)
		}
		if p.Timeout < 0 {
			return fmt.Errorf("provider %q timeout cannot be negative", name)
		}
	}
	return nil
}
