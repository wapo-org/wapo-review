package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadEnvironmentAndProvider(t *testing.T) {
	env := map[string]string{"ORCHESTRATOR_MODE": "hatchet", "HATCHET_CLIENT_TOKEN": "token", "LLM_PROVIDERS": "main", "LLM_MAIN_PROTOCOL": "openai", "LLM_MAIN_BASE_URL": "https://llm.invalid", "LLM_MAIN_API_KEY": "key", "LLM_MAIN_MODEL": "model", "LLM_MAIN_TIMEOUT": "2s"}
	c, err := Load(func(key string) (string, bool) { v, ok := env[key]; return v, ok }, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers["main"].Timeout != 2*time.Second {
		t.Fatalf("timeout = %v", c.Providers["main"].Timeout)
	}
}

func TestLoadCredentialsAndRejectInvalidMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"orchestrator_mode":"local","state_dir":"/tmp/state"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(func(string) (string, bool) { return "", false }, path)
	if err != nil || c.StateDir != "/tmp/state" {
		t.Fatalf("config=%+v err=%v", c, err)
	}
	_, err = Load(func(key string) (string, bool) {
		if key == "ORCHESTRATOR_MODE" {
			return "remote", true
		}
		return "", false
	}, "")
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestLoadLegacyCredentialsAndCodexProxyAutoDiscovery(t *testing.T) {
	stateDir := t.TempDir()
	codexDir := filepath.Join(stateDir, "codex-key")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatal(err)
	}
	toml := `
model_provider = "customproxy"
model = "gpt-6.2-sol"
model_reasoning_effort = "high"

[model_providers.customproxy]
base_url = "https://proxy.example.invalid/v1"
wire_api = "responses"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "auth.json"), []byte(`{"OPENAI_API_KEY":"sk-proxy-test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credPath, []byte(`{"GITHUB_APP_ID":"12345","GITHUB_APP_WEBHOOK_SECRET":"wh1","GITHUB_WEBHOOK_SECRET":"wh2"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(func(key string) (string, bool) {
		if key == "WAPO_REVIEW_STATE_DIR" {
			return stateDir, true
		}
		return "", false
	}, credPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c.GitHubAppID != "12345" || len(c.WebhookSecrets()) != 2 {
		t.Fatalf("unexpected legacy github fields: app=%q secrets=%v", c.GitHubAppID, c.WebhookSecrets())
	}
	p, ok := c.Providers["default"]
	if !ok || p.Protocol != "openai-responses" || p.BaseURL != "https://proxy.example.invalid/v1" || p.APIKey != "sk-proxy-test" || p.Model != "gpt-6.2-sol" {
		t.Fatalf("unexpected auto-discovered codex proxy provider: %+v", p)
	}
}
