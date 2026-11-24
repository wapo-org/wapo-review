package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testAdapter struct{ values map[string]string }

func (a testAdapter) Name() string { return "test" }
func (a testAdapter) ListKeys(context.Context) ([]string, error) {
	var k []string
	for x := range a.values {
		k = append(k, x)
	}
	return k, nil
}
func (a testAdapter) Get(_ context.Context, k string) (string, error) { return a.values[k], nil }
func TestChainAndSandboxFilter(t *testing.T) {
	ctx := context.Background()
	a := testAdapter{map[string]string{"QA_TOKEN": "safe", "VERCEL_TOKEN": "private", "TEST_API_PASSWORD": "private"}}
	v, e := (ChainedAdapter{Adapters: []Adapter{a}}).Get(ctx, "QA_TOKEN")
	if e != nil || v != "safe" {
		t.Fatalf("chain: %q %v", v, e)
	}
	got := CollectSandboxVaultSecrets(ctx, nil, a)
	if len(got) != 1 || got["QA_TOKEN"] != "safe" {
		t.Fatalf("unexpected secrets: %#v", got)
	}
	for _, k := range []string{"QA_OK", "OPENROUTER_KEY", "TEST_API_KEY"} {
		if !IsAllowedSandboxVaultKey(k) {
			t.Errorf("%s denied", k)
		}
	}
	for _, k := range []string{"VERCEL_TOKEN", "GITHUB_APP_KEY", "QA_EMAIL", "QA_PASSWORD", "LINEAR_API_KEY"} {
		if IsAllowedSandboxVaultKey(k) {
			t.Errorf("%s allowed", k)
		}
	}
}
func TestVaultCLIUsesArgumentVector(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "vault")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\"\n"
	if e := os.WriteFile(p, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	got, e := (VaultCLIAdapter{Binary: p}).Get(context.Background(), "QA_KEY;touch /tmp/injected")
	if e == nil || got != "" {
		t.Fatalf("invalid key accepted: %q %v", got, e)
	}
	got, e = (VaultCLIAdapter{Binary: p}).Get(context.Background(), "QA_KEY")
	if e != nil || got != "get\nQA_KEY" {
		t.Fatalf("output %q, %v", got, e)
	}
}
func TestQAProfileKnownValuesAndDescribe(t *testing.T) {
	p := &QAProfile{Source: "x", Vercel: map[string]string{"token": "vercel-sensitive-value"}, Personas: map[string]Persona{"primary": {Email: "persona-sensitive-value", Password: "password-sensitive-value", About: "test"}}, Secrets: map[string]QASecret{"key": {Value: "qa-sensitive-value", About: "safe"}}}
	values := p.KnownValues()
	if len(values) != 4 {
		t.Fatalf("values %#v", values)
	}
	b, _ := jsonMarshal(p.Describe())
	for _, secret := range []string{"vercel-sensitive-value", "persona-sensitive-value", "password-sensitive-value", "qa-sensitive-value"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("Describe leaked %q", secret)
		}
	}
}
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
