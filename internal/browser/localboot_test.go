package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectLocalServicesMonorepo(t *testing.T) {
	root := t.TempDir()
	// Monorepo under workspace/ with apps/web (Vite) and apps/api (Hono)
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("platform/package.json", `{"name":"monorepo","workspaces":["apps/*"]}`)
	mustWrite("platform/package-lock.json", `{}`)
	mustWrite("platform/apps/web/package.json", `{"name":"@app/web","scripts":{"dev":"vite --port 5173"},"devDependencies":{"vite":"^6.0.0"}}`)
	mustWrite("platform/apps/api/package.json", `{"name":"@app/api","scripts":{"dev:local":"tsx src/local.ts"},"dependencies":{"hono":"^4.0.0"}}`)

	plan := DetectLocalServices(root)
	if plan.Primary == nil || plan.Primary.Framework != "Vite" || plan.Primary.Port != 5173 || plan.Primary.RelDir != "platform/apps/web" {
		t.Fatalf("unexpected primary service: %+v", plan.Primary)
	}
	if plan.Companion == nil || plan.Companion.Framework != "NodeAPI" || plan.Companion.RelDir != "platform/apps/api" {
		t.Fatalf("unexpected companion service: %+v", plan.Companion)
	}
	if plan.InstallRelDir != "platform" || !strings.Contains(plan.InstallCmd, "npm ci") {
		t.Fatalf("unexpected install plan: dir=%q cmd=%q", plan.InstallRelDir, plan.InstallCmd)
	}
}

func TestDetectLocalServicesSingleAPI(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"svc","scripts":{"dev":"tsx watch src/index.ts --port 4000"},"dependencies":{"express":"^5.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := DetectLocalServices(root)
	if plan.Primary == nil || plan.Primary.Role != "api" || plan.Primary.Port != 4000 {
		t.Fatalf("unexpected API-only plan: %+v", plan.Primary)
	}
	if plan.Companion != nil {
		t.Fatalf("expected no companion for single API app, got %+v", plan.Companion)
	}
}
