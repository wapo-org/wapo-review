package secrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var sandboxKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,80}$`)
var denied = []string{"GITHUB_APP_", "GITHUB_TOKEN", "GITHUB_WEBHOOK", "VERCEL_", "SSH_KEY", "PRIVATE_KEY", "WEBHOOK_SECRET", "SIGNING_", "CLIENT_SECRET", "DEPLOY_KEY", "SESSION_SECRET", "INFISICAL_", "DATABASE_URL", "REDIS_", "UPSTASH_", "QSTASH_", "MODAL_", "LINEAR_", "CODEKEY_", "TENANT_ID_SECRET", "MASTER_KEY", "ADMIN_"}

func IsAllowedSandboxVaultKey(key string) bool {
	if !sandboxKey.MatchString(key) || strings.HasSuffix(key, "_PASSWORD") || strings.HasSuffix(key, "_EMAIL") {
		return false
	}
	for _, d := range denied {
		if strings.Contains(key, d) {
			return false
		}
	}
	return strings.HasPrefix(key, "QA_") || strings.HasPrefix(key, "OPENROUTER_") || strings.HasPrefix(key, "TEST_API_")
}
func CollectSandboxVaultSecrets(ctx context.Context, profile *QAProfile, adapter Adapter) map[string]string {
	out := map[string]string{}
	if adapter != nil {
		if keys, e := adapter.ListKeys(ctx); e == nil {
			for _, k := range keys {
				if IsAllowedSandboxVaultKey(k) {
					if v, e := adapter.Get(ctx, k); e == nil && v != "" {
						out[k] = v
					}
				}
			}
		}
	}
	if profile != nil {
		for k, v := range profile.Secrets {
			key := strings.ToUpper(k)
			if v.Value != "" && sandboxKey.MatchString(key) {
				out[key] = v.Value
			}
		}
	}
	return out
}
func MergedQASecrets(profile *QAProfile, vault map[string]string) map[string]string {
	out := map[string]string{}
	if profile != nil {
		for k, v := range profile.Secrets {
			out[k] = v.Value
		}
	}
	for k, v := range vault {
		out[strings.ToLower(k)] = v
	}
	return out
}
func StandaloneVaultScript(storePath string) string {
	return fmt.Sprintf(`#!/usr/bin/env python3
import fnmatch,json,sys
STORE=%q
try:
 with open(STORE,encoding="utf-8") as f: values=json.load(f)
except (OSError,ValueError): values={}
a=sys.argv[1:]
if a==["list"]:
 print("\\n".join(sorted(values))); raise SystemExit(0)
if len(a)==2 and a[0]=="search":
 q=a[1].lower(); print("\\n".join(k for k in sorted(values) if q in k.lower() or fnmatch.fnmatch(k.lower(),q))); raise SystemExit(0)
if len(a)==2 and a[0]=="get":
 k=a[1] if a[1] in values else a[1].upper()
 if k not in values: print("vault: secret not found",file=sys.stderr); raise SystemExit(1)
 print(values[k],end=""); raise SystemExit(0)
print("vault: read-only; supported commands are list, search, and get",file=sys.stderr); raise SystemExit(2)
`, storePath)
}
