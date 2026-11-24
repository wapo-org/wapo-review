package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

type Adapter interface {
	Get(context.Context, string) (string, error)
	ListKeys(context.Context) ([]string, error)
	Name() string
}

var validKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type EnvAdapter struct{ Environ map[string]string }

func (a EnvAdapter) Name() string { return "env" }
func (a EnvAdapter) Get(_ context.Context, key string) (string, error) {
	if !validKey.MatchString(key) {
		return "", errors.New("invalid secret key")
	}
	return a.env()[key], nil
}
func (a EnvAdapter) ListKeys(context.Context) ([]string, error) {
	var keys []string
	for k := range a.env() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
func (a EnvAdapter) env() map[string]string {
	if a.Environ != nil {
		return a.Environ
	}
	out := map[string]string{}
	for _, entry := range os.Environ() {
		if i := strings.IndexByte(entry, '='); i >= 0 {
			out[entry[:i]] = entry[i+1:]
		}
	}
	return out
}

type JSONFileAdapter struct{ Path string }

func (a JSONFileAdapter) Name() string { return "json-file" }
func (a JSONFileAdapter) values() (map[string]any, error) {
	b, e := os.ReadFile(a.Path)
	if e != nil {
		return nil, e
	}
	var v map[string]any
	e = json.Unmarshal(b, &v)
	return v, e
}
func (a JSONFileAdapter) Get(_ context.Context, key string) (string, error) {
	if !validKey.MatchString(key) {
		return "", errors.New("invalid secret key")
	}
	v, e := a.values()
	if e != nil {
		return "", e
	}
	if x, ok := v[key]; ok {
		return strings.TrimSpace(strings.TrimSpace(toString(x))), nil
	}
	return "", nil
}
func (a JSONFileAdapter) ListKeys(context.Context) ([]string, error) {
	v, e := a.values()
	if e != nil {
		return nil, e
	}
	k := make([]string, 0, len(v))
	for x := range v {
		k = append(k, x)
	}
	sort.Strings(k)
	return k, nil
}
func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(strings.TrimSpace(stringValue(v)))
}
func stringValue(v any) string { b, _ := json.Marshal(v); return string(b) }

type VaultCLIAdapter struct{ Binary string }

func (a VaultCLIAdapter) Name() string { return "vault-cli" }
func (a VaultCLIAdapter) binary() string {
	if a.Binary != "" {
		return a.Binary
	}
	return "/usr/local/bin/vault"
}
func (a VaultCLIAdapter) run(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, a.binary(), args...).Output()
}
func (a VaultCLIAdapter) ListKeys(ctx context.Context) ([]string, error) {
	b, e := a.run(ctx, "list")
	if e != nil {
		return nil, e
	}
	var k []string
	for _, s := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(s) != "" {
			k = append(k, strings.TrimSpace(s))
		}
	}
	sort.Strings(k)
	return k, nil
}
func (a VaultCLIAdapter) Get(ctx context.Context, key string) (string, error) {
	if !validKey.MatchString(key) {
		return "", errors.New("invalid secret key")
	}
	b, e := a.run(ctx, "get", key)
	if e != nil {
		return "", e
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

type ChainedAdapter struct{ Adapters []Adapter }

func (a ChainedAdapter) Name() string { return "chain" }
func (a ChainedAdapter) Get(ctx context.Context, key string) (string, error) {
	var errs []error
	for _, x := range a.Adapters {
		v, e := x.Get(ctx, key)
		if e == nil && v != "" {
			return v, nil
		}
		if e != nil {
			errs = append(errs, e)
		}
	}
	return "", errors.Join(errs...)
}
func (a ChainedAdapter) ListKeys(ctx context.Context) ([]string, error) {
	set := map[string]bool{}
	var errs []error
	for _, x := range a.Adapters {
		k, e := x.ListKeys(ctx)
		if e != nil {
			errs = append(errs, e)
			continue
		}
		for _, v := range k {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, errors.Join(errs...)
}
