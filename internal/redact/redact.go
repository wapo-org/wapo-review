package redact

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

const Replacement = "[REDACTED]"

type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:ghs_|ghp_|sk-or-|sk-ant-)[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`(?s)-----BEGIN .*? PRIVATE KEY-----.*?-----END .*? PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`),
}

func New(secrets ...string) *Redactor {
	r := &Redactor{}
	r.Register(secrets...)
	return r
}

func (r *Redactor) Register(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, secret := range secrets {
		if secret != "" {
			r.secrets = append(r.secrets, secret)
		}
	}
}

func (r *Redactor) RedactString(value string) string {
	r.mu.RLock()
	secrets := append([]string(nil), r.secrets...)
	r.mu.RUnlock()
	for _, secret := range secrets {
		value = strings.ReplaceAll(value, secret, Replacement)
	}
	for _, pattern := range patterns {
		value = pattern.ReplaceAllString(value, Replacement)
	}
	return value
}

func (r *Redactor) RedactValue(value any) any {
	switch v := value.(type) {
	case string:
		return r.RedactString(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[r.RedactString(key)] = r.RedactValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.RedactValue(item)
		}
		return out
	default:
		return value
	}
}

func (r *Redactor) Redact(value any) string { return r.RedactString(fmt.Sprint(value)) }

func (r *Redactor) RedactAttr(a slog.Attr) slog.Attr {
	a.Key = r.RedactString(a.Key)
	return slog.Attr{Key: a.Key, Value: r.redactLogValue(a.Value)}
}

func (r *Redactor) redactLogValue(v slog.Value) slog.Value {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(r.RedactString(v.String()))
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]slog.Attr, len(attrs))
		for i, a := range attrs {
			out[i] = r.RedactAttr(a)
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		if x, ok := v.Any().(slog.LogValuer); ok {
			return r.redactLogValue(x.LogValue())
		}
		return slog.StringValue(r.RedactString(fmt.Sprint(v.Any())))
	default:
		return v
	}
}
