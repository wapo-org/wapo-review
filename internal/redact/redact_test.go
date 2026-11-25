package redact

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestRedactAttrNestedGroups(t *testing.T) {
	r := New("secret-value")
	attr := r.RedactAttr(slog.Group("outer", slog.String("token", "secret-value"), slog.Group("inner", slog.Any("value", "prefix secret-value"))))
	outer := attr.Value.Group()
	if len(outer) != 2 || outer[0].Value.String() != Replacement {
		t.Fatalf("outer group was not redacted: %#v", outer)
	}
	inner := outer[1].Value.Group()
	if len(inner) != 1 || inner[0].Value.String() != "prefix "+Replacement {
		t.Fatalf("nested group was not redacted: %#v", inner)
	}
}

func TestRedactMapKeysJSONSafe(t *testing.T) {
	r := New("secret-value")
	arrayKey := map[[4]byte]string{{1, 2, 3, 4}: "secret-value"}
	if _, ok := r.RedactValue(arrayKey).(map[string]any); !ok {
		t.Fatal("array-key map was not converted to string-key map")
	}
	redacted := r.RedactValue(map[string]string{"key": "secret-value"})
	data, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-value") || !strings.Contains(string(data), Replacement) {
		t.Fatalf("unexpected JSON %s", data)
	}
}

func TestRedactStringsAndNestedValues(t *testing.T) {
	r := New("custom-secret")
	out := r.RedactString("custom-secret Bearer abc.def ghs_123456789012 sk-ant-123456789012")
	for _, secret := range []string{"custom-secret", "abc.def", "ghs_123456789012", "sk-ant-123456789012"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret remained: %s", secret)
		}
	}
	nested := r.RedactValue(map[string]any{"value": []any{"custom-secret"}}).(map[string]any)
	if nested["value"].([]any)[0] != Replacement {
		t.Fatal(nested)
	}
}

func TestConcurrentRegistrationAndRedaction(t *testing.T) {
	r := New("initial-secret")
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Register("next-secret"); _ = r.RedactString("initial-secret next-secret") }()
	}
	wg.Wait()
}
