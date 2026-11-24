package redact

import (
	"strings"
	"sync"
	"testing"
)

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
