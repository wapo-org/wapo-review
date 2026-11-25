package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/wapo-org/wapo-review/internal/redact"
)

func TestLoggerRedactsMessagesAndAttributes(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, "json", redact.New("my-secret"))
	logger.Info("message my-secret", "token", "my-secret")
	if strings.Contains(output.String(), "my-secret") || !strings.Contains(output.String(), redact.Replacement) {
		t.Fatal(output.String())
	}
}

type deferredSecret string

func (s deferredSecret) LogValue() slog.Value { return slog.StringValue(string(s)) }

func TestLoggerRedactsResolvedValuesAndAttributeKeys(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, "json", redact.New("my-secret"))
	logger.Info("message", slog.Any("key-my-secret", deferredSecret("my-secret")))
	if strings.Contains(output.String(), "my-secret") || !strings.Contains(output.String(), redact.Replacement) {
		t.Fatal(output.String())
	}
}
