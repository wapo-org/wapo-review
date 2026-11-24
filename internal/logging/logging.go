package logging

import (
	"io"
	"log/slog"

	"github.com/wapo-org/wapo-review/internal/redact"
)

type Logger struct {
	base     *slog.Logger
	redactor *redact.Redactor
}

func New(w io.Writer, format string, redactor *redact.Redactor) *Logger {
	if redactor == nil {
		redactor = redact.New()
	}
	var handler slog.Handler
	options := &slog.HandlerOptions{}
	if format == "text" {
		handler = slog.NewTextHandler(w, options)
	} else {
		handler = slog.NewJSONHandler(w, options)
	}
	return &Logger{base: slog.New(handler), redactor: redactor}
}

func (l *Logger) Debug(msg string, args ...any) {
	l.base.Debug(l.redactor.RedactString(msg), l.attrs(args...)...)
}
func (l *Logger) Info(msg string, args ...any) {
	l.base.Info(l.redactor.RedactString(msg), l.attrs(args...)...)
}
func (l *Logger) Warn(msg string, args ...any) {
	l.base.Warn(l.redactor.RedactString(msg), l.attrs(args...)...)
}
func (l *Logger) Error(msg string, args ...any) {
	l.base.Error(l.redactor.RedactString(msg), l.attrs(args...)...)
}

func (l *Logger) attrs(args ...any) []any {
	out := make([]any, len(args))
	for i, arg := range args {
		if attr, ok := arg.(slog.Attr); ok {
			out[i] = redactAttr(l.redactor, attr)
		} else {
			out[i] = l.redactor.RedactValue(arg)
		}
	}
	return out
}

func redactAttr(r *redact.Redactor, attr slog.Attr) slog.Attr {
	attr.Key = r.RedactString(attr.Key)
	if attr.Value.Kind() == slog.KindGroup {
		items := attr.Value.Group()
		for i := range items {
			items[i] = redactAttr(r, items[i])
		}
		attr.Value = slog.GroupValue(items...)
	} else {
		attr.Value = slog.AnyValue(r.RedactValue(attr.Value.Any()))
	}
	return attr
}
