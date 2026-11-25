package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/redact"
)

type CompletionGuard interface {
	Check(context.Context, ReviewEvidence) error
}

type ReviewEvidence struct {
	CalledTools    map[string]bool
	ToolCallCounts map[string]int
	CompletedItems map[string]bool
}

type ToolCalledGuard string

func RequireToolCalled(name string) CompletionGuard { return ToolCalledGuard(name) }

func (g ToolCalledGuard) Check(_ context.Context, e ReviewEvidence) error {
	if !e.CalledTools[string(g)] {
		return fmt.Errorf("required tool %q has not run", g)
	}
	return nil
}

type AllItemsGuard []string

func RequireAllItemsCompleted(items []string) CompletionGuard {
	return AllItemsGuard(append([]string(nil), items...))
}

func (g AllItemsGuard) Check(_ context.Context, e ReviewEvidence) error {
	for _, i := range g {
		if !e.CompletedItems[i] {
			return fmt.Errorf("item %q is incomplete", i)
		}
	}
	return nil
}

type ToolRecord struct {
	Name      string
	Arguments string
	Result    string
	Duration  time.Duration
	Error     string
}

type Turn struct {
	Message     *schema.Message
	ToolRecords []ToolRecord
}

type Result struct {
	Output   string
	Turns    []Turn
	Evidence ReviewEvidence
	Usage    Usage
	Nudges   int
}

type ReviewLoop struct {
	Model           model.ToolCallingChatModel
	SystemPrompt    string
	Tools           []tool.InvokableTool
	Guards          []CompletionGuard
	MaxTurns        int
	MaxNudges       int
	Timeout         time.Duration
	Redactor        *redact.Redactor
	FailOnToolError bool
	OnToolResult    func(rec ToolRecord, evidence *ReviewEvidence)
}

func (l *ReviewLoop) Run(ctx context.Context, request string) (Result, error) {
	if l.Model == nil {
		return Result{}, errors.New("model is required")
	}
	if l.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.Timeout)
		defer cancel()
	}
	maxTurns := l.MaxTurns
	if maxTurns <= 0 {
		maxTurns = 8
	}
	maxNudges := l.MaxNudges
	if maxNudges <= 0 {
		maxNudges = 2
	}
	redactor := l.Redactor
	if redactor == nil {
		redactor = redact.New()
	}

	infos := make([]*schema.ToolInfo, 0, len(l.Tools))
	byName := make(map[string]tool.InvokableTool, len(l.Tools))
	for _, t := range l.Tools {
		info, err := t.Info(ctx)
		if err != nil {
			return Result{}, err
		}
		infos = append(infos, info)
		byName[info.Name] = t
	}

	m := l.Model
	if len(infos) > 0 {
		var err error
		m, err = l.Model.WithTools(infos)
		if err != nil {
			return Result{}, err
		}
	}

	messages := make([]*schema.Message, 0, 2)
	if strings.TrimSpace(l.SystemPrompt) != "" {
		messages = append(messages, schema.SystemMessage(l.SystemPrompt))
	}
	messages = append(messages, schema.UserMessage(request))

	ledger := &CostLedger{}
	result := Result{
		Evidence: ReviewEvidence{
			CalledTools:    map[string]bool{},
			ToolCallCounts: map[string]int{},
			CompletedItems: map[string]bool{},
		},
	}

	for turn := 0; turn < maxTurns; turn++ {
		if err := ctx.Err(); err != nil {
			result.Usage = ledger.Snapshot()
			return result, err
		}
		turnStart := time.Now()
		msg, err := generateWithRetry(ctx, m, messages)
		if err != nil {
			result.Usage = ledger.Snapshot()
			return result, err
		}
		ledger.RecordMessage(msg, time.Since(turnStart))
		result.Turns = append(result.Turns, Turn{Message: msg})
		messages = append(messages, msg)

		if len(msg.ToolCalls) == 0 {
			var guardErr error
			for _, g := range l.Guards {
				if e := g.Check(ctx, result.Evidence); e != nil {
					guardErr = e
					break
				}
			}
			if guardErr != nil && result.Nudges < maxNudges {
				result.Nudges++
				messages = append(messages, schema.UserMessage(
					fmt.Sprintf("Continue the review. Outstanding completion requirement: %s. Satisfy it before returning your final answer.", guardErr.Error()),
				))
				continue
			}
			result.Usage = ledger.Snapshot()
			if guardErr != nil {
				return result, guardErr
			}
			result.Output = msg.Content
			return result, nil
		}

		for _, call := range msg.ToolCalls {
			t := byName[call.Function.Name]
			if t == nil {
				errMsg := fmt.Sprintf("unregistered tool %q", call.Function.Name)
				if l.FailOnToolError {
					result.Usage = ledger.Snapshot()
					return result, errors.New(errMsg)
				}
				rec := ToolRecord{Name: call.Function.Name, Arguments: redactor.RedactString(call.Function.Arguments), Error: errMsg}
				result.Turns[len(result.Turns)-1].ToolRecords = append(result.Turns[len(result.Turns)-1].ToolRecords, rec)
				messages = append(messages, schema.ToolMessage(fmt.Sprintf(`{"error":%q}`, errMsg), call.ID, schema.WithToolName(call.Function.Name)))
				continue
			}
			start := time.Now()
			out, err := t.InvokableRun(ctx, call.Function.Arguments)
			rec := ToolRecord{
				Name:      call.Function.Name,
				Arguments: redactor.RedactString(call.Function.Arguments),
				Result:    redactor.RedactString(out),
				Duration:  time.Since(start),
			}
			toolPayload := out
			if err != nil {
				rec.Error = redactor.RedactString(err.Error())
				if toolPayload == "" {
					toolPayload = fmt.Sprintf(`{"error":%q}`, rec.Error)
				}
			} else {
				result.Evidence.CalledTools[call.Function.Name] = true
				result.Evidence.ToolCallCounts[call.Function.Name]++
			}
			toolPayload = redactor.RedactString(toolPayload)
			result.Turns[len(result.Turns)-1].ToolRecords = append(result.Turns[len(result.Turns)-1].ToolRecords, rec)
			if l.OnToolResult != nil {
				l.OnToolResult(rec, &result.Evidence)
			}
			messages = append(messages, schema.ToolMessage(toolPayload, call.ID, schema.WithToolName(call.Function.Name)))
			if err != nil && (l.FailOnToolError || ctx.Err() != nil) {
				result.Usage = ledger.Snapshot()
				return result, err
			}
		}
	}
	result.Usage = ledger.Snapshot()
	return result, errors.New("review exceeded maximum turns")
}

// DecodeOutput parses JSON from an assistant response, stripping optional
// ```json ... ``` markdown code fences cleanly.
func DecodeOutput[T any](content string) (T, error) {
	var out T
	s := strings.TrimSpace(content)
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			s = s[nl+1:]
		}
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	err := json.Unmarshal([]byte(s), &out)
	return out, err
}

func isTransientGenerateErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"429", "500", "502", "503", "504",
		"rate limit", "too many requests", "overloaded", "server_error", "upstream_error",
		"request could not be completed",
		"timeout", "timed out", "eof", "connection reset", "broken pipe",
		"temporarily unavailable", "bad gateway", "service unavailable", "gateway timeout",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func generateWithRetry(ctx context.Context, m model.ToolCallingChatModel, messages []*schema.Message) (*schema.Message, error) {
	backoffs := []time.Duration{time.Second}
	var lastErr error
	for attempt := 0; attempt < len(backoffs)+1; attempt++ {
		msg, err := m.Generate(ctx, messages)
		if err == nil {
			return msg, nil
		}
		lastErr = err
		if attempt >= len(backoffs) || ctx.Err() != nil || !isTransientGenerateErr(err) {
			return nil, err
		}
		t := time.NewTimer(backoffs[attempt])
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return nil, lastErr
}
