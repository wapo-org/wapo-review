package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/workspace"
)

type skepticMock struct{ responses []*schema.Message }

func (m *skepticMock) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *skepticMock) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	if len(m.responses) == 0 {
		return nil, errors.New("no scripted response")
	}
	r := m.responses[0]
	m.responses = m.responses[1:]
	return r, nil
}
func (m *skepticMock) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("unused")
}

func TestRunAdversarialGateRecordsKeepAndDrop(t *testing.T) {
	findings := []workspace.VerifiedFinding{{ID: "valid", File: "x.go", Title: "Concrete bug"}, {ID: "bad", File: "x.go", Title: "Garbled"}}
	args := func(id, verdict, reason string) string {
		b, _ := json.Marshal(verdictArgs{FindingID: id, Verdict: verdict, Reason: reason})
		return string(b)
	}
	mock := &skepticMock{responses: []*schema.Message{{Role: schema.Assistant, ToolCalls: []schema.ToolCall{
		{ID: "1", Function: schema.FunctionCall{Name: "record_verdict", Arguments: args("valid", "keep", "Confirmed by caller flow.")}},
		{ID: "2", Function: schema.FunctionCall{Name: "record_verdict", Arguments: args("bad", "drop", "The quoted expression is not present in the source.")}},
	}}, {Role: schema.Assistant, Content: "done"}}}
	report := RunAdversarialGate(context.Background(), func(context.Context) (model.ToolCallingChatModel, error) { return mock, nil }, t.TempDir(), nil, findings, 1, nil)
	if len(report.Kept) != 1 || report.Kept[0].ID != "valid" || len(report.Dropped) != 1 || report.Dropped[0].Reason != "The quoted expression is not present in the source." {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestRunAdversarialGateFailsOpen(t *testing.T) {
	f := []workspace.VerifiedFinding{{ID: "one"}, {ID: "two"}}
	report := RunAdversarialGate(context.Background(), func(context.Context) (model.ToolCallingChatModel, error) { return nil, errors.New("factory failed") }, t.TempDir(), nil, f, 1, nil)
	if len(report.Kept) != 2 {
		t.Fatalf("factory error dropped findings: %+v", report)
	}
	mock := &skepticMock{responses: []*schema.Message{{Role: schema.Assistant, ToolCalls: []schema.ToolCall{{ID: "1", Function: schema.FunctionCall{Name: "record_verdict", Arguments: `{"finding_id":"one","verdict":"drop","reason":"disproved"}`}}}}}}
	report = RunAdversarialGate(context.Background(), func(context.Context) (model.ToolCallingChatModel, error) { return mock, nil }, t.TempDir(), nil, f, 1, nil)
	if len(report.Kept) != 2 || len(report.Dropped) != 0 {
		t.Fatalf("missing verdict did not fail open: %+v", report)
	}
}

var _ tool.InvokableTool = verdictTool{}
