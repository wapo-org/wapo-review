package visual

import (
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type stubMultimodalModel struct {
	reply string
	err   error
	seen  []*schema.Message
}

func (m *stubMultimodalModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}
func (m *stubMultimodalModel) Generate(_ context.Context, msgs []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.seen = msgs
	if m.err != nil {
		return nil, m.err
	}
	return &schema.Message{Role: schema.Assistant, Content: m.reply}, nil
}
func (m *stubMultimodalModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("not implemented")
}

func writeTinyPNG(t *testing.T, p string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

func TestVisualScorerMultimodalModelAndGracefulDegradation(t *testing.T) {
	sheet := filepath.Join(t.TempDir(), "sheet.png")
	writeTinyPNG(t, sheet)

	mm := &stubMultimodalModel{
		reply: "```json\n{\"score\":88,\"verdict\":\"pass\",\"issues\":[{\"severity\":\"low\",\"description\":\"slight padding mismatch\",\"location\":\"header\"}],\"summary\":\"Looks clean\"}\n```",
	}
	res, err := (VisualScorer{Model: mm}).Score(context.Background(), VisualScoreRequest{
		ContactSheetPath: sheet,
		PRSummary:        "Update dashboard header",
	})
	if err != nil {
		t.Fatalf("VisualScorer.Score failed: %v", err)
	}
	if res.Score != 88 || res.Verdict != "pass" || len(res.Issues) != 1 {
		t.Fatalf("unexpected score result: %+v", res)
	}
	if len(mm.seen) != 1 || len(mm.seen[0].MultiContent) != 2 ||
		mm.seen[0].MultiContent[1].Type != schema.ChatMessagePartTypeImageURL ||
		!strings.HasPrefix(mm.seen[0].MultiContent[1].ImageURL.URL, "data:image/png;base64,") {
		t.Fatalf("expected multimodal PNG data URL part, got %+v", mm.seen)
	}

	// Graceful degradation on model error.
	degraded, err := (VisualScorer{Model: &stubMultimodalModel{err: errors.New("vision down")}}).Score(context.Background(), VisualScoreRequest{ContactSheetPath: sheet})
	if err != nil || degraded.Verdict != "unavailable" {
		t.Fatalf("expected unavailable fallback on vision error, got %+v err=%v", degraded, err)
	}
}
