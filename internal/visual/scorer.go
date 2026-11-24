package visual

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
	"github.com/wapo-org/wapo-review/internal/agent"
)

type VisualScoreRequest struct {
	ContactSheetPath string
	FramePaths       []string
	PRSummary        string
	ConsoleErrors    []string
	FailedRequests   []string
	RepoMemory       string
}

type VisualIssue struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
}

type VisualScoreResult struct {
	Score   int           `json:"score"`
	Verdict string        `json:"verdict"`
	Issues  []VisualIssue `json:"issues"`
	Summary string        `json:"summary"`
}

type VisionClient interface {
	Score(ctx context.Context, prompt string, pngBytes []byte) (string, error)
}

// VisualScorer evaluates UI contact sheets or frames using either an Eino
// multimodal ToolCallingChatModel or a custom VisionClient.
type VisualScorer struct {
	Model  model.ToolCallingChatModel
	Client VisionClient
}

func (s VisualScorer) Score(ctx context.Context, r VisualScoreRequest) (VisualScoreResult, error) {
	if s.Model == nil && s.Client == nil {
		return VisualScoreResult{Verdict: "unavailable", Summary: "Vision scoring is unavailable"}, nil
	}
	p := r.ContactSheetPath
	if p == "" && len(r.FramePaths) > 0 {
		p = r.FramePaths[0]
	}
	if p == "" {
		return VisualScoreResult{}, errors.New("contact sheet or frame is required")
	}
	pngBytes, err := os.ReadFile(p)
	if err != nil {
		return VisualScoreResult{}, err
	}

	prompt := fmt.Sprintf(
		"Score the UI visual quality (layout, alignment, contrast, overflow, broken rendering) from 0 to 100. "+
			"Return ONLY JSON matching {\"score\":0..100,\"verdict\":\"pass|warn|fail\",\"issues\":[{\"severity\":\"...\",\"description\":\"...\",\"location\":\"...\"}],\"summary\":\"...\"}.\n"+
			"PR Summary: %s\nConsole Errors: %v\nFailed Requests: %v\nRepository Memory: %s",
		r.PRSummary, r.ConsoleErrors, r.FailedRequests, r.RepoMemory,
	)

	var raw string
	if s.Model != nil {
		msg, err := s.Model.Generate(ctx, []*schema.Message{ImageMessage(prompt, pngBytes)})
		if err != nil {
			return VisualScoreResult{Verdict: "unavailable", Summary: "Vision model request failed"}, nil
		}
		raw = msg.Content
	} else {
		raw, err = s.Client.Score(ctx, prompt, pngBytes)
		if err != nil {
			return VisualScoreResult{Verdict: "unavailable", Summary: "Vision scoring failed"}, nil
		}
	}

	out, err := agent.DecodeOutput[VisualScoreResult](raw)
	if err != nil {
		return VisualScoreResult{}, err
	}
	if out.Score < 0 || out.Score > 100 {
		return VisualScoreResult{}, errors.New("visual score outside 0..100")
	}
	return out, nil
}

// ImageMessage builds a multimodal Eino user message with both the text prompt
// and an inline base64 PNG image data URL part.
func ImageMessage(prompt string, png []byte) *schema.Message {
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	return &schema.Message{
		Role: schema.User,
		MultiContent: []schema.ChatMessagePart{
			{
				Type: schema.ChatMessagePartTypeText,
				Text: prompt,
			},
			{
				Type: schema.ChatMessagePartTypeImageURL,
				ImageURL: &schema.ChatMessageImageURL{
					URL:    dataURL,
					Detail: schema.ImageURLDetailHigh,
				},
			},
		},
	}
}
