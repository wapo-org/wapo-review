package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// responsesChatModel implements Eino's model.ToolCallingChatModel against the
// OpenAI Responses API (`POST <BaseURL>/responses`), which custom Codex /
// OpenAI-compatible proxies using `wire_api = "responses"` speak.
type responsesChatModel struct {
	baseURL         string
	apiKey          string
	modelName       string
	reasoningEffort string
	maxTokens       int
	client          *http.Client
	tools           []*schema.ToolInfo
}

func newResponsesChatModel(cfg ProviderConfig) model.ToolCallingChatModel {
	cli := httpClientWithHeaders(cfg.HTTPClient, cfg.ExtraHeaders, cfg.Timeout)
	if cli == nil {
		cli = &http.Client{Timeout: cfg.Timeout}
	}
	return &responsesChatModel{
		baseURL:         strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:          cfg.APIKey,
		modelName:       cfg.Model,
		reasoningEffort: strings.ToLower(strings.TrimSpace(cfg.ReasoningEffort)),
		maxTokens:       cfg.MaxTokens,
		client:          cli,
	}
}

func (m *responsesChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	cp := *m
	cp.tools = append([]*schema.ToolInfo(nil), tools...)
	return &cp, nil
}

func (m *responsesChatModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return nil, errors.New("streaming not implemented for openai-responses adapter; use Generate")
}

func (m *responsesChatModel) Generate(ctx context.Context, msgs []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	var instructions []string
	var input []any

	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		switch msg.Role {
		case schema.System:
			if strings.TrimSpace(msg.Content) != "" {
				instructions = append(instructions, msg.Content)
			}
		case schema.User:
			if len(msg.MultiContent) > 0 {
				var parts []map[string]any
				for _, part := range msg.MultiContent {
					switch part.Type {
					case schema.ChatMessagePartTypeText:
						parts = append(parts, map[string]any{"type": "input_text", "text": part.Text})
					case schema.ChatMessagePartTypeImageURL:
						if part.ImageURL != nil {
							parts = append(parts, map[string]any{"type": "input_image", "image_url": part.ImageURL.URL})
						}
					}
				}
				input = append(input, map[string]any{"role": "user", "content": parts})
			} else {
				input = append(input, map[string]any{"role": "user", "content": msg.Content})
			}
		case schema.Assistant:
			if items, ok := msg.Extra["openai_responses_output_items"].([]map[string]any); ok && len(items) > 0 {
				for _, item := range items {
					input = append(input, item)
				}
				break
			}
			if reasoning, ok := msg.Extra["openai_responses_reasoning_items"].([]map[string]any); ok {
				for _, item := range reasoning {
					input = append(input, item)
				}
			}
			if strings.TrimSpace(msg.Content) != "" {
				input = append(input, map[string]any{"role": "assistant", "content": msg.Content})
			}
			for _, tc := range msg.ToolCalls {
				callID := tc.ID
				if callID == "" {
					callID = "call_" + tc.Function.Name
				}
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   callID,
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				})
			}
		case schema.Tool:
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": msg.ToolCallID,
				"output":  msg.Content,
			})
		}
	}

	payload := map[string]any{
		"model":   m.modelName,
		"input":   input,
		"store":   false,
		"include": []string{"reasoning.encrypted_content"},
	}
	if len(instructions) > 0 {
		payload["instructions"] = strings.Join(instructions, "\n\n")
	}
	if m.maxTokens > 0 {
		payload["max_output_tokens"] = m.maxTokens
	}
	if m.reasoningEffort != "" {
		payload["reasoning"] = map[string]any{"effort": m.reasoningEffort}
	}
	if len(m.tools) > 0 {
		var toolDefs []map[string]any
		for _, t := range m.tools {
			params := map[string]any{"type": "object", "properties": map[string]any{}}
			if t.ParamsOneOf != nil {
				if js, err := t.ParamsOneOf.ToJSONSchema(); err == nil && js != nil {
					if raw, err := json.Marshal(js); err == nil {
						params = flattenToolSchema(raw)
					}
				}
			}
			toolDefs = append(toolDefs, map[string]any{
				"type":        "function",
				"name":        t.Name,
				"description": t.Desc,
				"parameters":  params,
			})
		}
		payload["tools"] = toolDefs
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint := m.baseURL + "/responses"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.apiKey)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai-responses HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		OutputText        string `json:"output_text"`
		Status            string `json:"status"`
		IncompleteDetails *struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Output []struct {
			Type             string `json:"type"`
			EncryptedContent string `json:"encrypted_content,omitempty"`
			Summary          []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"summary"`
			CallID    string `json:"call_id"`
			ID        string `json:"id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Content   []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage struct {
			InputTokens        int `json:"input_tokens"`
			OutputTokens       int `json:"output_tokens"`
			TotalTokens        int `json:"total_tokens"`
			InputTokensDetails struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
			OutputTokensDetails struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"output_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("decode openai-responses body: %w", err)
	}
	if parsed.Status == "incomplete" {
		reason := "unknown reason"
		if parsed.IncompleteDetails != nil && parsed.IncompleteDetails.Reason != "" {
			reason = parsed.IncompleteDetails.Reason
		}
		return nil, fmt.Errorf("incomplete response: %s", reason)
	}

	out := &schema.Message{
		Role: schema.Assistant,
		ResponseMeta: &schema.ResponseMeta{
			Usage: &schema.TokenUsage{
				PromptTokens:     parsed.Usage.InputTokens,
				CompletionTokens: parsed.Usage.OutputTokens,
				TotalTokens:      parsed.Usage.TotalTokens,
				PromptTokenDetails: schema.PromptTokenDetails{
					CachedTokens: parsed.Usage.InputTokensDetails.CachedTokens,
				},
				CompletionTokensDetails: schema.CompletionTokensDetails{
					ReasoningTokens: parsed.Usage.OutputTokensDetails.ReasoningTokens,
				},
			},
		},
	}

	var textParts []string
	var reasoningItems []map[string]any
	var orderedOutput []map[string]any
	for _, item := range parsed.Output {
		switch item.Type {
		case "reasoning":
			rItem := map[string]any{"type": "reasoning", "id": item.ID, "summary": item.Summary}
			if item.EncryptedContent != "" {
				rItem["encrypted_content"] = item.EncryptedContent
			}
			reasoningItems = append(reasoningItems, rItem)
			orderedOutput = append(orderedOutput, rItem)
		case "message":
			var msgTexts []string
			for _, c := range item.Content {
				if (c.Type == "output_text" || c.Type == "text") && c.Text != "" {
					textParts = append(textParts, c.Text)
					msgTexts = append(msgTexts, c.Text)
				}
			}
			if len(msgTexts) > 0 {
				orderedOutput = append(orderedOutput, map[string]any{
					"role":    "assistant",
					"content": strings.Join(msgTexts, "\n"),
				})
			}
		case "function_call":
			cid := item.CallID
			if cid == "" {
				cid = item.ID
			}
			out.ToolCalls = append(out.ToolCalls, schema.ToolCall{
				ID:   cid,
				Type: "function",
				Function: schema.FunctionCall{
					Name:      item.Name,
					Arguments: item.Arguments,
				},
			})
			orderedOutput = append(orderedOutput, map[string]any{
				"type":      "function_call",
				"call_id":   cid,
				"name":      item.Name,
				"arguments": item.Arguments,
			})
		}
	}
	if len(reasoningItems) > 0 || len(orderedOutput) > 0 {
		out.Extra = map[string]any{}
		if len(reasoningItems) > 0 {
			out.Extra["openai_responses_reasoning_items"] = reasoningItems
		}
		if len(orderedOutput) > 0 {
			out.Extra["openai_responses_output_items"] = orderedOutput
		}
	}
	if len(textParts) > 0 {
		out.Content = strings.Join(textParts, "\n")
	} else {
		out.Content = parsed.OutputText
	}
	return out, nil
}

// flattenToolSchema dereferences a root `$ref` (`#/$defs/<Name>`) produced by
// jsonschema.Reflect so OpenAI Responses API always sees a top-level
// `{"type":"object","properties":{...}}` schema without empty placeholder fields.
func flattenToolSchema(raw []byte) map[string]any {
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	if ref, ok := parsed["$ref"].(string); ok {
		var defs map[string]any
		var name string
		if strings.HasPrefix(ref, "#/$defs/") {
			name = strings.TrimPrefix(ref, "#/$defs/")
			defs, _ = parsed["$defs"].(map[string]any)
		} else if strings.HasPrefix(ref, "#/definitions/") {
			name = strings.TrimPrefix(ref, "#/definitions/")
			defs, _ = parsed["definitions"].(map[string]any)
		}
		if defs != nil {
			if target, ok := defs[name].(map[string]any); ok {
				flat := make(map[string]any, len(target)+1)
				for k, v := range target {
					flat[k] = v
				}
				if len(defs) > 1 {
					flat["$defs"] = defs
				}
				parsed = flat
			}
		}
	}
	delete(parsed, "$schema")
	if _, ok := parsed["type"]; !ok {
		parsed["type"] = "object"
	}
	if _, ok := parsed["properties"]; !ok {
		parsed["properties"] = map[string]any{}
	}
	return parsed
}
