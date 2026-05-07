package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *Client) runZhipuTurn(ctx context.Context, req TurnRequest) (TurnResult, error) {
	if c == nil || !c.Ready() {
		return TurnResult{}, fmt.Errorf("尚未配置智谱 API Key")
	}
	if strings.TrimSpace(req.UserInput) == "" {
		return TurnResult{}, fmt.Errorf("对话输入不能为空")
	}

	tools := make([]zhipuTool, 0, len(req.Tools))
	handlers := make(map[string]func(context.Context, json.RawMessage) (string, error), len(req.Tools))
	for _, tool := range req.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" || tool.Handler == nil {
			continue
		}
		handlers[name] = tool.Handler
		tools = append(tools, zhipuTool{
			Type: "function",
			Function: zhipuToolFunction{
				Name:        name,
				Description: strings.TrimSpace(tool.Description),
				Parameters:  tool.Parameters,
			},
		})
	}

	messages := make([]zhipuChatMessage, 0, len(req.Messages)+2)
	if strings.TrimSpace(req.Instructions) != "" {
		messages = append(messages, zhipuChatMessage{
			Role:    "system",
			Content: strings.TrimSpace(req.Instructions),
		})
	}
	for _, msg := range req.Messages {
		role := strings.TrimSpace(msg.Role)
		content := strings.TrimSpace(msg.Content)
		if role == "" || content == "" {
			continue
		}
		messages = append(messages, zhipuChatMessage{
			Role:    role,
			Content: content,
		})
	}
	messages = append(messages, zhipuChatMessage{
		Role:    "user",
		Content: strings.TrimSpace(req.UserInput),
	})

	result := TurnResult{}
	for step := 0; step < 8; step++ {
		resp, err := c.createZhipuChatCompletion(ctx, zhipuChatRequest{
			Model:    c.settings.Model,
			Messages: messages,
			Tools:    tools,
		})
		if err != nil {
			return TurnResult{}, err
		}
		if len(resp.Choices) == 0 {
			return TurnResult{}, fmt.Errorf("智谱未返回有效结果")
		}

		msg := resp.Choices[0].Message
		text := strings.TrimSpace(zhipuContentText(msg.Content))
		if text != "" {
			result.AssistantText = text
		}

		if len(msg.ToolCalls) == 0 {
			if strings.TrimSpace(result.AssistantText) == "" {
				result.AssistantText = "我已经完成这次处理。"
			}
			return result, nil
		}

		messages = append(messages, zhipuChatMessage{
			Role:      "assistant",
			Content:   msg.Content,
			ToolCalls: msg.ToolCalls,
		})
		for _, toolCall := range msg.ToolCalls {
			handler := handlers[strings.TrimSpace(toolCall.Function.Name)]
			output := `{"ok":false,"error":"未找到对应工具"}`
			if handler != nil {
				toolOutput, err := handler(ctx, json.RawMessage(toolCall.Function.Arguments))
				if err != nil {
					output = fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())
				} else if strings.TrimSpace(toolOutput) != "" {
					output = toolOutput
				} else {
					output = `{"ok":true}`
				}
			}
			messages = append(messages, zhipuChatMessage{
				Role:       "tool",
				ToolCallID: toolCall.ID,
				Content:    output,
			})
		}
	}

	if strings.TrimSpace(result.AssistantText) == "" {
		result.AssistantText = "本轮工具调用已完成，但没有生成最终答复。"
	}
	return result, nil
}

func (c *Client) createZhipuChatCompletion(ctx context.Context, req zhipuChatRequest) (zhipuChatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return zhipuChatResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.settings.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return zhipuChatResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.settings.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return zhipuChatResponse{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return zhipuChatResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zhipuChatResponse{}, friendlyZhipuError(resp.StatusCode, data)
	}

	out := zhipuChatResponse{}
	if err := json.Unmarshal(data, &out); err != nil {
		return zhipuChatResponse{}, err
	}
	return out, nil
}

func friendlyZhipuError(statusCode int, data []byte) error {
	body := strings.TrimSpace(string(data))
	if body == "" {
		return fmt.Errorf("智谱调用失败，请稍后重试")
	}
	payload := responseErrorEnvelope{}
	if err := json.Unmarshal(data, &payload); err != nil || strings.TrimSpace(payload.Error.Message) == "" {
		return fmt.Errorf("智谱调用失败：%s", body)
	}
	message := strings.TrimSpace(payload.Error.Message)
	switch statusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("智谱 API Key 无效或已失效，请检查大模型配置")
	case http.StatusForbidden:
		return fmt.Errorf("当前智谱 Key 没有权限访问该模型或接口，请检查项目权限")
	case http.StatusTooManyRequests:
		return fmt.Errorf("智谱请求过于频繁，请稍后再试")
	}
	return fmt.Errorf("智谱调用失败：%s", message)
}

func zhipuContentText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []any:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			if m, ok := item.(map[string]any); ok {
				if text, ok := m["text"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, strings.TrimSpace(text))
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

type zhipuChatRequest struct {
	Model    string             `json:"model"`
	Messages []zhipuChatMessage `json:"messages"`
	Tools    []zhipuTool        `json:"tools,omitempty"`
}

type zhipuChatMessage struct {
	Role       string           `json:"role"`
	Content    any              `json:"content,omitempty"`
	ToolCalls  []zhipuToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type zhipuTool struct {
	Type     string             `json:"type"`
	Function zhipuToolFunction  `json:"function"`
}

type zhipuToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type zhipuToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function zhipuToolCallFunction  `json:"function"`
}

type zhipuToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type zhipuChatResponse struct {
	Choices []zhipuChoice `json:"choices"`
}

type zhipuChoice struct {
	Message zhipuChatMessage `json:"message"`
}
