package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"wafbps/internal/netutil"
)

type Settings struct {
	Provider        string
	APIKey          string
	BaseURL         string
	ProxyURL        string
	Model           string
	ReasoningEffort string
	TimeoutSeconds  int
}

type Message struct {
	Role    string
	Content string
}

type FunctionTool struct {
	Name        string
	Description string
	Parameters  map[string]any
	Handler     func(context.Context, json.RawMessage) (string, error)
}

type TurnRequest struct {
	Instructions string
	Messages     []Message
	UserInput    string
	Tools        []FunctionTool
}

type TurnResult struct {
	AssistantText string
}

type Client struct {
	settings   Settings
	httpClient *http.Client
}

func New(settings Settings) *Client {
	settings = normalizeSettings(settings)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = netutil.ConfiguredProxyFunc(settings.ProxyURL)
	return &Client{
		settings: settings,
		httpClient: &http.Client{
			Timeout:   time.Duration(settings.TimeoutSeconds) * time.Second,
			Transport: transport,
		},
	}
}

func normalizeSettings(settings Settings) Settings {
	settings.Provider = normalizeProvider(settings.Provider)
	if strings.TrimSpace(settings.APIKey) == "" {
		settings.APIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	}
	if strings.TrimSpace(settings.BaseURL) == "" {
		if settings.Provider == "zhipu" {
			settings.BaseURL = "https://open.bigmodel.cn/api/paas/v4"
		} else {
			settings.BaseURL = "https://api.openai.com/v1"
		}
	}
	settings.BaseURL = strings.TrimRight(strings.TrimSpace(settings.BaseURL), "/")
	if strings.TrimSpace(settings.Model) == "" {
		if settings.Provider == "zhipu" {
			settings.Model = "glm-5.1"
		} else {
			settings.Model = "gpt-5.4"
		}
	}
	if strings.TrimSpace(settings.ReasoningEffort) == "" {
		settings.ReasoningEffort = "low"
	}
	if settings.TimeoutSeconds <= 0 {
		settings.TimeoutSeconds = 90
	}
	return settings
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "zhipu", "zhipuai", "glm":
		return "zhipu"
	default:
		return "openai"
	}
}

func (c *Client) Ready() bool {
	return c != nil && strings.TrimSpace(c.settings.APIKey) != ""
}

func (c *Client) RunTurn(ctx context.Context, req TurnRequest) (TurnResult, error) {
	if normalizeProvider(c.settings.Provider) == "zhipu" {
		return c.runZhipuTurn(ctx, req)
	}
	return c.runOpenAITurn(ctx, req)
}

func (c *Client) runOpenAITurn(ctx context.Context, req TurnRequest) (TurnResult, error) {
	if c == nil || !c.Ready() {
		return TurnResult{}, fmt.Errorf("尚未配置大模型 API Key")
	}
	if strings.TrimSpace(req.UserInput) == "" {
		return TurnResult{}, fmt.Errorf("对话输入不能为空")
	}

	tools := make([]responseTool, 0, len(req.Tools))
	handlers := make(map[string]func(context.Context, json.RawMessage) (string, error), len(req.Tools))
	for _, tool := range req.Tools {
		name := strings.TrimSpace(tool.Name)
		if name == "" || tool.Handler == nil {
			continue
		}
		handlers[name] = tool.Handler
		tools = append(tools, responseTool{
			Type:        "function",
			Name:        name,
			Description: strings.TrimSpace(tool.Description),
			Strict:      true,
			Parameters:  tool.Parameters,
		})
	}

	input := make([]any, 0, len(req.Messages)+1)
	for _, msg := range req.Messages {
		role := strings.TrimSpace(msg.Role)
		content := strings.TrimSpace(msg.Content)
		if role == "" || content == "" {
			continue
		}
		input = append(input, map[string]any{
			"role":    role,
			"content": content,
		})
	}
	input = append(input, map[string]any{
		"role":    "user",
		"content": strings.TrimSpace(req.UserInput),
	})

	result := TurnResult{}
	for step := 0; step < 8; step++ {
		resp, err := c.createResponse(ctx, responseRequest{
			Model:             c.settings.Model,
			Instructions:      strings.TrimSpace(req.Instructions),
			Input:             input,
			Tools:             tools,
			ParallelToolCalls: true,
			Reasoning: &responseReasoning{
				Effort: c.settings.ReasoningEffort,
			},
		})
		if err != nil {
			return TurnResult{}, err
		}

		text := strings.TrimSpace(resp.OutputText)
		if text == "" {
			text = extractResponseText(resp.Output)
		}
		if text != "" {
			result.AssistantText = text
		}

		nextInput := make([]any, 0, len(resp.Output)*2)
		hasToolCall := false
		for _, raw := range resp.Output {
			nextInput = append(nextInput, raw)
			item := responseOutputMeta{}
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}
			if item.Type != "function_call" {
				continue
			}
			hasToolCall = true
			handler := handlers[strings.TrimSpace(item.Name)]
			output := `{"ok":false,"error":"未找到对应工具"}`
			if handler != nil {
				toolOutput, err := handler(ctx, json.RawMessage(item.Arguments))
				if err != nil {
					output = fmt.Sprintf(`{"ok":false,"error":%q}`, err.Error())
				} else if strings.TrimSpace(toolOutput) != "" {
					output = toolOutput
				} else {
					output = `{"ok":true}`
				}
			}
			nextInput = append(nextInput, map[string]any{
				"type":    "function_call_output",
				"call_id": item.CallID,
				"output":  output,
			})
		}

		if !hasToolCall {
			if strings.TrimSpace(result.AssistantText) == "" {
				result.AssistantText = "我已经完成这次处理。"
			}
			return result, nil
		}
		input = nextInput
	}

	if strings.TrimSpace(result.AssistantText) == "" {
		result.AssistantText = "本轮工具调用已完成，但没有生成最终答复。"
	}
	return result, nil
}

func (c *Client) createResponse(ctx context.Context, req responseRequest) (responseEnvelope, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return responseEnvelope{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.settings.BaseURL+"/responses", bytes.NewReader(body))
	if err != nil {
		return responseEnvelope{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.settings.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return responseEnvelope{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return responseEnvelope{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseEnvelope{}, friendlyOpenAIError(resp.StatusCode, data)
	}

	out := responseEnvelope{}
	if err := json.Unmarshal(data, &out); err != nil {
		return responseEnvelope{}, err
	}
	return out, nil
}

type responseErrorEnvelope struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Param   any    `json:"param"`
		Code    string `json:"code"`
	} `json:"error"`
}

func friendlyOpenAIError(statusCode int, data []byte) error {
	body := strings.TrimSpace(string(data))
	if body == "" {
		return fmt.Errorf("大模型调用失败，请稍后重试")
	}
	payload := responseErrorEnvelope{}
	if err := json.Unmarshal(data, &payload); err != nil || strings.TrimSpace(payload.Error.Message) == "" {
		return fmt.Errorf("大模型调用失败：%s", body)
	}
	message := strings.TrimSpace(payload.Error.Message)
	code := strings.TrimSpace(payload.Error.Code)
	switch code {
	case "insufficient_quota":
		return fmt.Errorf("当前 OpenAI API 额度不足，请检查 API Key、项目额度和 billing")
	case "invalid_function_parameters":
		return fmt.Errorf("智能体工具定义有误：%s", message)
	}
	switch statusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("OpenAI API Key 无效或已失效，请检查大模型配置")
	case http.StatusForbidden:
		return fmt.Errorf("当前 OpenAI Key 没有权限访问该模型或接口，请检查项目权限")
	case http.StatusTooManyRequests:
		return fmt.Errorf("OpenAI 请求过于频繁，请稍后再试")
	}
	return fmt.Errorf("大模型调用失败：%s", message)
}

func extractResponseText(items []json.RawMessage) string {
	lines := make([]string, 0)
	for _, raw := range items {
		item := responseMessageOutput{}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			if strings.TrimSpace(content.Text) == "" {
				continue
			}
			lines = append(lines, strings.TrimSpace(content.Text))
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

type responseRequest struct {
	Model             string             `json:"model"`
	Instructions      string             `json:"instructions,omitempty"`
	Input             []any              `json:"input"`
	Tools             []responseTool     `json:"tools,omitempty"`
	ParallelToolCalls bool               `json:"parallel_tool_calls,omitempty"`
	Reasoning         *responseReasoning `json:"reasoning,omitempty"`
}

type responseReasoning struct {
	Effort string `json:"effort,omitempty"`
}

type responseTool struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Strict      bool           `json:"strict,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type responseEnvelope struct {
	OutputText string            `json:"output_text"`
	Output     []json.RawMessage `json:"output"`
}

type responseOutputMeta struct {
	Type      string `json:"type"`
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type responseMessageOutput struct {
	Type    string                  `json:"type"`
	Content []responseMessageRecord `json:"content"`
}

type responseMessageRecord struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
