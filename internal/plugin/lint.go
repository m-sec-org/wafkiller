package plugin

import (
	"fmt"
	"regexp"
	"strings"

	"wafbps/internal/model"
)

type LintIssue struct {
	Level   string
	Message string
}

var multipartBoundaryPattern = regexp.MustCompile(`boundary=([^;]+)`)

func Lint(raw string, p model.Plugin) []LintIssue {
	issues := make([]LintIssue, 0)
	trimmedRaw := strings.TrimSpace(raw)
	host := strings.TrimSpace(p.Host)
	contentType := ""
	for key, value := range p.Headers {
		if strings.EqualFold(strings.TrimSpace(key), "Content-Type") {
			contentType = strings.TrimSpace(value)
			break
		}
	}

	if strings.Contains(raw, `\r\n`) && !strings.Contains(raw, "\nHost: ") {
		issues = append(issues, LintIssue{
			Level:   "error",
			Message: "HTTP 报文疑似被写成单行 \\r\\n 转义字符串，解析器无法按真实多行报文处理。",
		})
	}

	if host == "" {
		issues = append(issues, LintIssue{
			Level:   "warning",
			Message: "缺少 Host 头，建议显式写成 Host: {{TARGET_HOST_HEADER}}。",
		})
	} else if !strings.Contains(host, "{{TARGET_HOST_HEADER}}") {
		if strings.Contains(host, "{{TARGET_HOST}}") {
			issues = append(issues, LintIssue{
				Level:   "warning",
				Message: "Host 头建议使用 {{TARGET_HOST_HEADER}}，它比 {{TARGET_HOST}} 更贴近真实请求。",
			})
		} else {
			issues = append(issues, LintIssue{
				Level:   "error",
				Message: "Host 头不是动态变量，规则请求可能打到错误主机；请使用 {{TARGET_HOST_HEADER}}。",
			})
		}
	}

	if ua := headerValue(p.Headers, "User-Agent"); ua == "" {
		issues = append(issues, LintIssue{
			Level:   "warning",
			Message: "缺少 User-Agent，建议写成 User-Agent: {{USER_AGENT}}，尽量贴近真实浏览器请求。",
		})
	}

	if headerValue(p.Headers, "Accept") != "" || headerValue(p.Headers, "Origin") != "" || headerValue(p.Headers, "Referer") != "" {
		issues = append(issues, LintIssue{
			Level:   "warning",
			Message: "规则包含 Accept/Origin/Referer；除非该绕过技巧明确依赖这些头，否则建议删除以减少与原始请求的差异。",
		})
	}

	if strings.EqualFold(headerValue(p.Headers, "Transfer-Encoding"), "chunked") && strings.TrimSpace(p.Body) == "" {
		issues = append(issues, LintIssue{
			Level:   "error",
			Message: "Transfer-Encoding: chunked 已设置，但请求体为空。",
		})
	}

	if strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		match := multipartBoundaryPattern.FindStringSubmatch(contentType)
		if len(match) < 2 || strings.TrimSpace(match[1]) == "" {
			issues = append(issues, LintIssue{
				Level:   "error",
				Message: "multipart/form-data 缺少有效 boundary 参数。",
			})
		} else {
			boundary := strings.Trim(strings.TrimSpace(match[1]), `"`)
			if !strings.Contains(p.Body, boundary) {
				issues = append(issues, LintIssue{
					Level:   "error",
					Message: fmt.Sprintf("multipart boundary=%s 与 body 不一致，body 中没有找到对应边界。", boundary),
				})
			}
		}
	}

	if trimmedRaw == "" {
		issues = append(issues, LintIssue{
			Level:   "error",
			Message: "规则内容为空。",
		})
	}

	return issues
}

func HasBlockingIssues(issues []LintIssue) bool {
	for _, issue := range issues {
		if strings.EqualFold(issue.Level, "error") {
			return true
		}
	}
	return false
}

func RenderLintWarnings(issues []LintIssue) []string {
	if len(issues) == 0 {
		return nil
	}
	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		prefix := "提示"
		if strings.EqualFold(issue.Level, "error") {
			prefix = "错误"
		}
		lines = append(lines, fmt.Sprintf("[%s] %s", prefix, strings.TrimSpace(issue.Message)))
	}
	return lines
}

func headerValue(headers map[string]string, key string) string {
	for current, value := range headers {
		if strings.EqualFold(strings.TrimSpace(current), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
