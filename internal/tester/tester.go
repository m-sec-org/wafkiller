package tester

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"wafbps/internal/detector"
	"wafbps/internal/model"
	"wafbps/internal/netutil"
)

type Service struct {
	client    *http.Client
	transport *http.Transport
	settings  model.TesterSettings
	vars      map[string]string
}

func New(settings model.TesterSettings, vars map[string]string, proxyURL string) *Service {
	timeoutSeconds := settings.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	concurrency := settings.Concurrency
	if concurrency < 1 {
		concurrency = 100
	}
	poolSize := concurrency * 2
	if poolSize < 128 {
		poolSize = 128
	}
	transport := &http.Transport{
		Proxy:                 netutil.ConfiguredProxyFunc(proxyURL),
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: !settings.VerifyTLS},
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          poolSize * 2,
		MaxIdleConnsPerHost:   poolSize,
		MaxConnsPerHost:       poolSize,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Service{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		transport: transport,
		settings:  settings,
		vars:      vars,
	}
}

func (s *Service) CloseIdleConnections() {
	if s == nil || s.transport == nil {
		return
	}
	s.transport.CloseIdleConnections()
}

func (s *Service) Run(site model.Site, p model.Plugin) model.TestResult {
	return s.RunWithDetection(site, p, nil)
}

func (s *Service) RunWithDetection(site model.Site, p model.Plugin, detection *model.DetectionResult) model.TestResult {
	return s.RunWithDetectionContext(context.Background(), site, p, detection)
}

func (s *Service) RunWithDetectionContext(ctx context.Context, site model.Site, p model.Plugin, detection *model.DetectionResult) model.TestResult {
	result := model.TestResult{
		Site:   site,
		Plugin: p,
		RunAt:  time.Now(),
	}

	req, body, err := s.buildRequest(ctx, site, p, detection)
	if err != nil {
		result.Error = err.Error()
		result.Verdict = "构建失败"
		return result
	}
	result.SentRequest = renderRequestPacket(req, body)

	start := time.Now()
	resp, err := s.client.Do(req)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		result.Verdict = "请求异常"
		return result
	}
	defer closeResponseBody(resp.Body)

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.settings.MaxBodyPreview)))
	result.StatusCode = resp.StatusCode
	result.ResponseBody = string(responseBody)
	result.ResponseHead = flattenHeaders(resp.Header)
	result.Verdict, result.MatchedRule, result.BaselineSim, result.BlockedSim, result.DiffRatio = s.classify(req.URL.String(), resp.StatusCode, result.ResponseHead, result.ResponseBody, p, detection)

	return result
}

func closeResponseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64*1024))
	_ = body.Close()
}

func (s *Service) buildRequest(ctx context.Context, site model.Site, p model.Plugin, detection *model.DetectionResult) (*http.Request, string, error) {
	baseURL := ""
	if detection != nil {
		baseURL = strings.TrimSpace(detection.DetectedURL)
		if baseURL == "" {
			baseURL = strings.TrimSpace(detection.Baseline.URL)
		}
	}
	if baseURL == "" {
		baseURL = strings.TrimSpace(site.URL)
	}
	if baseURL == "" {
		host := strings.TrimSpace(site.Host)
		if host == "" {
			host = strings.TrimSpace(site.Domain)
		}
		if host == "" {
			return nil, "", fmt.Errorf("site has no host")
		}
		baseURL = fmt.Sprintf("%s://%s", s.settings.DefaultScheme, host)
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, "", err
	}

	uri := s.applyVariables(p.RequestURI, site, p)
	targetURL, err := url.Parse(uri)
	if err != nil {
		return nil, "", err
	}
	if !targetURL.IsAbs() {
		targetURL = base.ResolveReference(targetURL)
	}
	if p.Scheme != "" {
		targetURL.Scheme = p.Scheme
	}

	extraVars := requestVariableMap(base, targetURL, site)
	body := s.applyVariablesWithExtra(p.Body, site, p, extraVars)
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(p.Method), targetURL.String(), bytes.NewBufferString(body))
	if err != nil {
		return nil, "", err
	}

	host := s.applyVariablesWithExtra(p.Host, site, p, extraVars)
	if host != "" {
		req.Host = host
	}

	for key, value := range p.Headers {
		headerValue := s.applyVariablesWithExtra(value, site, p, extraVars)
		req.Header.Set(textproto.CanonicalMIMEHeaderKey(key), headerValue)
	}
	if req.Header.Get("User-Agent") == "" && s.vars["USER_AGENT"] != "" {
		req.Header.Set("User-Agent", s.vars["USER_AGENT"])
	}
	if body != "" && req.Header.Get("Content-Length") == "" {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return req, body, nil
}

func (s *Service) applyVariables(raw string, site model.Site, p model.Plugin) string {
	return s.applyVariablesWithExtra(raw, site, p, nil)
}

func (s *Service) applyVariablesWithExtra(raw string, site model.Site, p model.Plugin, extra map[string]string) string {
	values := map[string]string{
		"TARGET_URL":    site.URL,
		"TARGET_HOST":   site.Host,
		"TARGET_DOMAIN": site.Domain,
		"TARGET_IP":     site.IP,
		"TARGET_PORT":   site.Port,
		"TARGET_TITLE":  site.Title,
		"TARGET_WAF":    site.WAF,
		"PLUGIN_NAME":   p.Name,
		"TIMESTAMP":     strconv.FormatInt(time.Now().Unix(), 10),
		"RAND":          strconv.FormatInt(time.Now().UnixNano(), 36),
	}
	for key, value := range extra {
		values[key] = value
	}
	for key, value := range s.vars {
		values[key] = value
	}

	out := raw
	for key, value := range values {
		out = strings.ReplaceAll(out, "{{"+key+"}}", value)
	}
	return decodeRuleEscapes(out)
}

func decodeRuleEscapes(raw string) string {
	if raw == "" {
		return raw
	}
	raw = strings.ReplaceAll(raw, `\x00`, string([]byte{0}))
	raw = strings.ReplaceAll(raw, `\0`, string([]byte{0}))
	return raw
}

func requestVariableMap(base *url.URL, target *url.URL, site model.Site) map[string]string {
	values := map[string]string{}

	if target != nil {
		values["TARGET_URL"] = target.String()
		values["TARGET_HOST"] = target.Host
		values["TARGET_HOST_HEADER"] = target.Host
		if target.Scheme != "" && target.Host != "" {
			values["TARGET_ORIGIN"] = target.Scheme + "://" + target.Host
		}
	}

	if base != nil {
		if values["TARGET_URL"] == "" {
			values["TARGET_URL"] = base.String()
		}
		if values["TARGET_HOST"] == "" {
			values["TARGET_HOST"] = base.Host
		}
		if values["TARGET_HOST_HEADER"] == "" {
			values["TARGET_HOST_HEADER"] = base.Host
		}
		if values["TARGET_ORIGIN"] == "" && base.Scheme != "" && base.Host != "" {
			values["TARGET_ORIGIN"] = base.Scheme + "://" + base.Host
		}
		baseline := *base
		query := baseline.Query()
		query.Set("id", "1")
		baseline.Path = "/"
		baseline.RawQuery = query.Encode()
		values["TARGET_BASELINE_URL"] = baseline.String()
	}

	if values["TARGET_HOST"] == "" {
		values["TARGET_HOST"] = site.Host
		values["TARGET_HOST_HEADER"] = site.Host
	}
	if values["TARGET_URL"] == "" {
		values["TARGET_URL"] = site.URL
	}
	if values["TARGET_ORIGIN"] == "" && strings.TrimSpace(values["TARGET_URL"]) != "" {
		if parsed, err := url.Parse(values["TARGET_URL"]); err == nil && parsed != nil && parsed.Scheme != "" && parsed.Host != "" {
			values["TARGET_ORIGIN"] = parsed.Scheme + "://" + parsed.Host
		}
	}
	if values["TARGET_BASELINE_URL"] == "" && strings.TrimSpace(values["TARGET_ORIGIN"]) != "" {
		values["TARGET_BASELINE_URL"] = values["TARGET_ORIGIN"] + "/?id=1"
	}

	return values
}

func (s *Service) classify(requestURL string, status int, headers string, body string, p model.Plugin, detection *model.DetectionResult) (string, string, float64, float64, float64) {
	if strings.EqualFold(strings.TrimSpace(p.ValidationMode), "baseline_similarity") && detection != nil {
		threshold := p.SimilarityThreshold
		if threshold <= 0 {
			threshold = 0.92
		}
		current := responseSnapshotFromResult(requestURL, status, headers, body)
		baselineSim := detector.ResponseSimilarity(detection.Baseline, current)
		blockedSim := 0.0
		if detection.HasWAF {
			blockedSim = detector.ResponseSimilarity(detection.BlockedResponse, current)
		}
		diffRatio := 1 - baselineSim
		if diffRatio < 0 {
			diffRatio = 0
		}

		matchedRule := fmt.Sprintf("基线相似度:%.2f", baselineSim)
		if blockedSim > 0 {
			matchedRule += fmt.Sprintf(" | 拦截相似度:%.2f", blockedSim)
		}
		matchedRule += fmt.Sprintf(" | 页面差异:%.0f%% | 阈值:%.2f", diffRatio*100, threshold)

		if isBaselineReplayPlugin(p) {
			replayThreshold := threshold
			if replayThreshold > 0.90 {
				replayThreshold = 0.90
			}
			if status == detection.Baseline.StatusCode {
				matchedRule += " | 基线回放"
				if len(body) == len(detection.Baseline.Body) {
					return "可能绕过", matchedRule + " | 长度一致", baselineSim, blockedSim, diffRatio
				}
				if baselineSim >= replayThreshold && baselineSim >= blockedSim {
					return "可能绕过", matchedRule, baselineSim, blockedSim, diffRatio
				}
			}
		}

		if baselineSim >= threshold && baselineSim >= blockedSim {
			return "可能绕过", matchedRule, baselineSim, blockedSim, diffRatio
		}
		for _, code := range s.settings.BlockStatusCodes {
			if code == status {
				return "已拦截", matchedRule + fmt.Sprintf(" | 状态码:%d", code), baselineSim, blockedSim, diffRatio
			}
		}
		lower := strings.ToLower(body)
		for _, keyword := range s.settings.BlockKeywords {
			if strings.Contains(lower, strings.ToLower(keyword)) {
				return "已拦截", matchedRule + fmt.Sprintf(" | 关键字:%s", keyword), baselineSim, blockedSim, diffRatio
			}
		}
		if blockedSim >= 0.9 && blockedSim > baselineSim {
			return "已拦截", matchedRule, baselineSim, blockedSim, diffRatio
		}
		return "需要复核", matchedRule, baselineSim, blockedSim, diffRatio
	}

	for _, code := range s.settings.BlockStatusCodes {
		if code == status {
			return "已拦截", fmt.Sprintf("状态码:%d", code), 0, 0, 0
		}
	}

	lower := strings.ToLower(body)
	for _, keyword := range s.settings.BlockKeywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return "已拦截", fmt.Sprintf("关键字:%s", keyword), 0, 0, 0
		}
	}

	if status >= 200 && status < 400 {
		return "可能绕过", "状态码:成功", 0, 0, 0
	}
	if status == 0 {
		return "无响应", "", 0, 0, 0
	}
	return "需要复核", fmt.Sprintf("状态码:%d", status), 0, 0, 0
}

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func responseSnapshotFromResult(requestURL string, status int, headers string, body string) model.ResponseSnapshot {
	title := ""
	if match := titlePattern.FindStringSubmatch(body); len(match) > 1 {
		title = strings.TrimSpace(match[1])
	}
	raw := fmt.Sprintf("HTTP/1.1 %d\n%s\n\n%s", status, headers, body)
	return model.ResponseSnapshot{
		URL:        requestURL,
		StatusCode: status,
		Headers:    headers,
		Body:       body,
		Title:      title,
		Raw:        raw,
	}
}

func flattenHeaders(headers http.Header) string {
	lines := make([]string, 0, len(headers))
	for key, values := range headers {
		lines = append(lines, key+": "+strings.Join(values, ", "))
	}
	return strings.Join(lines, "\n")
}

func renderRequestPacket(req *http.Request, body string) string {
	if req == nil {
		return ""
	}
	lines := []string{
		fmt.Sprintf("%s %s HTTP/1.1", req.Method, req.URL.RequestURI()),
	}
	if req.Host != "" {
		lines = append(lines, "Host: "+req.Host)
	} else if req.URL.Host != "" {
		lines = append(lines, "Host: "+req.URL.Host)
	}
	headerLines := make([]string, 0, len(req.Header))
	for key, values := range req.Header {
		headerLines = append(headerLines, key+": "+strings.Join(values, ", "))
	}
	sort.Strings(headerLines)
	lines = append(lines, headerLines...)
	lines = append(lines, "", body)
	return strings.Join(lines, "\n")
}

func isBaselineReplayPlugin(p model.Plugin) bool {
	if !strings.EqualFold(strings.TrimSpace(p.Method), http.MethodGet) {
		return false
	}
	uri := strings.TrimSpace(p.RequestURI)
	return uri == "/?id=1" || uri == "?id=1"
}
