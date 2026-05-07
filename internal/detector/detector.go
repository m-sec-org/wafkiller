package detector

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	htmlcharset "golang.org/x/net/html/charset"

	"wafbps/internal/model"
	"wafbps/internal/netutil"
)

var tokenPattern = regexp.MustCompile(`[\p{L}\p{N}]+`)
var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type Service struct {
	client    *http.Client
	transport *http.Transport
	settings  model.TesterSettings
	vars      map[string]string
}

const ConnectionBlockedClusterKey = "cluster-connection-blocked"

func New(settings model.TesterSettings, vars map[string]string, proxyURL string) *Service {
	timeoutSeconds := settings.TimeoutSeconds
	if timeoutSeconds <= 0 || timeoutSeconds > 2 {
		timeoutSeconds = 2
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
		IdleConnTimeout:       20 * time.Second,
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

func (s *Service) Analyze(site model.Site) model.DetectionResult {
	return s.AnalyzeContext(context.Background(), site)
}

func (s *Service) ProbeBaseline(site model.Site) (string, model.ResponseSnapshot, error) {
	return s.ProbeBaselineContext(context.Background(), site)
}

func (s *Service) ProbeBaselineContext(ctx context.Context, site model.Site) (string, model.ResponseSnapshot, error) {
	return s.ProbeBaselineWithDetectionContext(ctx, site, nil)
}

func (s *Service) ProbeStoredBaselineContext(ctx context.Context, previous model.DetectionResult) (string, model.ResponseSnapshot, error) {
	target := strings.TrimSpace(previous.DetectedURL)
	if target == "" {
		target = strings.TrimSpace(previous.Baseline.URL)
	}
	if target == "" {
		return "", model.ResponseSnapshot{}, fmt.Errorf("missing stored baseline url")
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil || strings.TrimSpace(parsed.Host) == "" {
		return "", model.ResponseSnapshot{}, fmt.Errorf("invalid stored baseline url")
	}
	baselineURL := s.baselineURL(parsed)
	baseline, err := s.fetch(ctx, baselineURL)
	if err != nil {
		return "", model.ResponseSnapshot{}, err
	}
	return baselineURL, baseline, nil
}

func (s *Service) ProbeBaselineWithDetectionContext(ctx context.Context, site model.Site, previous *model.DetectionResult) (string, model.ResponseSnapshot, error) {
	candidates, err := s.candidateURLs(site)
	if previous != nil {
		candidates, err = s.candidateURLsWithDetection(site, *previous)
	}
	if err != nil {
		return "", model.ResponseSnapshot{}, err
	}

	var errors []string
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return "", model.ResponseSnapshot{}, ctx.Err()
		}
		baselineURL := s.baselineURL(candidate)
		baseline, baselineErr := s.fetch(ctx, baselineURL)
		if baselineErr == nil {
			return baselineURL, baseline, nil
		}
		if isCanceledRequest(ctx, baselineErr) {
			return "", model.ResponseSnapshot{}, context.Canceled
		}
		errors = append(errors, fmt.Sprintf("%s 原始页失败: %v", baselineURL, baselineErr))
	}

	if len(errors) == 0 {
		return "", model.ResponseSnapshot{}, fmt.Errorf("请求异常")
	}
	return "", model.ResponseSnapshot{}, fmt.Errorf(strings.Join(errors, " | "))
}

func (s *Service) candidateURLsWithDetection(site model.Site, previous model.DetectionResult) ([]*url.URL, error) {
	schemes := preferredSchemes(site, s.settings.DefaultScheme)
	candidates := make([]*url.URL, 0, 6)
	seen := map[string]struct{}{}

	addParsed := func(parsed *url.URL) {
		if parsed == nil || strings.TrimSpace(parsed.Host) == "" {
			return
		}
		key := parsed.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, parsed)
	}

	addReference := func(raw string) {
		parsed, err := s.parseReference(raw, schemes)
		if err != nil || parsed == nil {
			return
		}
		addParsed(parsed)
	}

	addReference(previous.DetectedURL)
	addReference(previous.Baseline.URL)

	siteCandidates, err := s.candidateURLs(site)
	if err != nil {
		if len(candidates) > 0 {
			return candidates, nil
		}
		return nil, err
	}
	for _, candidate := range siteCandidates {
		addParsed(candidate)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("site has no reachable url candidate")
	}
	return candidates, nil
}

func (s *Service) AnalyzeContext(ctx context.Context, site model.Site) model.DetectionResult {
	result := model.DetectionResult{
		Site:  site,
		RunAt: time.Now(),
	}

	candidates, err := s.candidateURLs(site)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	var errors []string
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			result.Error = "已停止"
			return result
		}

		baselineURL := s.baselineURL(candidate)
		baseline, baselineErr := s.fetch(ctx, baselineURL)
		if isCanceledRequest(ctx, baselineErr) {
			result.Error = "已停止"
			return result
		}
		if baselineErr != nil {
			errors = append(errors, fmt.Sprintf("%s 原始页失败: %v", baselineURL, baselineErr))
			continue
		}

		probeAURL := s.probeURL(candidate, "a")
		probeA, probeAErr := s.fetch(ctx, probeAURL)
		if isCanceledRequest(ctx, probeAErr) {
			result.Error = "已停止"
			return result
		}

		if ctx.Err() != nil {
			result.Error = "已停止"
			return result
		}

		probeBURL := s.probeURL(candidate, "b")
		probeB, probeBErr := s.fetch(ctx, probeBURL)
		if isCanceledRequest(ctx, probeBErr) {
			result.Error = "已停止"
			return result
		}

		if isConnectionBlocked(probeAErr) && isConnectionBlocked(probeBErr) {
			result.DetectedURL = baselineURL
			result.Baseline = baseline
			result.ProbeA = blockedConnectionSnapshot(probeAURL, probeAErr)
			result.ProbeB = blockedConnectionSnapshot(probeBURL, probeBErr)
			result.SimilarityA = 0
			result.SimilarityB = 0
			result.ChangedA = true
			result.ChangedB = true
			result.HasWAF = true
			result.BlockedResponse = blockedConnectionSnapshot(baselineURL, fmt.Errorf("探测请求被远端直接断开"))
			result.ClusterHint = "连接断开型拦截 | 探测请求被远端直接中断"
			result.ClusterKey = ConnectionBlockedClusterKey
			break
		}

		if probeAErr != nil {
			errors = append(errors, fmt.Sprintf("%s 探测一失败: %v", probeAURL, probeAErr))
		}
		if probeBErr != nil {
			errors = append(errors, fmt.Sprintf("%s 探测二失败: %v", probeBURL, probeBErr))
		}
		if probeAErr != nil || probeBErr != nil {
			continue
		}

		result.DetectedURL = baselineURL
		result.Baseline = baseline
		result.ProbeA = probeA
		result.ProbeB = probeB
		break
	}

	if result.DetectedURL == "" {
		result.Error = "请求异常"
		if len(errors) > 0 {
			result.Error += ": " + strings.Join(errors, " | ")
		}
		return result
	}

	result.SimilarityA = similarity(result.Baseline, result.ProbeA)
	result.SimilarityB = similarity(result.Baseline, result.ProbeB)
	result.ChangedA = changed(result.Baseline, result.ProbeA, result.SimilarityA)
	result.ChangedB = changed(result.Baseline, result.ProbeB, result.SimilarityB)
	result.HasWAF = result.ChangedA && result.ChangedB
	if result.HasWAF && shouldVerifyDynamicBaseline(result) {
		replay, replayErr := s.fetch(ctx, result.DetectedURL)
		if isCanceledRequest(ctx, replayErr) {
			result.Error = "已停止"
			return result
		}
		if replayErr == nil {
			replaySim := similarity(result.Baseline, replay)
			if changed(result.Baseline, replay, replaySim) {
				result.HasWAF = false
				result.BlockedResponse = model.ResponseSnapshot{}
				result.ClusterKey = ""
				result.ClusterHint = fmt.Sprintf("原始页二次复探相似度 %.2f | 页面动态变化，忽略 WAF 判定", replaySim)
			}
		}
	}
	if result.HasWAF {
		if result.BlockedResponse.Raw == "" {
			result.BlockedResponse = s.pickBlockedResponse(result)
		}
		if result.ClusterHint == "" {
			result.ClusterHint = clusterHint(result.BlockedResponse)
		}
		if result.ClusterKey == "" {
			result.ClusterKey = clusterKey(result.BlockedResponse)
		}
	}
	return result
}

func shouldVerifyDynamicBaseline(result model.DetectionResult) bool {
	if !(result.ChangedA && result.ChangedB) {
		return false
	}
	diff := result.SimilarityA - result.SimilarityB
	if diff < 0 {
		diff = -diff
	}
	return diff <= 0.05
}

func (s *Service) candidateURLs(site model.Site) ([]*url.URL, error) {
	schemes := preferredSchemes(site, s.settings.DefaultScheme)
	candidates := make([]*url.URL, 0, len(schemes)+2)
	seen := map[string]struct{}{}

	addCandidate := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}

		if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
			if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
				key := parsed.String()
				if _, ok := seen[key]; ok {
					return
				}
				seen[key] = struct{}{}
				candidates = append(candidates, parsed)
			}
			return
		}

		normalized := raw
		if !strings.HasPrefix(normalized, "//") {
			normalized = "//" + normalized
		}
		parsed, err := url.Parse(normalized)
		if err != nil || parsed.Host == "" {
			return
		}
		for _, scheme := range schemes {
			clone := *parsed
			clone.Scheme = scheme
			key := clone.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			candidates = append(candidates, &clone)
		}
	}

	addCandidate(site.OriginalURL)
	addCandidate(site.URL)

	host := strings.TrimSpace(site.Host)
	if host == "" {
		host = strings.TrimSpace(site.Domain)
	}
	if host == "" {
		return nil, fmt.Errorf("site has no host")
	}

	basePath := "/"
	baseQuery := ""
	if parsed, err := s.parseReference(site.OriginalURL, schemes); err == nil && parsed != nil {
		basePath = nonEmptyPath(parsed.Path)
		baseQuery = parsed.RawQuery
	} else if parsed, err := s.parseReference(site.URL, schemes); err == nil && parsed != nil {
		basePath = nonEmptyPath(parsed.Path)
		baseQuery = parsed.RawQuery
	}

	for _, scheme := range schemes {
		candidate := &url.URL{
			Scheme:   scheme,
			Host:     host,
			Path:     basePath,
			RawQuery: baseQuery,
		}
		key := candidate.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("site has no reachable url candidate")
	}
	return candidates, nil
}

func (s *Service) baselineURL(base *url.URL) string {
	return s.requestURL(base, "1")
}

func (s *Service) probeURL(base *url.URL, marker string) string {
	return s.requestURL(base, fmt.Sprintf("1'+and+'%s'='%s", marker, marker))
}

func (s *Service) requestURL(base *url.URL, rawID string) string {
	probe := *base
	values := probe.Query()
	values.Set("id", rawID)
	probe.RawQuery = values.Encode()
	probe.Path = "/"
	return probe.String()
}

func (s *Service) parseReference(raw string, schemes []string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		if parsed.Host == "" {
			return nil, nil
		}
		return parsed, nil
	}

	normalized := raw
	if !strings.HasPrefix(normalized, "//") {
		normalized = "//" + normalized
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Host == "" {
		return nil, err
	}
	if len(schemes) > 0 {
		parsed.Scheme = schemes[0]
	}
	return parsed, nil
}

func (s *Service) fetch(ctx context.Context, target string) (model.ResponseSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return model.ResponseSnapshot{}, err
	}
	userAgent := strings.TrimSpace(s.vars["USER_AGENT"])
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return model.ResponseSnapshot{}, err
	}
	defer closeResponseBody(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.settings.MaxBodyPreview)))
	if err != nil {
		return model.ResponseSnapshot{}, err
	}
	headers := flattenHeaders(resp.Header)
	bodyText := decodeResponseBody(body, resp.Header.Get("Content-Type"))

	snapshot := model.ResponseSnapshot{
		URL:        target,
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       bodyText,
		Title:      extractTitle(bodyText),
	}
	snapshot.Raw = fmt.Sprintf("HTTP/1.1 %d %s\n%s\n\n%s", resp.StatusCode, http.StatusText(resp.StatusCode), headers, bodyText)
	return snapshot, nil
}

func closeResponseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64*1024))
	_ = body.Close()
}

func decodeResponseBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return ""
	}

	reader, err := htmlcharset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		return string(body)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(body)
	}
	return string(decoded)
}

func (s *Service) pickBlockedResponse(result model.DetectionResult) model.ResponseSnapshot {
	if result.SimilarityA <= result.SimilarityB {
		return result.ProbeA
	}
	return result.ProbeB
}

func isCanceledRequest(ctx context.Context, err error) bool {
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled)
}

func similarity(base, probe model.ResponseSnapshot) float64 {
	baseLength := responseLength(base)
	probeLength := responseLength(probe)
	if baseLength > 0 && baseLength == probeLength {
		return 1
	}

	baseTokens := tokenize(base.Title + "\n" + base.Body + "\n" + base.Headers)
	probeTokens := tokenize(probe.Title + "\n" + probe.Body + "\n" + probe.Headers)
	if len(baseTokens) == 0 && len(probeTokens) == 0 {
		return 1
	}
	if len(baseTokens) == 0 || len(probeTokens) == 0 {
		return 0
	}

	baseSet := make(map[string]struct{}, len(baseTokens))
	for _, token := range baseTokens {
		baseSet[token] = struct{}{}
	}
	probeSet := make(map[string]struct{}, len(probeTokens))
	for _, token := range probeTokens {
		probeSet[token] = struct{}{}
	}

	intersect := 0
	union := make(map[string]struct{}, len(baseSet)+len(probeSet))
	for token := range baseSet {
		union[token] = struct{}{}
		if _, ok := probeSet[token]; ok {
			intersect++
		}
	}
	for token := range probeSet {
		union[token] = struct{}{}
	}
	if len(union) == 0 {
		return 0
	}

	tokenScore := float64(intersect) / float64(len(union))
	lengthScore := lengthSimilarity(baseLength, probeLength)
	if lengthScore == 0 {
		return tokenScore
	}
	return (tokenScore * 0.7) + (lengthScore * 0.3)
}

func ResponseSimilarity(base, probe model.ResponseSnapshot) float64 {
	return similarity(base, probe)
}

func FingerprintSignature(snapshot model.ResponseSnapshot) string {
	sum := sha1.Sum([]byte(fingerprintMaterial(snapshot)))
	return "fp-" + hex.EncodeToString(sum[:])
}

func FingerprintHint(snapshot model.ResponseSnapshot) string {
	return clusterHint(snapshot)
}

func FingerprintVerifiedMatch(stored, current model.ResponseSnapshot) bool {
	if FingerprintSignature(stored) != FingerprintSignature(current) {
		return false
	}
	return fingerprintEvidence(stored, current, 0.93, 0.92)
}

func FingerprintCloseMatch(stored, current model.ResponseSnapshot) bool {
	if stored.StatusCode != current.StatusCode {
		return false
	}
	return fingerprintEvidence(stored, current, 0.95, 0.9)
}

func changed(base, probe model.ResponseSnapshot, sim float64) bool {
	if sameResponseLength(base, probe) {
		return false
	}
	if probe.StatusCode == 0 {
		return true
	}
	if base.StatusCode != probe.StatusCode {
		return true
	}
	if sim < 0.82 {
		return true
	}
	baseTitle := normalizeText(base.Title)
	probeTitle := normalizeText(probe.Title)
	if baseTitle != "" && probeTitle != "" && baseTitle != probeTitle && sim < 0.92 {
		return true
	}
	return false
}

func clusterHint(snapshot model.ResponseSnapshot) string {
	title := emptyFallback(snapshot.Title, "无标题")
	server := headerValue(snapshot.Headers, "Server")
	keywords := topKeywords(snapshot.Body, 6)
	return fmt.Sprintf("状态=%d | 标题=%s | 服务端=%s | 关键词=%s", snapshot.StatusCode, title, emptyFallback(server, "未知"), strings.Join(keywords, ", "))
}

func isConnectionBlocked(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	keywords := []string{
		"connection reset",
		"broken pipe",
		"eof",
		"use of closed network connection",
		"connection closed",
		"server closed",
		"tls: handshake failure",
		"stream error",
	}
	for _, keyword := range keywords {
		if strings.Contains(message, keyword) {
			return true
		}
	}
	return false
}

func blockedConnectionSnapshot(target string, err error) model.ResponseSnapshot {
	message := "连接被远端直接断开"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		message = err.Error()
	}
	body := "连接断开型拦截\n" + message
	return model.ResponseSnapshot{
		URL:        target,
		StatusCode: 0,
		Headers:    "X-WAFKiller-Disconnect: true",
		Body:       body,
		Title:      "连接断开型拦截",
		Raw:        "HTTP/1.1 000 Connection Closed\nX-WAFKiller-Disconnect: true\n\n" + body,
	}
}

func responseLength(snapshot model.ResponseSnapshot) int {
	raw := strings.TrimSpace(snapshot.Raw)
	if raw != "" {
		return len(raw)
	}
	return len(snapshot.Headers) + len(snapshot.Body) + len(snapshot.Title)
}

func sameResponseLength(base, probe model.ResponseSnapshot) bool {
	baseLength := responseLength(base)
	probeLength := responseLength(probe)
	return baseLength > 0 && baseLength == probeLength
}

func lengthSimilarity(baseLength, probeLength int) float64 {
	if baseLength <= 0 || probeLength <= 0 {
		return 0
	}
	if baseLength == probeLength {
		return 1
	}

	maxLength := baseLength
	minLength := probeLength
	if probeLength > maxLength {
		maxLength = probeLength
		minLength = baseLength
	}
	return float64(minLength) / float64(maxLength)
}

func clusterKey(snapshot model.ResponseSnapshot) string {
	fingerprint := strings.Join([]string{
		fmt.Sprintf("%d", snapshot.StatusCode),
		normalizeText(snapshot.Title),
		normalizeText(headerValue(snapshot.Headers, "Server")),
		strings.Join(topKeywords(snapshot.Body, 8), "|"),
	}, "|")
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(fingerprint))
	return fmt.Sprintf("cluster-%x", hasher.Sum64())
}

func fingerprintMaterial(snapshot model.ResponseSnapshot) string {
	body := normalizeText(snapshot.Body)
	if len(body) > 512 {
		body = body[:512]
	}
	headers := []string{
		normalizeText(headerValue(snapshot.Headers, "Server")),
		normalizeText(headerValue(snapshot.Headers, "Content-Type")),
		normalizeText(headerValue(snapshot.Headers, "X-Powered-By")),
		normalizeText(headerValue(snapshot.Headers, "X-CDN")),
	}
	return strings.Join([]string{
		fmt.Sprintf("status=%d", snapshot.StatusCode),
		"title=" + normalizeText(snapshot.Title),
		"len=" + fmt.Sprintf("%d", responseLength(snapshot)),
		"headers=" + strings.Join(headers, "|"),
		"keywords=" + strings.Join(topKeywords(snapshot.Body, 12), "|"),
		"body=" + body,
	}, "\n")
}

func fingerprintEvidence(stored, current model.ResponseSnapshot, similarityFloor, lengthFloor float64) bool {
	if stored.StatusCode != current.StatusCode {
		return false
	}

	storedTitle := normalizeText(stored.Title)
	currentTitle := normalizeText(current.Title)
	if storedTitle != "" && currentTitle != "" && storedTitle != currentTitle {
		return false
	}

	storedServer := normalizeText(headerValue(stored.Headers, "Server"))
	currentServer := normalizeText(headerValue(current.Headers, "Server"))
	if storedServer != "" && currentServer != "" && storedServer != currentServer {
		return false
	}

	lengthScore := lengthSimilarity(responseLength(stored), responseLength(current))
	if lengthScore < lengthFloor {
		return false
	}

	if ResponseSimilarity(stored, current) < similarityFloor {
		return false
	}

	return keywordOverlap(topKeywords(stored.Body, 10), topKeywords(current.Body, 10)) >= 3
}

func keywordOverlap(left, right []string) int {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	set := make(map[string]struct{}, len(left))
	for _, item := range left {
		set[item] = struct{}{}
	}
	count := 0
	for _, item := range right {
		if _, ok := set[item]; ok {
			count++
		}
	}
	return count
}

func topKeywords(body string, limit int) []string {
	tokens := tokenize(body)
	counts := map[string]int{}
	for _, token := range tokens {
		if len([]rune(token)) < 3 {
			continue
		}
		counts[token]++
	}
	type pair struct {
		Key   string
		Count int
	}
	items := make([]pair, 0, len(counts))
	for key, count := range counts {
		items = append(items, pair{Key: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	out := make([]string, 0, limit)
	for _, item := range items {
		out = append(out, item.Key)
		if len(out) == limit {
			break
		}
	}
	if len(out) == 0 {
		return []string{"empty"}
	}
	return out
}

func preferredSchemes(site model.Site, fallback string) []string {
	schemes := make([]string, 0, 4)
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		switch value {
		case "http", "https":
		default:
			return
		}
		for _, existing := range schemes {
			if existing == value {
				return
			}
		}
		schemes = append(schemes, value)
	}

	protocol := strings.ToLower(strings.TrimSpace(site.Protocol))
	switch {
	case strings.Contains(protocol, "https"):
		add("https")
	case strings.Contains(protocol, "http"):
		add("http")
	}

	switch strings.TrimSpace(site.Port) {
	case "443":
		add("https")
	case "80":
		add("http")
	}

	add(fallback)
	add("https")
	add("http")
	return schemes
}

func nonEmptyPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "/"
	}
	return path
}

func tokenize(raw string) []string {
	matches := tokenPattern.FindAllString(strings.ToLower(normalizeText(raw)), -1)
	out := make([]string, 0, len(matches))
	for _, token := range matches {
		switch token {
		case "", "http", "https", "html", "body", "head", "div", "span", "class":
			continue
		default:
			out = append(out, token)
		}
	}
	return out
}

func normalizeText(raw string) string {
	replacer := strings.NewReplacer(
		"\r", " ",
		"\n", " ",
		"\t", " ",
		"&nbsp;", " ",
		"'", " ",
		"\"", " ",
	)
	text := replacer.Replace(raw)
	text = strings.ToLower(text)
	text = titlePattern.ReplaceAllString(text, "$1")
	return strings.Join(strings.Fields(text), " ")
}

func extractTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func flattenHeaders(headers http.Header) string {
	lines := make([]string, 0, len(headers))
	for key, values := range headers {
		lines = append(lines, key+": "+strings.Join(values, ", "))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func headerValue(headers string, key string) string {
	prefix := strings.ToLower(key) + ":"
	for _, line := range strings.Split(headers, "\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			return ""
		}
	}
	return ""
}

func emptyFallback(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
