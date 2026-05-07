package ui

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"wafbps/internal/detector"
	"wafbps/internal/model"
	"wafbps/internal/store"
)

type wafYAMLFileRule struct {
	Name string            `yaml:"name"`
	Rule []wafYAMLRuleNode `yaml:"rule"`
}

type wafYAMLRuleNode struct {
	Logic      string                 `yaml:"logic"`
	Regexps    wafYAMLRegexpNode      `yaml:"regexps"`
	Conditions []wafYAMLConditionNode `yaml:"conditions"`
}

type wafYAMLRegexpNode struct {
	Header []string `yaml:"header"`
	Body   []string `yaml:"body"`
	Regexp []string `yaml:"regexp"`
}

type wafYAMLConditionNode struct {
	Type    string `yaml:"type"`
	Key     string `yaml:"key,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	Status  int    `yaml:"status,omitempty"`
}

type wafYAMLMatcher struct {
	Name  string
	Rules []wafYAMLCompiledRule
}

type wafYAMLCompiledRule struct {
	Logic      string
	Header     []*regexp.Regexp
	Body       []*regexp.Regexp
	Regexp     []*regexp.Regexp
	Conditions []wafYAMLCompiledCondition
}

type wafYAMLCompiledCondition struct {
	Type    string
	Key     string
	Raw     string
	Pattern *regexp.Regexp
	Status  int
}

func loadWAFYAMLMatchers(path string) []wafYAMLMatcher {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw []wafYAMLFileRule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}

	matchers := make([]wafYAMLMatcher, 0, len(raw))
	for _, item := range raw {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		matcher := wafYAMLMatcher{Name: name}
		for _, rule := range item.Rule {
			compiled := wafYAMLCompiledRule{
				Logic:      strings.ToLower(strings.TrimSpace(rule.Logic)),
				Header:     compileWAFYAMLRegexps(rule.Regexps.Header),
				Body:       compileWAFYAMLRegexps(rule.Regexps.Body),
				Regexp:     compileWAFYAMLRegexps(rule.Regexps.Regexp),
				Conditions: compileWAFYAMLConditions(rule.Conditions),
			}
			if compiled.Logic == "" {
				compiled.Logic = "all"
			}
			if len(compiled.Header) == 0 && len(compiled.Body) == 0 && len(compiled.Regexp) == 0 && len(compiled.Conditions) == 0 {
				continue
			}
			matcher.Rules = append(matcher.Rules, compiled)
		}
		if len(matcher.Rules) > 0 {
			matchers = append(matchers, matcher)
		}
	}
	return matchers
}

func compileWAFYAMLRegexps(values []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(values))
	for _, value := range values {
		pattern := strings.TrimSpace(value)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func compileWAFYAMLConditions(values []wafYAMLConditionNode) []wafYAMLCompiledCondition {
	compiled := make([]wafYAMLCompiledCondition, 0, len(values))
	for _, value := range values {
		kind := strings.ToLower(strings.TrimSpace(value.Type))
		if kind == "" {
			continue
		}
		item := wafYAMLCompiledCondition{
			Type:   kind,
			Key:    strings.ToLower(strings.TrimSpace(value.Key)),
			Status: value.Status,
			Raw:    strings.TrimSpace(value.Pattern),
		}
		if strings.TrimSpace(value.Pattern) != "" {
			re, err := regexp.Compile("(?i)" + strings.TrimSpace(value.Pattern))
			if err != nil {
				continue
			}
			item.Pattern = re
		}
		if item.Pattern == nil && item.Status == 0 {
			continue
		}
		compiled = append(compiled, item)
	}
	return compiled
}

func matchAnyWAFYAMLRegexp(exprs []*regexp.Regexp, target string) bool {
	if len(exprs) == 0 {
		return true
	}
	for _, expr := range exprs {
		if expr != nil && expr.MatchString(target) {
			return true
		}
	}
	return false
}

func headerValueMatch(headers string, key string, expr *regexp.Regexp) bool {
	if expr == nil {
		return false
	}
	key = strings.ToLower(strings.TrimSpace(key))
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		if key != "" && name != key {
			continue
		}
		if expr.MatchString(strings.TrimSpace(parts[1])) {
			return true
		}
	}
	return false
}

func cookieValueMatch(headers string, expr *regexp.Regexp) bool {
	if expr == nil {
		return false
	}
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "set-cookie:") && !strings.HasPrefix(lower, "cookie:") {
			continue
		}
		if expr.MatchString(line) {
			return true
		}
	}
	return false
}

func reasonValue(snapshot model.ResponseSnapshot) string {
	raw := strings.TrimSpace(snapshot.Raw)
	if raw == "" {
		return ""
	}
	first := strings.SplitN(raw, "\n", 2)[0]
	first = strings.TrimSpace(first)
	if first == "" {
		return ""
	}
	parts := strings.SplitN(first, " ", 3)
	if len(parts) < 3 {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func matchWAFYAMLCondition(condition wafYAMLCompiledCondition, snapshot model.ResponseSnapshot, generic string) bool {
	switch condition.Type {
	case "header":
		return headerValueMatch(snapshot.Headers, condition.Key, condition.Pattern)
	case "cookie":
		return cookieValueMatch(snapshot.Headers, condition.Pattern)
	case "content", "body":
		return condition.Pattern != nil && condition.Pattern.MatchString(snapshot.Body)
	case "regexp":
		return condition.Pattern != nil && condition.Pattern.MatchString(generic)
	case "reason":
		return condition.Pattern != nil && condition.Pattern.MatchString(reasonValue(snapshot))
	case "status":
		return snapshot.StatusCode == condition.Status
	default:
		return false
	}
}

func wafDisplayAlias(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if alias, ok := map[string]string{
		"AliYunDun":               "阿里云盾",
		"Anquanbao":               "安全宝",
		"Qcloud":                  "腾讯云WAF",
		"Yundun":                  "云盾",
		"Yunsuo":                  "云锁",
		"Safedog":                 "安全狗",
		"Chuang Yu Shield":        "知道创宇",
		"Tencent Cloud Firewall":  "腾讯云防火墙",
		"Huawei Cloud Firewall":   "华为云防火墙",
		"Cloudflare":              "Cloudflare",
		"Open-Resty Lua Nginx":    "OpenResty",
		"BIG-IP AppSec Manager":   "F5 BIG-IP ASM",
		"BIG-IP AP Manager":       "F5 BIG-IP APM",
		"BIG-IP Local Traffic Manager": "F5 BIG-IP LTM",
	}[name]; ok {
		return alias
	}
	if idx := strings.Index(name, " ("); idx > 0 {
		name = strings.TrimSpace(name[:idx])
	}
	return name
}

func describeWAFYAMLCondition(condition wafYAMLCompiledCondition) string {
	switch condition.Type {
	case "header":
		return "Header " + emptyFallback(condition.Key, "*") + " ~= " + emptyFallback(condition.Raw, "-")
	case "cookie":
		return "Cookie ~= " + emptyFallback(condition.Raw, "-")
	case "content", "body":
		return "Body ~= " + emptyFallback(condition.Raw, "-")
	case "regexp":
		return "Regexp ~= " + emptyFallback(condition.Raw, "-")
	case "reason":
		return "Reason ~= " + emptyFallback(condition.Raw, "-")
	case "status":
		return "Status = " + strconv.Itoa(condition.Status)
	default:
		return condition.Type
	}
}

func matchLegacyWAFYAMLRule(rule wafYAMLCompiledRule, headers string, body string, generic string) (bool, []string) {
	details := make([]string, 0, 3)
	for _, expr := range rule.Header {
		if expr != nil && expr.MatchString(headers) {
			details = append(details, "Header ~= "+expr.String())
		}
	}
	for _, expr := range rule.Body {
		if expr != nil && expr.MatchString(body) {
			details = append(details, "Body ~= "+expr.String())
		}
	}
	for _, expr := range rule.Regexp {
		if expr != nil && expr.MatchString(generic) {
			details = append(details, "Regexp ~= "+expr.String())
		}
	}
	if !matchAnyWAFYAMLRegexp(rule.Header, headers) {
		return false, nil
	}
	if !matchAnyWAFYAMLRegexp(rule.Body, body) {
		return false, nil
	}
	if !matchAnyWAFYAMLRegexp(rule.Regexp, generic) {
		return false, nil
	}
	return true, details
}

func matchCompiledWAFYAMLRule(rule wafYAMLCompiledRule, snapshot model.ResponseSnapshot, generic string) (bool, []string) {
	if len(rule.Conditions) == 0 {
		return false, nil
	}
	details := make([]string, 0, len(rule.Conditions))
	if rule.Logic == "any" {
		for _, condition := range rule.Conditions {
			if matchWAFYAMLCondition(condition, snapshot, generic) {
				details = append(details, describeWAFYAMLCondition(condition))
			}
		}
		return len(details) > 0, details
	}
	for _, condition := range rule.Conditions {
		if !matchWAFYAMLCondition(condition, snapshot, generic) {
			return false, nil
		}
		details = append(details, describeWAFYAMLCondition(condition))
	}
	return true, details
}

func (d *dashboard) matchWAFYAML(snapshot model.ResponseSnapshot) (string, string, bool) {
	if len(d.yamlMatchers) == 0 {
		return "", "", false
	}

	headers := snapshot.Headers
	body := snapshot.Body
	raw := snapshot.Raw
	if strings.TrimSpace(raw) == "" {
		raw = headers + "\n\n" + body
	}
	generic := raw + "\n" + snapshot.Title

	for _, matcher := range d.yamlMatchers {
		for _, rule := range matcher.Rules {
			if len(rule.Conditions) > 0 {
				matched, details := matchCompiledWAFYAMLRule(rule, snapshot, generic)
				if matched {
					return wafDisplayAlias(matcher.Name), strings.Join(details, " | "), true
				}
				continue
			}
			matched, details := matchLegacyWAFYAMLRule(rule, headers, body, generic)
			if matched {
				return wafDisplayAlias(matcher.Name), strings.Join(details, " | "), true
			}
		}
	}

	return "", "", false
}

func (d *dashboard) applyWAFYAMLMatches() int {
	if len(d.yamlMatchers) == 0 {
		return 0
	}
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}
	if d.dbState.Current.ClusterLabels == nil {
		d.dbState.Current.ClusterLabels = map[string]string{}
	}
	if d.clusterLabelSources == nil {
		d.clusterLabelSources = map[string]string{}
	}
	if d.dbState.Current.ClusterLabelSources == nil {
		d.dbState.Current.ClusterLabelSources = map[string]string{}
	}

	applied := 0
	for clusterKey, memberKeys := range d.clusterMembers {
		clusterKey = strings.TrimSpace(clusterKey)
		if clusterKey == "" || len(memberKeys) == 0 {
			continue
		}
		if d.ignoredClusters[clusterKey] {
			continue
		}

		existing := strings.TrimSpace(d.clusterLabels[clusterKey])
		if existing == "" {
			for _, memberKey := range memberKeys {
				detection, ok := d.detections[memberKey]
				if !ok {
					continue
				}
				existing = strings.TrimSpace(detection.ClusterLabel)
				if existing != "" {
					break
				}
			}
		}
		if existing != "" {
			continue
		}

		label, detail, ok := d.matchWAFYAML(d.clusterBlockedSnapshot(clusterKey))
		if !ok || strings.TrimSpace(label) == "" {
			continue
		}

		d.clusterLabels[clusterKey] = label
		d.clusterLabelSources[clusterKey] = "yaml"
		if strings.TrimSpace(detail) != "" {
			if d.clusterRuleDetails == nil {
				d.clusterRuleDetails = map[string]string{}
			}
			d.clusterRuleDetails[clusterKey] = detail
		}
		d.dbState.Current.ClusterLabels[clusterKey] = label
		d.dbState.Current.ClusterLabelSources[clusterKey] = "yaml"
		if strings.TrimSpace(detail) != "" {
			if d.dbState.Current.ClusterRuleDetails == nil {
				d.dbState.Current.ClusterRuleDetails = map[string]string{}
			}
			d.dbState.Current.ClusterRuleDetails[clusterKey] = detail
		}
		for _, memberKey := range memberKeys {
			detection, exists := d.detections[memberKey]
			if !exists {
				continue
			}
			detection.ClusterLabel = label
			d.detections[memberKey] = detection
			if current, ok := d.dbState.Current.Detections[memberKey]; ok {
				current.ClusterLabel = label
				d.dbState.Current.Detections[memberKey] = current
			}
		}
		updated := false
		for index := range d.clusterBaseline {
			if d.clusterBaseline[index].Key != clusterKey {
				continue
			}
			d.clusterBaseline[index].Label = label
			updated = true
		}
		if !updated {
			d.clusterBaseline = append(d.clusterBaseline, store.ClusterBaselineItem{
				Key:       clusterKey,
				Label:     label,
				Signature: strings.TrimSpace(detector.FingerprintSignature(d.clusterBlockedSnapshot(clusterKey))),
			})
		}
		if signature, remembered := d.rememberClusterFingerprint(clusterKey, label, detail); remembered {
			if d.dbState.Fingerprints == nil {
				d.dbState.Fingerprints = map[string]store.ClusterFingerprint{}
			}
			d.fingerprintMu.RLock()
			d.dbState.Fingerprints[signature] = d.fingerprints[signature]
			d.fingerprintMu.RUnlock()
		}
		applied++
	}

	if applied > 0 {
		d.dbState.Current.ClusterBaseline = append([]store.ClusterBaselineItem(nil), d.clusterBaseline...)
	}
	return applied
}
