package plugin

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"wafbps/internal/model"
)

const builtinTemplateFilename = "template.http"

const builtinTemplateRule = `# @name: template
# @color: blue (cyan、blue、green、amber、orange、gold、pink、purple、violet、lavender、red、rose、teal、yellow、white、ice)
# @validate: baseline_similarity
# @threshold: 0.90
# @tags: Write Disposition Here,ex:chunked编码分割payload，每2字符一个chunk，绕过关键词匹配；payload: id=1' and 'a'='a
# @intent: none
POST / HTTP/1.1
Host: {{TARGET_HOST_HEADER}}
User-Agent: {{USER_AGENT}}
Content-Type: application/x-www-form-urlencoded

something
`

func Load(dir string) ([]model.Plugin, error) {
	if dir == "" {
		dir = "plugins"
	}
	if err := ensureBuiltinTemplateRule(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	plugins := make([]model.Plugin, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".http" && ext != ".req" && ext != ".txt" {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, err
		}

		p, err := Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fullPath, err)
		}
		if p.Name == "" {
			p.Name = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}
		p.Path = fullPath
		p.LintWarnings = RenderLintWarnings(Lint(string(data), p))
		plugins = append(plugins, p)
	}

	return plugins, nil
}

func ensureBuiltinTemplateRule(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, builtinTemplateFilename)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, []byte(builtinTemplateRule), 0o644)
}

func Parse(raw string) (model.Plugin, error) {
	var plugin model.Plugin
	plugin.Headers = map[string]string{}
	plugin.Raw = raw

	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	requestLineIdx := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# @") {
			parseMeta(&plugin, strings.TrimPrefix(trimmed, "# @"))
			continue
		}
		if isRequestLine(trimmed) {
			requestLineIdx = i
			break
		}
	}
	if requestLineIdx == -1 {
		return plugin, fmt.Errorf("no valid HTTP request line found")
	}

	parts := strings.Fields(lines[requestLineIdx])
	if len(parts) < 2 {
		return plugin, fmt.Errorf("invalid request line")
	}
	plugin.Method = parts[0]
	plugin.RequestURI = parts[1]

	reader := bufio.NewScanner(strings.NewReader(strings.Join(lines[requestLineIdx+1:], "\n")))
	inBody := false
	bodyLines := make([]string, 0)
	for reader.Scan() {
		line := reader.Text()
		if !inBody {
			if strings.TrimSpace(line) == "" {
				inBody = true
				continue
			}
			headerParts := strings.SplitN(line, ":", 2)
			if len(headerParts) != 2 {
				continue
			}
			key := strings.TrimSpace(headerParts[0])
			value := strings.TrimSpace(headerParts[1])
			if strings.EqualFold(key, "Host") {
				plugin.Host = value
				continue
			}
			plugin.Headers[key] = value
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	if err := reader.Err(); err != nil {
		return plugin, err
	}
	plugin.Body = strings.Join(bodyLines, "\n")

	return plugin, nil
}

func parseMeta(plugin *model.Plugin, meta string) {
	parts := strings.SplitN(meta, ":", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(strings.ToLower(parts[0]))
	value := strings.TrimSpace(parts[1])
	switch {
	case key == "name":
		plugin.Name = value
	case key == "waf":
		return
	case key == "tags":
		plugin.Tags = splitCSV(value)
	case key == "color":
		plugin.Color = strings.ToLower(value)
	case key == "intent":
		plugin.Intents = append(plugin.Intents, model.RuleIntent{
			Name: strings.ToLower(value),
			Args: map[string]string{},
		})
	case strings.HasPrefix(key, "intent."):
		intentArg := strings.TrimSpace(strings.TrimPrefix(key, "intent."))
		if intentArg == "" {
			return
		}
		intent := ensurePluginIntent(plugin)
		intent.Args[intentArg] = trimQuotedMetaValue(value)
	case key == "scheme":
		plugin.Scheme = strings.ToLower(value)
	case key == "preflight_mode" || key == "preflight-mode" || key == "preflight":
		plugin.PreflightMode = strings.ToLower(value)
	case key == "preflight_prune" || key == "preflight-prune":
		if flag, ok := parseBoolMetaValue(value); ok {
			plugin.PreflightPrune = &flag
		}
	case key == "validate" || key == "validation":
		plugin.ValidationMode = strings.ToLower(value)
	case key == "threshold" || key == "similarity":
		if score, err := strconv.ParseFloat(value, 64); err == nil && score > 0 {
			plugin.SimilarityThreshold = score
		}
	case key == "note" || key == "notes":
		plugin.Notes = value
	}
}

func ensurePluginIntent(plugin *model.Plugin) *model.RuleIntent {
	if len(plugin.Intents) == 0 {
		plugin.Intents = append(plugin.Intents, model.RuleIntent{
			Name: "custom",
			Args: map[string]string{},
		})
	}
	intent := &plugin.Intents[len(plugin.Intents)-1]
	if intent.Args == nil {
		intent.Args = map[string]string{}
	}
	return intent
}

func trimQuotedMetaValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func parseBoolMetaValue(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "y", "on":
		return true, true
	case "false", "0", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}

func isRequestLine(line string) bool {
	methods := []string{
		"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ",
	}
	upper := strings.ToUpper(line)
	for _, method := range methods {
		if strings.HasPrefix(upper, method) && strings.Contains(upper, "HTTP/") {
			return true
		}
	}
	return false
}

func splitCSV(raw string) []string {
	chunks := strings.Split(raw, ",")
	out := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		value := strings.TrimSpace(chunk)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
