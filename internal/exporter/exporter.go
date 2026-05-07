package exporter

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"wafbps/internal/model"
)

type Summary struct {
	TotalResults    int            `json:"total_results"`
	PossibleBypass  int            `json:"possible_bypass"`
	Blocked         int            `json:"blocked"`
	ReviewNeeded    int            `json:"review_needed"`
	RequestErrors   int            `json:"request_errors"`
	NoResponse      int            `json:"no_response"`
	TopWAF          string         `json:"top_waf"`
	VerdictBreakout map[string]int `json:"verdict_breakout"`
	WAFBreakout     map[string]int `json:"waf_breakout"`
}

type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Summary     Summary            `json:"summary"`
	Results     []model.TestResult `json:"results"`
}

func ExportJSON(path string, results []model.TestResult) error {
	report := Report{
		GeneratedAt: time.Now(),
		Summary:     BuildSummary(results),
		Results:     results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ExportHTML(path string, results []model.TestResult) error {
	report := Report{
		GeneratedAt: time.Now(),
		Summary:     BuildSummary(results),
		Results:     results,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(renderHTML(report)), 0o644)
}

func BuildSummary(results []model.TestResult) Summary {
	summary := Summary{
		TotalResults:    len(results),
		VerdictBreakout: map[string]int{},
		WAFBreakout:     map[string]int{},
	}

	for _, result := range results {
		verdict := strings.TrimSpace(result.Verdict)
		if verdict == "" {
			verdict = "未知"
		}
		waf := strings.TrimSpace(result.Site.WAF)
		if waf == "" {
			waf = "未知"
		}

		summary.VerdictBreakout[verdict]++
		summary.WAFBreakout[waf]++

		switch {
		case strings.Contains(verdict, "可能绕过"):
			summary.PossibleBypass++
		case strings.Contains(verdict, "已拦截"):
			summary.Blocked++
		case strings.Contains(verdict, "复核"):
			summary.ReviewNeeded++
		case strings.Contains(verdict, "无响应"):
			summary.NoResponse++
		case strings.Contains(verdict, "异常") || strings.Contains(verdict, "失败"):
			summary.RequestErrors++
		}
	}

	summary.TopWAF = topKey(summary.WAFBreakout)
	return summary
}

func renderHTML(report Report) string {
	rows := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		rows = append(rows, fmt.Sprintf(`
		<tr>
			<td>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td><span class="badge %s">%s</span></td>
			<td>%d</td>
			<td>%s</td>
			<td>%s</td>
		</tr>`,
			escape(result.RunAt.Format("2006-01-02 15:04:05")),
			escape(result.Site.Host),
			escape(result.Plugin.Name),
			badgeClass(result.Verdict),
			escape(result.Verdict),
			result.StatusCode,
			escape(result.MatchedRule),
			escape(result.Duration.Round(time.Millisecond).String()),
		))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF 绕过车库报告</title>
<style>
body{margin:0;padding:32px;background:#07090e;color:#e0ecff;font-family:Menlo,Monaco,monospace}
.shell{max-width:1440px;margin:0 auto}
.hero{padding:24px 28px;border-left:6px solid #00f2ff;background:linear-gradient(135deg,rgba(0,242,255,.14),rgba(255,71,136,.08))}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:20px 0}
.card{padding:16px 18px;background:#111827;border-top:4px solid #00f2ff}
.label{font-size:12px;color:#8c9bba;text-transform:uppercase;letter-spacing:.08em}
.value{font-size:28px;font-weight:700;margin-top:8px}
table{width:100%%;border-collapse:collapse;background:#0d1320}
th,td{padding:12px;border-bottom:1px solid rgba(140,155,186,.15);text-align:left;vertical-align:top}
th{color:#8c9bba;font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge-bypass{background:rgba(73,255,150,.14);color:#49ff96}
.badge-blocked{background:rgba(255,71,136,.15);color:#ff4788}
.badge-review{background:rgba(255,168,56,.15);color:#ffa838}
.badge-error{background:rgba(74,143,255,.18);color:#4a8fff}
</style>
</head>
<body>
<div class="shell">
	<div class="hero">
		<div class="label">WAF 绕过车库报告</div>
		<h1>测试结果导出</h1>
		<p>生成时间：%s</p>
	</div>
	<div class="cards">
		<div class="card"><div class="label">结果总数</div><div class="value">%d</div></div>
		<div class="card" style="border-top-color:#49ff96"><div class="label">可能绕过</div><div class="value">%d</div></div>
		<div class="card" style="border-top-color:#ff4788"><div class="label">已拦截</div><div class="value">%d</div></div>
		<div class="card" style="border-top-color:#ffa838"><div class="label">需要复核</div><div class="value">%d</div></div>
		<div class="card" style="border-top-color:#4a8fff"><div class="label">热点 WAF</div><div class="value">%s</div></div>
	</div>
	<table>
		<thead>
			<tr>
				<th>测试时间</th>
				<th>目标站点</th>
				<th>插件</th>
				<th>判定</th>
				<th>状态码</th>
				<th>命中规则</th>
				<th>耗时</th>
			</tr>
		</thead>
		<tbody>%s
		</tbody>
	</table>
</div>
</body>
</html>`,
		escape(report.GeneratedAt.Format("2006-01-02 15:04:05")),
		report.Summary.TotalResults,
		report.Summary.PossibleBypass,
		report.Summary.Blocked,
		report.Summary.ReviewNeeded,
		escape(report.Summary.TopWAF),
		strings.Join(rows, ""))
}

func badgeClass(verdict string) string {
	switch {
	case strings.Contains(verdict, "可能绕过"):
		return "badge-bypass"
	case strings.Contains(verdict, "已拦截"):
		return "badge-blocked"
	case strings.Contains(verdict, "复核"):
		return "badge-review"
	default:
		return "badge-error"
	}
}

func topKey(counts map[string]int) string {
	type kv struct {
		Key   string
		Count int
	}
	items := make([]kv, 0, len(counts))
	for key, count := range counts {
		items = append(items, kv{Key: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	if len(items) == 0 {
		return "暂无"
	}
	return items[0].Key
}

func escape(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return html.EscapeString(value)
}
