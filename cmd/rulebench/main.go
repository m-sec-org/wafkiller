package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wafbps/internal/config"
	"wafbps/internal/model"
	"wafbps/internal/plugin"
	"wafbps/internal/store"
	"wafbps/internal/tester"
)

type target struct {
	site      model.Site
	detection model.DetectionResult
}

type output struct {
	result model.TestResult
}

func main() {
	configPath := flag.String("config", config.DefaultConfigPath, "config path")
	ruleName := flag.String("rule", "POST Multipart探测", "rule name")
	concurrency := flag.Int("concurrency", 100, "worker concurrency")
	timeoutSeconds := flag.Int("timeout", 1, "request timeout seconds")
	limit := flag.Int("limit", 0, "limit targets, 0 means all")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	must(err)
	cfg.Tester.Concurrency = *concurrency
	cfg.Tester.TimeoutSeconds = *timeoutSeconds

	db, err := store.New(cfg.App.DatabasePath).Load()
	must(err)

	plugins, err := plugin.Load(cfg.Plugin.Dir)
	must(err)
	rule, ok := findRule(plugins, *ruleName)
	if !ok {
		names := make([]string, 0, len(plugins))
		for _, p := range plugins {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "rule %q not found. available rules:\n%s\n", *ruleName, strings.Join(names, "\n"))
		os.Exit(2)
	}

	targets := suspectedTargets(db.Current.Detections, rule)
	if *limit > 0 && *limit < len(targets) {
		targets = targets[:*limit]
	}
	if len(targets) == 0 {
		fmt.Println("no suspected WAF targets matched this rule")
		return
	}

	service := tester.New(cfg.Tester, cfg.Variables, "")
	defer service.CloseIdleConnections()

	ctx := context.Background()
	jobs := make(chan target, len(targets))
	outputs := make(chan output, *concurrency)
	for _, item := range targets {
		jobs <- item
	}
	close(jobs)

	var active int64
	var wg sync.WaitGroup
	startedAt := time.Now()
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				atomic.AddInt64(&active, 1)
				detectionCopy := item.detection
				result := service.RunWithDetectionContext(ctx, item.site, rule, &detectionCopy)
				atomic.AddInt64(&active, -1)
				outputs <- output{result: result}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outputs)
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	completed := 0
	lastCompleted := 0
	possible := 0
	blocked := 0
	review := 0
	errors := 0
	timeouts := 0
	errorSamples := make([]string, 0, 5)
	lastTick := time.Now()
	printMetrics := func(label string) {
		now := time.Now()
		elapsed := now.Sub(startedAt)
		windowSeconds := now.Sub(lastTick).Seconds()
		if windowSeconds <= 0 {
			windowSeconds = 1
		}
		delta := completed - lastCompleted
		windowRate := float64(delta) / windowSeconds
		avgRate := float64(completed) / elapsed.Seconds()
		fmt.Printf("[%s %s] done=%d/%d window=%.1f/s avg=%.1f/s active=%d queued=%d possible=%d blocked=%d review=%d errors=%d timeouts=%d\n",
			label,
			elapsed.Truncate(time.Second),
			completed,
			len(targets),
			windowRate,
			avgRate,
			atomic.LoadInt64(&active),
			len(jobs),
			possible,
			blocked,
			review,
			errors,
			timeouts,
		)
		lastCompleted = completed
		lastTick = now
	}

	fmt.Printf("[bench init] rule=%q targets=%d concurrency=%d timeout=%ds\n", rule.Name, len(targets), *concurrency, *timeoutSeconds)
	for {
		select {
		case item, ok := <-outputs:
			if !ok {
				printMetrics("final")
				for _, sample := range errorSamples {
					fmt.Println("[bench error]", sample)
				}
				return
			}
			completed++
			verdict := strings.TrimSpace(item.result.Verdict)
			switch {
			case strings.Contains(verdict, "可能绕过"):
				possible++
			case strings.Contains(verdict, "已拦截"):
				blocked++
			default:
				review++
			}
			if strings.TrimSpace(item.result.Error) != "" {
				errors++
				if len(errorSamples) < 5 {
					errorSamples = append(errorSamples, fmt.Sprintf("%s => %s", siteKey(item.result.Site), item.result.Error))
				}
				if strings.Contains(strings.ToLower(item.result.Error), "timeout") || strings.Contains(strings.ToLower(item.result.Error), "deadline") {
					timeouts++
				}
			}
		case <-ticker.C:
			printMetrics("tick")
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func findRule(plugins []model.Plugin, name string) (model.Plugin, bool) {
	for _, p := range plugins {
		if strings.EqualFold(strings.TrimSpace(p.Name), strings.TrimSpace(name)) {
			return p, true
		}
	}
	return model.Plugin{}, false
}

func suspectedTargets(detections map[string]model.DetectionResult, rule model.Plugin) []target {
	keys := make([]string, 0, len(detections))
	for key := range detections {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	out := make([]target, 0)
	for _, key := range keys {
		detection := detections[key]
		if !detection.HasWAF {
			continue
		}
		site := detection.Site
		siteKey := siteKey(site)
		if siteKey == "" {
			siteKey = key
		}
		if seen[siteKey] {
			continue
		}
		seen[siteKey] = true
		out = append(out, target{site: site, detection: detection})
	}
	return out
}

func siteKey(site model.Site) string {
	if strings.TrimSpace(site.URL) != "" {
		return strings.TrimSpace(site.URL)
	}
	if strings.TrimSpace(site.Host) != "" {
		return strings.TrimSpace(site.Host)
	}
	return strings.TrimSpace(site.Domain)
}
