package tester

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"wafbps/internal/model"
	"wafbps/internal/plugin"
)

func TestServiceTimeoutThroughputDoesNotCollapse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := plugin.Parse(`# @name: safedog-bypass
# @color: green
# @validate: baseline_similarity
# @threshold: 0.92
GET /wap?id=1%0fand%0f1=1 HTTP/1.1
Host: {{TARGET_HOST_HEADER}}
User-Agent: {{USER_AGENT}}`)
	if err != nil {
		t.Fatal(err)
	}

	settings := model.TesterSettings{
		TimeoutSeconds: 1,
		Concurrency:    100,
		DefaultScheme:  "http",
		MaxBodyPreview: 1024,
	}
	service := New(settings, map[string]string{
		"USER_AGENT": "Mozilla/5.0",
	}, "")
	defer service.CloseIdleConnections()

	site := model.Site{
		URL:  srv.URL,
		Host: parsed.Host,
	}
	const total = 300
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for i := 0; i < settings.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				result := service.Run(site, rule)
				if result.Verdict != "请求异常" {
					t.Errorf("expected timeout result, got %q", result.Verdict)
				}
			}
		}()
	}
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	rate := float64(total) / time.Since(started).Seconds()
	t.Logf("timeout-heavy throughput: %.1f/s", rate)
	if rate < 70 {
		t.Fatalf("timeout-heavy throughput collapsed: %.1f/s", rate)
	}
}
