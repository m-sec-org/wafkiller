package ui

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	htmlstd "html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"wafbps/internal/model"
)

var charsetMetaPattern = regexp.MustCompile(`(?is)<meta[^>]+charset[^>]*>`)
var cspMetaPattern = regexp.MustCompile(`(?is)<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>`)

func (d *dashboard) buildBrowserSnapshotPreview(snapshot model.ResponseSnapshot, cacheKey string, force bool) fyne.CanvasObject {
	if strings.TrimSpace(cacheKey) == "" {
		cacheKey = "cluster-empty"
	}
	if !force {
		if encoded := strings.TrimSpace(d.clusterSnapshotValue(cacheKey)); encoded != "" {
			if image := snapshotImageObject(encoded); image != nil {
				return image
			}
		}
		if _, pngPath, ok := snapshotCachePathsSafe(snapshot, cacheKey); ok && fileLooksValid(pngPath) {
			if image := snapshotImageObjectFromFile(pngPath); image != nil {
				return image
			}
		}
	}
	if strings.TrimSpace(snapshot.Body) == "" && strings.TrimSpace(snapshot.Raw) == "" {
		label := widget.NewLabel("选中聚类后，这里会显示浏览器真实快照。")
		label.Wrapping = fyne.TextWrapWord
		return container.NewCenter(neonPanel(accentBlue, container.NewPadded(label)))
	}

	holder := container.NewMax()
	holder.Objects = []fyne.CanvasObject{buildBrowserSnapshotLoading("正在生成浏览器真实快照...")}

	go func() {
		encoded, err := d.ensureClusterSnapshot(snapshot, cacheKey, force)
		if err != nil {
			message := widget.NewLabel("真实快照生成失败\n" + err.Error())
			message.Wrapping = fyne.TextWrapWord
			d.runOnUI(func() {
				holder.Objects = []fyne.CanvasObject{
					container.NewVBox(
						neonPanel(accentPink, container.NewPadded(message)),
						buildHTMLSnapshotPreview(snapshot),
					),
				}
				holder.Refresh()
			})
			return
		}

		image := snapshotImageObject(encoded)
		if image == nil {
			d.runOnUI(func() {
				holder.Objects = []fyne.CanvasObject{buildHTMLSnapshotPreview(snapshot)}
				holder.Refresh()
			})
			return
		}
		d.runOnUI(func() {
			holder.Objects = []fyne.CanvasObject{image}
			d.persistDatabase()
			holder.Refresh()
		})
	}()

	return holder
}

func buildBrowserSnapshotLoading(text string) fyne.CanvasObject {
	progress := widget.NewProgressBarInfinite()
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return container.NewCenter(neonPanel(accentBlue, container.NewVBox(label, progress)))
}

func snapshotImageObject(encoded string) fyne.CanvasObject {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return nil
	}

	image := canvas.NewImageFromReader(bytes.NewReader(raw), "cluster-snapshot.png")
	image.FillMode = canvas.ImageFillContain
	image.SetMinSize(fyne.NewSize(0, 220))
	scroll := container.NewVScroll(container.NewPadded(image))
	scroll.SetMinSize(fyne.NewSize(0, 240))
	return scroll
}

func snapshotImageObjectFromFile(path string) fyne.CanvasObject {
	if strings.TrimSpace(path) == "" || !fileLooksValid(path) {
		return nil
	}
	image := canvas.NewImageFromFile(path)
	image.FillMode = canvas.ImageFillContain
	image.SetMinSize(fyne.NewSize(0, 220))
	scroll := container.NewVScroll(container.NewPadded(image))
	scroll.SetMinSize(fyne.NewSize(0, 240))
	return scroll
}

func (d *dashboard) ensureClusterSnapshot(snapshot model.ResponseSnapshot, cacheKey string, force bool) (string, error) {
	if !force {
		if encoded := strings.TrimSpace(d.clusterSnapshotValue(cacheKey)); encoded != "" {
			return encoded, nil
		}
	}

	pngPath, err := captureBrowserSnapshot(snapshot, cacheKey, force)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(pngPath)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	d.setClusterSnapshotValue(cacheKey, encoded)
	return encoded, nil
}

func (d *dashboard) clusterSnapshotValue(key string) string {
	d.snapshotMu.Lock()
	defer d.snapshotMu.Unlock()
	return d.clusterSnapshots[key]
}

func (d *dashboard) setClusterSnapshotValue(key string, value string) {
	d.snapshotMu.Lock()
	defer d.snapshotMu.Unlock()
	if d.clusterSnapshots == nil {
		d.clusterSnapshots = map[string]string{}
	}
	if d.snapshotPresence == nil {
		d.snapshotPresence = map[string]bool{}
	}
	d.clusterSnapshots[key] = value
	d.snapshotPresence[key] = strings.TrimSpace(value) != ""
}

func (d *dashboard) clusterHasSnapshot(key string) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	d.snapshotMu.Lock()
	if present, ok := d.snapshotPresence[key]; ok {
		d.snapshotMu.Unlock()
		return present
	}
	encoded := strings.TrimSpace(d.clusterSnapshots[key])
	d.snapshotMu.Unlock()
	if encoded != "" {
		d.snapshotMu.Lock()
		if d.snapshotPresence == nil {
			d.snapshotPresence = map[string]bool{}
		}
		d.snapshotPresence[key] = true
		d.snapshotMu.Unlock()
		return true
	}

	snapshot := d.clusterBlockedSnapshot(key)
	_, pngPath, _ := snapshotCachePaths(snapshot, key)
	if !fileLooksValid(pngPath) {
		d.snapshotMu.Lock()
		if d.snapshotPresence == nil {
			d.snapshotPresence = map[string]bool{}
		}
		d.snapshotPresence[key] = false
		d.snapshotMu.Unlock()
		return false
	}
	d.snapshotMu.Lock()
	if d.snapshotPresence == nil {
		d.snapshotPresence = map[string]bool{}
	}
	d.snapshotPresence[key] = true
	d.snapshotMu.Unlock()
	return true
}

func captureBrowserSnapshot(snapshot model.ResponseSnapshot, cacheKey string, force bool) (string, error) {
	body := strings.TrimSpace(snapshot.Body)
	if body == "" {
		body = strings.TrimSpace(rawBody(snapshot.Raw))
	}
	if body == "" {
		return "", fmt.Errorf("当前聚类没有可渲染的 HTML 响应体")
	}

	browserPath, err := findHeadlessBrowserBinary()
	if err != nil {
		return "", err
	}

	htmlPath, pngPath, profileDir := snapshotCachePaths(snapshot, cacheKey)
	cacheDir := filepath.Dir(htmlPath)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}

	if !force {
		if _, err := os.Stat(pngPath); err == nil {
			return pngPath, nil
		}
	} else {
		_ = os.Remove(pngPath)
	}

	document := normalizeSnapshotHTML(snapshot, body)
	if err := os.WriteFile(htmlPath, []byte(document), 0o644); err != nil {
		return "", err
	}

	_ = os.RemoveAll(profileDir)
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--disable-background-networking",
		"--disable-background-timer-throttling",
		"--disable-renderer-backgrounding",
		"--disable-component-update",
		"--disable-sync",
		"--disable-default-apps",
		"--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication,CertificateTransparencyComponentUpdater,Translate,ChromeWhatsNewUI",
		"--metrics-recording-only",
		"--mute-audio",
		"--no-pings",
		"--password-store=basic",
		"--use-mock-keychain",
		"--disable-breakpad",
		"--disable-crash-reporter",
		"--hide-scrollbars",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-quic",
		"--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE localhost",
		"--allow-file-access-from-files",
		"--window-size=1440,960",
		"--default-background-color=ffffff",
		"--virtual-time-budget=1800",
		"--run-all-compositor-stages-before-draw",
		"--user-data-dir=" + profileDir,
		"--screenshot=" + pngPath,
		"file://" + htmlPath,
	}

	output, err := exec.CommandContext(ctx, browserPath, args...).CombinedOutput()
	if err != nil {
		if fileLooksValid(pngPath) {
			return pngPath, nil
		}
		return "", fmt.Errorf("浏览器截图失败: %v\n%s", err, summarizeBrowserSnapshotOutput(output))
	}
	if !fileLooksValid(pngPath) {
		return "", fmt.Errorf("浏览器未生成截图文件")
	}
	return pngPath, nil
}

func summarizeBrowserSnapshotOutput(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 {
		return ""
	}
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "deprecated_endpoint") ||
			strings.Contains(lower, "failed to connect to mcs endpoint") ||
			strings.Contains(lower, "tensorflow lite xnnpack delegate") ||
			strings.Contains(lower, "trying to load the allocator multiple times") ||
			strings.Contains(lower, "imkclient") ||
			strings.Contains(lower, "imkinputsession") {
			continue
		}
		filtered = append(filtered, line)
		if len(filtered) >= 6 {
			break
		}
	}
	if len(filtered) == 0 {
		return "浏览器进程异常退出，且未生成可用截图文件。"
	}
	return strings.Join(filtered, "\n")
}

func snapshotCachePaths(snapshot model.ResponseSnapshot, cacheKey string) (htmlPath string, pngPath string, profileDir string) {
	body := strings.TrimSpace(snapshot.Body)
	if body == "" {
		body = strings.TrimSpace(rawBody(snapshot.Raw))
	}
	cacheDir := filepath.Join(os.TempDir(), "wafkiller-browser-snapshots")
	fingerprint := sha1.Sum([]byte(cacheKey + "\n" + snapshot.URL + "\n" + body))
	name := hex.EncodeToString(fingerprint[:])
	return filepath.Join(cacheDir, name+".html"), filepath.Join(cacheDir, name+".png"), filepath.Join(cacheDir, "profile-"+name)
}

func snapshotCachePathsSafe(snapshot model.ResponseSnapshot, cacheKey string) (htmlPath string, pngPath string, ok bool) {
	body := strings.TrimSpace(snapshot.Body)
	if body == "" {
		body = strings.TrimSpace(rawBody(snapshot.Raw))
	}
	if strings.TrimSpace(cacheKey) == "" || body == "" {
		return "", "", false
	}
	htmlPath, pngPath, _ = snapshotCachePaths(snapshot, cacheKey)
	return htmlPath, pngPath, true
}

func fileLooksValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}

func findHeadlessBrowserBinary() (string, error) {
	candidates := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("未找到可用于截图的 Chrome/Chromium 浏览器")
}

func normalizeSnapshotHTML(snapshot model.ResponseSnapshot, body string) string {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<body") || strings.Contains(lower, "<!doctype") {
		return injectSnapshotPolicy(forceUTF8HTML(body))
	}

	title := htmlstd.EscapeString(emptyFallback(snapshot.Title, "WAF Killer Snapshot"))
	server := htmlstd.EscapeString(headerValueFromRaw(snapshot.Headers, "Server"))
	content := htmlstd.EscapeString(body)

	return fmt.Sprintf(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: file:; style-src 'unsafe-inline' data: file:; font-src data: file:; media-src data: file:; connect-src 'none'; frame-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <style>
    body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; margin: 0; background: #f6f8fb; color: #111827; }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 48px 32px 72px; }
    .meta { color: #0f766e; font-weight: 600; margin-bottom: 12px; }
    .card { background: #ffffff; border: 1px solid #dbe4f0; border-radius: 18px; box-shadow: 0 18px 50px rgba(15,23,42,0.12); padding: 28px; }
    pre { white-space: pre-wrap; word-break: break-word; font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size: 14px; line-height: 1.55; margin: 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="meta">服务端: %s</div>
    <div class="card"><pre>%s</pre></div>
  </div>
</body>
</html>`, title, server, content)
}

func forceUTF8HTML(document string) string {
	document = charsetMetaPattern.ReplaceAllString(document, "")
	document = cspMetaPattern.ReplaceAllString(document, "")

	lower := strings.ToLower(document)
	if strings.Contains(lower, "<head") {
		headIndex := strings.Index(lower, "<head")
		if headIndex >= 0 {
			closeOffset := strings.Index(lower[headIndex:], ">")
			if closeOffset >= 0 {
				insertAt := headIndex + closeOffset + 1
				return document[:insertAt] + `<meta charset="utf-8">` + snapshotPolicyMeta() + document[insertAt:]
			}
		}
	}

	if strings.Contains(lower, "<html") {
		if htmlIndex := strings.Index(lower, "<html"); htmlIndex >= 0 {
			closeOffset := strings.Index(lower[htmlIndex:], ">")
			if closeOffset >= 0 {
				insertAt := htmlIndex + closeOffset + 1
				return document[:insertAt] + `<head><meta charset="utf-8">` + snapshotPolicyMeta() + `</head>` + document[insertAt:]
			}
		}
	}

	return `<!doctype html><html><head><meta charset="utf-8">` + snapshotPolicyMeta() + `</head><body>` + document + `</body></html>`
}

func injectSnapshotPolicy(document string) string {
	if strings.Contains(strings.ToLower(document), "content-security-policy") {
		return document
	}
	lower := strings.ToLower(document)
	if strings.Contains(lower, "<head") {
		headIndex := strings.Index(lower, "<head")
		if headIndex >= 0 {
			closeOffset := strings.Index(lower[headIndex:], ">")
			if closeOffset >= 0 {
				insertAt := headIndex + closeOffset + 1
				return document[:insertAt] + snapshotPolicyMeta() + document[insertAt:]
			}
		}
	}
	return document
}

func snapshotPolicyMeta() string {
	return `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data: file:; style-src 'unsafe-inline' data: file:; font-src data: file:; media-src data: file:; connect-src 'none'; frame-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">`
}
