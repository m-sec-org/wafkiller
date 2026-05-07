package ui

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"wafbps/internal/agent"
	"wafbps/internal/config"
	"wafbps/internal/detector"
	"wafbps/internal/downstreamproxy"
	"wafbps/internal/exporter"
	"wafbps/internal/fofa"
	"wafbps/internal/model"
	"wafbps/internal/plugin"
	"wafbps/internal/store"
	"wafbps/internal/tester"
)

type dashboard struct {
	app    fyne.App
	window fyne.Window

	configPath string
	cfg        model.Config
	db         *store.Store
	dbState    store.Database

	sites         []model.Site
	filteredSites []model.Site
	plugins       []model.Plugin
	results       []model.TestResult
	detections    map[string]model.DetectionResult

	currentStep              int
	selectedSite             int
	selectedPlugin           int
	selectedResult           int
	selectedCluster          int
	selectedBypassCluster    int
	selectedClusterSite      int
	syncingFilter            bool
	identifyOnlyWAF          bool
	clusterLabels            map[string]string
	clusterLabelSources      map[string]string
	clusterRuleDetails       map[string]string
	clusterBaseline          []store.ClusterBaselineItem
	clusterMembers           map[string][]string
	clusterViewCache         []clusterView
	clusterViewsDirty        bool
	clusterSnapshots         map[string]string
	snapshotPresence         map[string]bool
	yamlMatchers             []wafYAMLMatcher
	recentClusters           map[string]bool
	ignoredClusters          map[string]bool
	fingerprints             map[string]store.ClusterFingerprint
	fingerprintMu            sync.RWMutex
	usedSampleWords          map[string]bool
	seenSiteKeys             map[string]bool
	siteTotalCount           int
	sessionBypassSites       map[string]bool
	sessionBypassResults     map[string]model.TestResult
	fingerprintBaseCount     int
	sampleWordMu             sync.Mutex
	currentScanID            string
	detectMu                 sync.Mutex
	snapshotMu               sync.Mutex
	searchCancel             context.CancelFunc
	searchRunning            bool
	searchTrigger            string
	searchOutcome            string
	detectCancel             context.CancelFunc
	detectRunning            bool
	detectStopReason         string
	detectOutcome            string
	clusterCancel            context.CancelFunc
	clusterRunning           bool
	clusterStopReason        string
	clusterOutcome           string
	fingerprintRunning       bool
	ruleValidationCancel     context.CancelFunc
	ruleValidationRunning    bool
	ruleValidationStopReason string
	pipelineCancel           context.CancelFunc
	pipelineRunning          bool
	pipelineStage            string
	pipelineSampleCount      int
	pipelineCurrentRun       int
	pipelineAddedSites       int
	pipelineBtn              *widget.Button

	queryEntry               *widget.Entry
	sizeEntry                *widget.Entry
	chinaOnlyCheck           *widget.Check
	concurrencyEntry         *widget.Entry
	snapshotConcurrencyEntry *widget.Entry
	pipelineCountEntry       *widget.Entry
	filterSelect             *widget.Select
	filterKeywordEntry       *widget.Entry
	clusterTagEntry          *widget.Entry
	libraryTagEntry          *widget.Entry
	libraryWAFSelect         *widget.Select

	workflowList         *widget.List
	workflowButtons      []*widget.Button
	workflowBody         *fyne.Container
	detailTabs           *container.AppTabs
	toolbarDetectBtn     *widget.Button
	identifyDetectBtn    *widget.Button
	searchBtn            *widget.Button
	sampleBtn            *widget.Button
	ruleValidationBtn    *widget.Button
	siteList             *widget.List
	clusterList          *widget.List
	pluginList           *widget.List
	resultList           *widget.List
	bypassStatsList      *widget.List
	siteDetails          *widget.Entry
	clusterDetails       *widget.Entry
	clusterPreview       *widget.Entry
	clusterSnapshot      *fyne.Container
	clusterResultList    *widget.List
	ruleStatsList        *widget.List
	pluginDetails        *widget.Entry
	resultDetails        *widget.Entry
	clusterSummaryLabel  *widget.Label
	clusterNoticeLabel   *canvas.Text
	ruleStatsSummary     *widget.Label
	clusterMetricBar     *fyne.Container
	fingerprintMetricBar *fyne.Container
	bypassStatsScope     *widget.Label
	bypassStatsEmpty     *widget.Label

	statusText            *canvas.Text
	siteCountValue        *canvas.Text
	siteDeltaValue        *canvas.Text
	suspectedValue        *canvas.Text
	suspectedDeltaValue   *canvas.Text
	labeledValue          *canvas.Text
	labeledDeltaValue     *canvas.Text
	ignoredValue          *canvas.Text
	clusterCountValue     *canvas.Text
	clusterDeltaValue     *canvas.Text
	clusterPendingValue   *canvas.Text
	clusterMarkedText     *canvas.Text
	clusterIgnoredText    *canvas.Text
	nonWAFFingerprintText *canvas.Text
	filteredValue         *canvas.Text
	pluginCountValue      *canvas.Text
	resultCountValue      *canvas.Text
	possibleValue         *canvas.Text
	possibleSlashValue    *canvas.Text
	possibleTotalValue    *canvas.Text
	blockedValue          *canvas.Text
	reviewValue           *canvas.Text
	topWAFValue           *canvas.Text
	cockpitLabel          *widget.Label
	selectionLabel        *widget.Label
	footerTrackLabel      *widget.Label
	currentFilterInfo     *widget.Label
	pulseLabel            *widget.Label
	currentStepLabel      *widget.Label
	clusterNoticeToken    int64

	consoleMu             sync.Mutex
	consoleLines          []string
	consoleBody           *fyne.Container
	consoleScroll         *container.Scroll
	consoleDetailBox      *fyne.Container
	consoleTitle          *widget.Label
	consoleStatus         *widget.Label
	consoleProgress       *neonProgressBar
	consoleProgressText   *widget.Label
	consoleClearBtn       *widget.Button
	consoleToggleBtn      *widget.Button
	consoleDetailsVisible bool
	consoleRefreshPending bool
	consoleUpdateMu       sync.Mutex
	consoleUpdatePending  bool
	consoleHasStatus      bool
	consoleStatusLatest   string
	consoleHasProgress    bool
	consoleProgressCur    int
	consoleProgressTotal  int

	bypassStatsRows       []bypassClusterStat
	bypassStatsPluginSet  map[string]bool
	bypassStatsPluginText string
	bypassStatsResults    []model.TestResult
	bypassStatsLastTapID  int
	bypassStatsLastTapAt  time.Time
	clusterResultRows     []clusterResultSiteDetail
	ruleStatsRows         []ruleStatsRow
	agentMessages         []agentChatMessage
	agentWindow           fyne.Window
	agentTranscript       *widget.Label
	agentTranscriptScroll *container.Scroll
	agentPromptEntry      *widget.Entry
	agentBusy             bool
	proxyService          *downstreamproxy.Service
	proxyTrafficEntries   []downstreamproxy.AuditEntry
	proxyTrafficMu        sync.Mutex
}

type uiEventQueue interface {
	QueueEvent(func())
}

type bypassClusterStat struct {
	Key        string
	Title      string
	GroupCount int
	Attempts   int
	Successes  int
	Rate       float64
}

type clusterResultSiteDetail struct {
	SiteKey      string
	ClusterKey   string
	Title        string
	URL          string
	RuleName     string
	Verdict      string
	MatchedRule  string
	StatusCode   int
	BaselineSim  float64
	BlockedSim   float64
	DiffRatio    float64
	Attempts     int
	Successes    int
	Passed       bool
	RawResponse  string
	Snapshot     model.ResponseSnapshot
	ResponseHead string
	ResponseBody string
}

type ruleStatsRow struct {
	Name      string
	Color     color.NRGBA
	Attempts  int
	Successes int
	Rate      float64
	Tested    bool
}

type ruleCompareSiteRow struct {
	SiteKey      string
	ClusterKey   string
	ClusterTitle string
	WAF          string
	Title        string
	URL          string
	First        model.TestResult
	Second       model.TestResult
}

type ruleCompareGroup struct {
	Key   string
	Title string
	WAF   string
	Rows  []ruleCompareSiteRow
}

type ruleCompareDiffRow struct {
	SiteKey      string
	ClusterKey   string
	ClusterTitle string
	WAF          string
	Title        string
	URL          string
	AResult      model.TestResult
	BResult      model.TestResult
}

type ruleCompareDiffGroup struct {
	Key   string
	Title string
	WAF   string
	Rows  []ruleCompareDiffRow
}

type agentChatMessage struct {
	Role string
	Text string
	At   time.Time
}

func bypassStatAccent(key string) color.NRGBA {
	palette := []color.NRGBA{
		accentAmber,
		accentBlue,
		accentGreen,
		accentPink,
		accentCyan,
		{R: 180, G: 120, B: 255, A: 255},
		{R: 255, G: 120, B: 196, A: 255},
		{R: 120, G: 232, B: 255, A: 255},
	}
	if len(palette) == 0 {
		return accentBlue
	}
	sum := 0
	for _, ch := range key {
		sum += int(ch)
	}
	return palette[sum%len(palette)]
}

func namedRuleAccent(name string) (color.NRGBA, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cyan", "blue-cyan":
		return accentCyan, true
	case "blue":
		return accentBlue, true
	case "green", "mint":
		return accentGreen, true
	case "amber", "orange", "gold":
		return accentAmber, true
	case "pink":
		return accentPink, true
	case "purple", "violet", "lavender":
		return color.NRGBA{R: 186, G: 150, B: 255, A: 255}, true
	case "red", "rose":
		return color.NRGBA{R: 255, G: 120, B: 144, A: 255}, true
	case "teal":
		return color.NRGBA{R: 90, G: 240, B: 220, A: 255}, true
	case "yellow":
		return color.NRGBA{R: 255, G: 214, B: 92, A: 255}, true
	case "white", "ice":
		return color.NRGBA{R: 225, G: 240, B: 255, A: 255}, true
	default:
		return color.NRGBA{}, false
	}
}

func pluginAccent(p model.Plugin) color.NRGBA {
	if accent, ok := namedRuleAccent(p.Color); ok {
		return accent
	}
	return bypassStatAccent("rule:" + strings.TrimSpace(p.Name))
}

func pluginIntentSummary(p model.Plugin) string {
	if len(p.Intents) == 0 {
		return "-"
	}
	lines := make([]string, 0, len(p.Intents))
	for _, intent := range p.Intents {
		name := strings.TrimSpace(intent.Name)
		if name == "" || strings.EqualFold(name, "none") {
			continue
		}
		args := make([]string, 0, len(intent.Args))
		for key, value := range intent.Args {
			args = append(args, fmt.Sprintf("%s=%q", key, value))
		}
		sort.Strings(args)
		if len(args) > 0 {
			name += " (" + strings.Join(args, ", ") + ")"
		}
		lines = append(lines, name)
	}
	if len(lines) == 0 {
		return "-"
	}
	return strings.Join(lines, "\n")
}

func ruleValidationAccent(name string) color.NRGBA {
	return bypassStatAccent("rule:" + strings.TrimSpace(name))
}

func (d *dashboard) baselineRequestPacket(site model.Site) string {
	return d.baselineRequestPacketForDetection(site, nil)
}

func (d *dashboard) baselineRequestPacketForDetection(site model.Site, detection *model.DetectionResult) string {
	targetURL := ""
	if detection != nil {
		targetURL = strings.TrimSpace(detection.DetectedURL)
		if targetURL == "" {
			targetURL = strings.TrimSpace(detection.Baseline.URL)
		}
	}
	if targetURL == "" {
		targetURL = strings.TrimSpace(site.OriginalURL)
	}
	if targetURL == "" {
		targetURL = strings.TrimSpace(site.URL)
	}

	var parsed *url.URL
	if targetURL != "" {
		if u, err := url.Parse(targetURL); err == nil && u != nil {
			parsed = u
		}
	}
	if parsed == nil || strings.TrimSpace(parsed.Host) == "" {
		host := strings.TrimSpace(site.Host)
		if host == "" {
			host = strings.TrimSpace(site.Domain)
		}
		if host == "" {
			return ""
		}
		scheme := strings.TrimSpace(d.cfg.Tester.DefaultScheme)
		if scheme == "" {
			scheme = "https"
		}
		parsed = &url.URL{Scheme: scheme, Host: host}
	}

	query := parsed.Query()
	query.Set("id", "1")
	parsed.Path = "/"
	parsed.RawQuery = query.Encode()

	hostHeader := parsed.Host
	userAgent := strings.TrimSpace(d.cfg.Variables["USER_AGENT"])
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	}

	lines := []string{
		fmt.Sprintf("GET %s HTTP/1.1", parsed.RequestURI()),
		"Host: " + hostHeader,
		"User-Agent: " + userAgent,
		"",
	}
	return strings.Join(lines, "\n")
}

func findCanvasText(obj fyne.CanvasObject) *canvas.Text {
	switch typed := obj.(type) {
	case *canvas.Text:
		return typed
	case *fyne.Container:
		for _, child := range typed.Objects {
			if text := findCanvasText(child); text != nil {
				return text
			}
		}
	}
	return nil
}

func (d *dashboard) runOnUI(fn func()) {
	if fn == nil {
		return
	}
	if d != nil && d.window != nil {
		if q, ok := any(d.window).(uiEventQueue); ok {
			q.QueueEvent(fn)
			return
		}
	}
	fn()
}

func (d *dashboard) runOnUISync(fn func()) {
	if fn == nil {
		return
	}
	if d != nil && d.window != nil {
		if q, ok := any(d.window).(uiEventQueue); ok {
			done := make(chan struct{})
			q.QueueEvent(func() {
				defer close(done)
				fn()
			})
			<-done
			return
		}
	}
	fn()
}

func (d *dashboard) newDetectToggleButton(goToIdentify bool) *widget.Button {
	btn := widget.NewButtonWithIcon("", detectResource(), func() {
		if d.detectRunning {
			d.stopDetectSites()
			return
		}
		if goToIdentify {
			d.gotoStep(1)
		}
		d.detectSites()
	})
	return btn
}

func (d *dashboard) updateDetectButtons() {
	d.runOnUI(func() {
		label := "开始识别"
		icon := detectResource()
		if d.detectRunning && !(d.pipelineRunning && d.pipelineStage == "detect") {
			label = "停止识别"
			icon = stopResource()
		}
		if d.toolbarDetectBtn != nil {
			d.toolbarDetectBtn.SetText(label)
			d.toolbarDetectBtn.SetIcon(icon)
			d.toolbarDetectBtn.Refresh()
		}
		if d.identifyDetectBtn != nil {
			d.identifyDetectBtn.SetText(label)
			d.identifyDetectBtn.SetIcon(icon)
			d.identifyDetectBtn.Refresh()
		}
	})
}

func (d *dashboard) updatePipelineButton() {
	d.runOnUI(func() {
		label := "一键执行"
		icon := playResource()
		if d.pipelineRunning {
			label = "停止"
			icon = stopResource()
		}
		if d.pipelineBtn != nil {
			d.pipelineBtn.SetText(label)
			d.pipelineBtn.SetIcon(icon)
			d.pipelineBtn.Refresh()
		}
	})
}

func (d *dashboard) updateSearchButtons() {
	d.runOnUI(func() {
		searchLabel := "搜索"
		sampleLabel := "随机采样"
		searchIcon := searchResource()
		sampleIcon := boltResource()
		if d.searchRunning && d.searchTrigger == "search" {
			searchLabel = "停止"
			searchIcon = stopResource()
		}
		if d.searchRunning && d.searchTrigger == "sample" {
			sampleLabel = "停止"
			sampleIcon = stopResource()
		}
		if d.searchBtn != nil {
			d.searchBtn.SetText(searchLabel)
			d.searchBtn.SetIcon(searchIcon)
			d.searchBtn.Refresh()
		}
		if d.sampleBtn != nil {
			d.sampleBtn.SetText(sampleLabel)
			d.sampleBtn.SetIcon(sampleIcon)
			d.sampleBtn.Refresh()
		}
	})
}

func (d *dashboard) updateRuleValidationButton() {
	d.runOnUI(func() {
		label := "规则验证"
		icon := shieldResource()
		if d.ruleValidationRunning {
			label = "停止"
			icon = stopResource()
		}
		if d.ruleValidationBtn != nil {
			d.ruleValidationBtn.SetText(label)
			d.ruleValidationBtn.SetIcon(icon)
			d.ruleValidationBtn.Refresh()
		}
	})
}

func (d *dashboard) stopRuleValidation(reason string) {
	d.detectMu.Lock()
	cancel := d.ruleValidationCancel
	running := d.ruleValidationRunning
	if running {
		d.ruleValidationStopReason = strings.TrimSpace(emptyFallback(reason, "用户手动停止"))
	}
	d.detectMu.Unlock()

	if !running || cancel == nil {
		return
	}
	cancel()
	d.appendConsoleLog(fmt.Sprintf("[ctrl] 已发送停止指令，原因=%s，正在终止规则验证", strings.TrimSpace(emptyFallback(reason, "用户手动停止"))))
	d.setConsoleStatus("正在停止规则验证...")
	d.updateRuleValidationButton()
}

func (d *dashboard) setPipelineStage(stage string) {
	d.detectMu.Lock()
	d.pipelineStage = stage
	d.detectMu.Unlock()
}

func (d *dashboard) stopClustering(reason string) {
	d.detectMu.Lock()
	cancel := d.clusterCancel
	running := d.clusterRunning
	if running {
		d.clusterStopReason = strings.TrimSpace(emptyFallback(reason, "用户手动停止"))
	}
	d.detectMu.Unlock()

	if !running || cancel == nil {
		return
	}
	cancel()
	d.appendConsoleLog(fmt.Sprintf("[ctrl] 已发送停止指令，原因=%s，正在终止聚类任务", strings.TrimSpace(emptyFallback(reason, "用户手动停止"))))
	d.setConsoleStatus("正在停止聚类...")
}

func (d *dashboard) stopPipeline() {
	d.detectMu.Lock()
	cancel := d.pipelineCancel
	running := d.pipelineRunning
	stage := d.pipelineStage
	searchCancel := d.searchCancel
	detectCancel := d.detectCancel
	clusterCancel := d.clusterCancel
	d.detectMu.Unlock()

	if !running || cancel == nil {
		return
	}

	cancel()
	switch stage {
	case "search":
		if searchCancel != nil {
			searchCancel()
		}
	case "detect":
		if detectCancel != nil {
			d.stopDetectSites()
		}
	case "cluster":
		if clusterCancel != nil {
			d.stopClustering("用户手动停止")
		}
	}
	d.appendConsoleLog(fmt.Sprintf("[ctrl] 一键执行已发送停止指令，当前阶段=%s", emptyFallback(stage, "待机")))
	d.setConsoleStatus("正在停止一键执行...")
	d.setStatus("一键执行 // 正在停止当前任务链")
}

func (d *dashboard) waitForStageIdle(ctx context.Context, isRunning func() bool) error {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	for {
		if !isRunning() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *dashboard) isSearchRunning() bool {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.searchRunning
}

func (d *dashboard) isDetectRunning() bool {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.detectRunning
}

func (d *dashboard) isClusterRunning() bool {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.clusterRunning
}

func (d *dashboard) currentSearchOutcome() string {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.searchOutcome
}

func (d *dashboard) currentDetectOutcome() string {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.detectOutcome
}

func (d *dashboard) currentClusterOutcome() string {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.clusterOutcome
}

func (d *dashboard) nextDetectTargets() []model.Site {
	source := d.filteredSites
	if len(source) == 0 {
		source = d.sites
	}
	if len(source) == 0 {
		return nil
	}

	targets := make([]model.Site, 0, len(source))
	for _, site := range source {
		if _, ok := d.detectionForSite(site); ok {
			continue
		}
		targets = append(targets, site)
	}
	return targets
}

func (d *dashboard) runPipeline() {
	d.detectMu.Lock()
	if d.pipelineRunning {
		d.detectMu.Unlock()
		d.stopPipeline()
		return
	}
	if d.searchRunning || d.detectRunning || d.clusterRunning {
		d.detectMu.Unlock()
		dialog.ShowInformation("任务进行中", "当前已有搜索、识别或聚类任务在运行，请先等待完成或停止后再执行一键任务。", d.window)
		return
	}
	pipelineCount := d.currentPipelineCount()
	if pipelineCount <= 0 {
		pipelineCount = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.pipelineCancel = cancel
	d.pipelineRunning = true
	d.pipelineStage = "search"
	d.pipelineSampleCount = pipelineCount
	d.pipelineCurrentRun = 0
	d.pipelineAddedSites = 0
	d.detectMu.Unlock()
	d.updatePipelineButton()

	go func() {
		defer func() {
			d.detectMu.Lock()
			d.pipelineCancel = nil
			d.pipelineRunning = false
			d.pipelineStage = ""
			d.pipelineSampleCount = 0
			d.pipelineCurrentRun = 0
			d.pipelineAddedSites = 0
			d.detectMu.Unlock()
			d.updatePipelineButton()
			cancel()
		}()

		for run := 1; run <= pipelineCount; run++ {
			d.detectMu.Lock()
			d.pipelineCurrentRun = run
			d.detectMu.Unlock()
			keyword := d.randomSampleKeyword()
			d.queryEntry.SetText(keyword)
			d.setStatus(fmt.Sprintf("一键执行 ×%d // 第 %d/%d 轮随机采样关键词 %s", pipelineCount, run, pipelineCount, keyword))
			if !d.fetchSites("pipeline") {
				return
			}
			if err := d.waitForStageIdle(ctx, d.isSearchRunning); err != nil {
				return
			}
			if d.currentSearchOutcome() != "completed" {
				return
			}
		}

		targets := d.nextDetectTargets()
		if len(targets) > 0 {
			d.setPipelineStage("detect")
			d.setStatus(fmt.Sprintf("一键执行 ×%d // 开始自动识别，新增目标 %d 个", pipelineCount, len(targets)))
			if d.detectSites() {
				if err := d.waitForStageIdle(ctx, d.isDetectRunning); err != nil {
					return
				}
				if d.currentDetectOutcome() != "completed" {
					return
				}
			}
		}

		d.setPipelineStage("cluster")
		d.setStatus(fmt.Sprintf("一键执行 ×%d // 开始自动聚类", pipelineCount))
		started := d.autoClusterResponses()
		if started {
			if err := d.waitForStageIdle(ctx, d.isClusterRunning); err != nil {
				return
			}
			if d.currentClusterOutcome() != "completed" {
				return
			}
		}

		d.appendConsoleLog(fmt.Sprintf("[done ×%d] 一键执行完成 | 已完成随机采样、识别、聚类", pipelineCount))
		d.setConsoleStatus("一键执行完成")
		d.setStatus(fmt.Sprintf("一键执行 ×%d // 已完成随机采样、识别、聚类", pipelineCount))
	}()
}

func Run() error {
	cfg, err := config.Load(config.DefaultConfigPath)
	if err != nil {
		return err
	}

	a := app.NewWithID("wafbps.cyberpunk.desktop")
	a.Settings().SetTheme(neonTheme{})

	db := store.New(cfg.App.DatabasePath)

	d := &dashboard{
		app:                   a,
		window:                a.NewWindow(cfg.App.WindowTitle),
		configPath:            cfg.App.ConfigPath,
		cfg:                   cfg,
		db:                    db,
		dbState:               emptyDatabaseState(),
		currentStep:           0,
		selectedSite:          -1,
		selectedPlugin:        -1,
		selectedResult:        -1,
		selectedCluster:       -1,
		selectedBypassCluster: -1,
		selectedClusterSite:   -1,
		clusterLabels:         map[string]string{},
		clusterLabelSources:   map[string]string{},
		clusterBaseline:       []store.ClusterBaselineItem{},
		clusterMembers:        map[string][]string{},
		clusterViewsDirty:     true,
		clusterSnapshots:      map[string]string{},
		snapshotPresence:      map[string]bool{},
		yamlMatchers:          loadWAFYAMLMatchers("waf.yaml"),
		recentClusters:        map[string]bool{},
		ignoredClusters:       map[string]bool{},
		fingerprints:          map[string]store.ClusterFingerprint{},
		usedSampleWords:       map[string]bool{},
		seenSiteKeys:          map[string]bool{},
		sessionBypassSites:    map[string]bool{},
		sessionBypassResults:  map[string]model.TestResult{},
		detections:            map[string]model.DetectionResult{},
	}

	d.window.Resize(fyne.NewSize(1220, 700))
	d.window.SetFixedSize(true)
	d.window.SetContent(d.buildContent())
	d.setStatus("启动中 // 正在后台恢复数据库和插件")
	d.window.Show()

	go d.bootstrapAsync()
	a.Run()
	return nil
}

func emptyDatabaseState() store.Database {
	return store.Database{
		Version:      store.CurrentVersion,
		Current:      store.Snapshot{Sites: []model.Site{}, SiteKeys: []string{}, Detections: map[string]model.DetectionResult{}, ClusterLabels: map[string]string{}, ClusterLabelSources: map[string]string{}, ClusterRuleDetails: map[string]string{}, ClusterBaseline: []store.ClusterBaselineItem{}, ClusterSnapshots: map[string]string{}, IgnoredClusters: map[string]bool{}, Results: []model.TestResult{}},
		Scans:        []store.ScanRecord{},
		Fingerprints: map[string]store.ClusterFingerprint{},
	}
}

func (d *dashboard) bootstrapAsync() {
	type dbLoadResult struct {
		state store.Database
		err   error
	}
	type startupLoadResult struct {
		cache store.StartupCache
		err   error
	}
	type pluginLoadResult struct {
		plugins []model.Plugin
		err     error
	}

	dbCh := make(chan dbLoadResult, 1)
	startupCh := make(chan startupLoadResult, 1)
	pluginCh := make(chan pluginLoadResult, 1)

	go func() {
		cache, err := d.db.LoadStartupCache()
		startupCh <- startupLoadResult{cache: cache, err: err}
	}()
	go func() {
		state, err := d.db.Load()
		dbCh <- dbLoadResult{state: state, err: err}
	}()
	go func() {
		plugins, err := plugin.Load(d.cfg.Plugin.Dir)
		pluginCh <- pluginLoadResult{plugins: plugins, err: err}
	}()

	var (
		dbErr      error
		pluginErr  error
		pluginRows []model.Plugin
	)

	for completed := 0; completed < 3; completed++ {
		select {
		case result := <-startupCh:
			if result.err != nil {
				continue
			}
			d.applyStartupCache(result.cache)
		case result := <-dbCh:
			dbErr = result.err
			if dbErr != nil {
				d.runOnUI(func() {
					dialog.ShowError(dbErr, d.window)
				})
				d.setStatus("错误 // 本地数据库恢复失败")
				continue
			}
			d.dbState = result.state
			if len(d.dbState.Current.Sites) > 0 {
				d.dbState.Current.Sites = []model.Site{}
				d.persistCurrentDBStateAsync()
			}
			fingerprintCount := d.restoreDatabaseStateFast()
			d.refreshDashboard()
			d.runOnUI(func() {
				if d.siteList != nil {
					d.siteList.Refresh()
				}
				if d.clusterList != nil {
					d.clusterList.Refresh()
				}
				d.updateSiteDetails()
				d.updateClusterDetails()
				d.updateResultDetails()
			})
			if d.siteTotalCount > 0 || len(d.detections) > 0 || len(d.results) > 0 || fingerprintCount > 0 {
				d.setStatus(fmt.Sprintf("数据库 // 已恢复 %d 条站点、%d 条识别、%d 条结果、%d 条指纹，正在整理分类...", d.siteTotalCount, len(d.detections), len(d.results), fingerprintCount))
			} else {
				d.setStatus("数据库 // 已恢复完成，正在整理分类...")
			}
			go d.finishBootstrapRestore()
		case result := <-pluginCh:
			pluginErr = result.err
			if pluginErr != nil {
				d.plugins = nil
				d.runOnUI(func() {
					if d.pluginList != nil {
						d.pluginList.Refresh()
					}
					if d.pluginDetails != nil {
						d.pluginDetails.SetText("")
					}
					dialog.ShowError(pluginErr, d.window)
				})
				d.setStatus("错误 // 无法加载插件目录")
				continue
			}
			pluginRows = result.plugins
			d.plugins = pluginRows
			d.selectedPlugin = -1
			d.runOnUI(func() {
				if d.pluginDetails != nil {
					d.pluginDetails.SetText("")
				}
				if d.pluginList != nil {
					d.pluginList.Refresh()
				}
			})
			d.refreshDashboard()
			if dbErr != nil {
				d.setStatus(fmt.Sprintf("插件就绪 // 已载入 %d 条规则", len(pluginRows)))
			}
		}
	}

	if dbErr == nil && pluginErr == nil {
		d.setStatus(fmt.Sprintf("启动完成 // 已恢复本地数据并载入 %d 条规则", len(pluginRows)))
	}
}

func (d *dashboard) buildContent() fyne.CanvasObject {
	d.queryEntry = widget.NewEntry()
	d.queryEntry.SetText(d.cfg.FOFA.Query)

	d.sizeEntry = widget.NewEntry()
	d.sizeEntry.SetText(strconv.Itoa(clampFOFASize(d.cfg.FOFA.Size)))
	if size, err := strconv.Atoi(strings.TrimSpace(d.sizeEntry.Text)); err != nil || size < 1 {
		d.sizeEntry.SetText("2000")
	}
	d.sizeEntry.OnChanged = func(value string) {
		sanitized := sanitizeFOFASizeInput(value)
		if sanitized != value {
			d.sizeEntry.SetText(sanitized)
		}
	}

	d.chinaOnlyCheck = widget.NewCheck("国内站点", nil)
	d.chinaOnlyCheck.SetChecked(true)

	d.concurrencyEntry = widget.NewEntry()
	d.concurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.Concurrency))
	if concurrency, err := strconv.Atoi(strings.TrimSpace(d.concurrencyEntry.Text)); err != nil || concurrency < 1 {
		d.concurrencyEntry.SetText("100")
	}

	d.snapshotConcurrencyEntry = widget.NewEntry()
	d.snapshotConcurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.SnapshotConcurrency))
	if concurrency, err := strconv.Atoi(strings.TrimSpace(d.snapshotConcurrencyEntry.Text)); err != nil || concurrency < 1 {
		d.snapshotConcurrencyEntry.SetText("20")
	}

	d.filterKeywordEntry = widget.NewEntry()
	d.filterKeywordEntry.SetPlaceHolder("输入关键字缩小赛道目标")
	d.filterKeywordEntry.OnChanged = func(_ string) {
		d.applyFilters()
	}

	d.filterSelect = widget.NewSelect([]string{"全部"}, func(_ string) {
		d.applyFilters()
	})

	d.libraryWAFSelect = widget.NewSelect([]string{"全部产品"}, func(string) {
		d.refreshCurrentStepView()
	})
	d.libraryWAFSelect.SetSelected("全部产品")

	d.libraryTagEntry = widget.NewEntry()
	d.libraryTagEntry.SetPlaceHolder("按技术点过滤规则，例如 JSON、大小写、分块")
	d.libraryTagEntry.OnChanged = func(string) {
		d.refreshCurrentStepView()
	}

	d.clusterTagEntry = widget.NewEntry()
	d.clusterTagEntry.SetPlaceHolder("输入当前聚类对应的 WAF 产品名称")

	d.statusText = canvas.NewText("待命 // 已载入配置，可以开始采集", accentCyan)
	d.statusText.TextSize = 13
	d.statusText.TextStyle = fyne.TextStyle{Bold: true}

	d.siteCountValue = metricValue("0", accentCyan)
	d.siteDeltaValue = metricDeltaText(accentCyan)
	d.suspectedValue = metricValue("0", color.NRGBA{R: 255, G: 196, B: 118, A: 255})
	d.suspectedDeltaValue = metricDeltaText(color.NRGBA{R: 255, G: 196, B: 118, A: 255})
	d.labeledValue = metricValue("0", accentPink)
	d.labeledDeltaValue = metricDeltaText(accentPink)
	d.ignoredValue = metricValue("0", accentGreen)
	d.clusterCountValue = metricValue("0", accentBlue)
	d.clusterDeltaValue = metricDeltaText(accentGreen)
	d.clusterPendingValue = metricValue("0", color.NRGBA{R: 162, G: 220, B: 255, A: 235})
	d.clusterPendingValue.TextSize = 24
	d.clusterMarkedText = canvas.NewText("已标记 0 组", color.NRGBA{R: 147, G: 255, B: 194, A: 230})
	d.clusterMarkedText.TextSize = 11
	d.clusterMarkedText.TextStyle = fyne.TextStyle{Bold: true}
	d.clusterIgnoredText = canvas.NewText("已忽略 0 组", color.NRGBA{R: 255, G: 184, B: 216, A: 230})
	d.clusterIgnoredText.TextSize = 11
	d.clusterIgnoredText.TextStyle = fyne.TextStyle{Bold: true}
	d.nonWAFFingerprintText = canvas.NewText("非waf指纹 0 个", color.NRGBA{R: 147, G: 255, B: 194, A: 230})
	d.nonWAFFingerprintText.TextSize = 11
	d.nonWAFFingerprintText.TextStyle = fyne.TextStyle{Bold: true}
	d.filteredValue = metricValue("0", accentAmber)
	d.pluginCountValue = metricValue("0", color.NRGBA{R: 186, G: 150, B: 255, A: 255})
	d.resultCountValue = metricValue("0", accentGreen)
	d.possibleValue = metricValue("0", accentGreen)
	d.possibleSlashValue = metricValue("/", color.NRGBA{R: 148, G: 176, B: 224, A: 210})
	d.possibleSlashValue.TextSize = 24
	d.possibleTotalValue = metricValue("0", color.NRGBA{R: 162, G: 220, B: 255, A: 235})
	d.blockedValue = metricValue("0", accentPink)
	d.reviewValue = metricValue("0", accentAmber)
	d.topWAFValue = metricValue("暂无", accentBlue)
	d.topWAFValue.TextSize = 16

	d.cockpitLabel = widget.NewLabel("")
	d.cockpitLabel.Wrapping = fyne.TextWrapWord

	d.selectionLabel = widget.NewLabel("")
	d.selectionLabel.Wrapping = fyne.TextWrapWord

	d.currentFilterInfo = widget.NewLabel("")
	d.currentFilterInfo.Wrapping = fyne.TextWrapWord

	d.pulseLabel = widget.NewLabel("")
	d.pulseLabel.Wrapping = fyne.TextWrapWord
	d.clusterSummaryLabel = widget.NewLabel("")
	d.clusterSummaryLabel.Wrapping = fyne.TextWrapWord
	d.clusterNoticeLabel = canvas.NewText("", accentGreen)
	d.clusterNoticeLabel.TextSize = 11
	d.clusterNoticeLabel.TextStyle = fyne.TextStyle{Bold: true}
	d.ruleStatsSummary = widget.NewLabel("规则绕过率 // 暂无验证数据")
	d.ruleStatsSummary.Wrapping = fyne.TextWrapWord
	d.clusterMetricBar = container.NewHBox(
		d.clusterMarkedText,
		canvas.NewText("  ", color.Transparent),
		d.clusterIgnoredText,
	)
	d.fingerprintMetricBar = container.NewHBox(d.nonWAFFingerprintText)

	d.siteDetails = widget.NewMultiLineEntry()
	d.siteDetails.Disable()
	d.siteDetails.SetMinRowsVisible(8)

	d.clusterDetails = widget.NewMultiLineEntry()
	d.clusterDetails.Disable()
	d.clusterDetails.SetMinRowsVisible(8)

	d.clusterPreview = widget.NewMultiLineEntry()
	d.clusterPreview.Disable()
	d.clusterPreview.SetMinRowsVisible(14)
	d.clusterSnapshot = container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "cluster-empty", false))
	d.clusterResultList = widget.NewList(
		func() int { return len(d.clusterResultRows) },
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(accentBlue)
			bar.SetMinSize(fyne.NewSize(6, 58))
			badge := listBadge(accentBlue, siteResource())
			title := widget.NewLabel("站点")
			title.TextStyle = fyne.TextStyle{Bold: true}
			subtitle := widget.NewLabel("相似度")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("判定")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(bar, badge, container.NewVBox(title, subtitle, meta))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.clusterResultRows) {
				return
			}
			rowData := d.clusterResultRows[id]
			row := item.(*fyne.Container)
			accent := verdictAccent(rowData.Verdict)
			if !rowData.Passed {
				accent = accentAmber
			}
			bar := row.Objects[0].(*canvas.Rectangle)
			bar.FillColor = accent
			bar.Refresh()
			row.Objects[1] = listBadge(accent, siteResource())

			content := row.Objects[2].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(rowData.Title)
			similarityText := fmt.Sprintf("基线 %.2f | 拦截 %.2f | 差异 %.0f%%", rowData.BaselineSim, rowData.BlockedSim, rowData.DiffRatio*100)
			content.Objects[1].(*widget.Label).SetText(similarityText)
			content.Objects[2].(*widget.Label).SetText(fmt.Sprintf("%s | %s | %d/%d", rowData.Verdict, emptyFallback(rowData.RuleName, "-"), rowData.Successes, rowData.Attempts))
			row.Refresh()
		},
	)
	d.clusterResultList.OnSelected = func(id widget.ListItemID) {
		d.selectedClusterSite = id
		d.updateClusterResultDetails()
	}
	d.ruleStatsList = widget.NewList(
		func() int { return len(d.ruleStatsRows) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 224})
			bar := canvas.NewRectangle(accentBlue)
			bar.SetMinSize(fyne.NewSize(4, 40))
			title := widget.NewLabel("规则")
			title.TextStyle = fyne.TextStyle{Bold: true}
			title.Wrapping = fyne.TextWrapOff
			title.Alignment = fyne.TextAlignLeading
			state := widget.NewLabel("未检测")
			state.Wrapping = fyne.TextWrapOff
			state.Alignment = fyne.TextAlignLeading
			rate := canvas.NewText("未检测", accentBlue)
			rate.TextStyle = fyne.TextStyle{Bold: true}
			rate.TextSize = 11
			row := container.NewHBox(
				container.NewGridWrap(fyne.NewSize(228, 20), title),
				container.NewGridWrap(fyne.NewSize(116, 20), state),
				container.NewGridWrap(fyne.NewSize(64, 20), container.NewCenter(rate)),
			)
			return container.NewStack(
				bg,
				container.NewHBox(bar, container.NewPadded(row), layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.ruleStatsRows) {
				return
			}
			rowData := d.ruleStatsRows[id]
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = rowData.Color
			bar.Refresh()
			content := main.Objects[1].(*fyne.Container).Objects[0].(*fyne.Container)
			content.Objects[0].(*fyne.Container).Objects[0].(*widget.Label).SetText(rowData.Name)
			state := content.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
			rate := findCanvasText(content.Objects[2])
			if rate == nil {
				return
			}
			if !rowData.Tested {
				state.SetText("未检测")
				rate.Text = "未检测"
			} else {
				state.SetText(fmt.Sprintf("成功 %d/%d", rowData.Successes, rowData.Attempts))
				rate.Text = fmt.Sprintf("%.0f%%", rowData.Rate*100)
			}
			rate.Color = rowData.Color
			rate.Refresh()
			row.Refresh()
		},
	)

	d.pluginDetails = widget.NewMultiLineEntry()
	d.pluginDetails.Disable()
	d.pluginDetails.SetMinRowsVisible(7)

	d.resultDetails = widget.NewMultiLineEntry()
	d.resultDetails.Disable()
	d.resultDetails.SetMinRowsVisible(7)

	d.consoleTitle = widget.NewLabel("控制台 // 待命")
	d.consoleStatus = widget.NewLabel("等待任务启动")
	d.consoleProgress = newNeonProgressBar()
	d.consoleProgress.SetValue(0)
	d.consoleProgressText = widget.NewLabel("0%")
	d.consoleBody = container.NewVBox()
	d.consoleScroll = container.NewVScroll(d.consoleBody)
	d.consoleScroll.SetMinSize(fyne.NewSize(0, 68))
	d.consoleDetailBox = container.NewMax(d.consoleScroll)
	d.consoleDetailBox.Hide()
	d.consoleClearBtn = widget.NewButton("清空", func() {
		d.resetConsole("控制台", "日志已清空")
	})
	d.consoleClearBtn.Importance = widget.LowImportance
	d.consoleToggleBtn = widget.NewButton("详情", func() {
		d.toggleConsoleDetails()
	})
	d.consoleToggleBtn.Importance = widget.LowImportance
	d.resetConsole("控制台", "等待任务启动")

	d.siteList = widget.NewList(
		func() int { return len(d.filteredSites) },
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(accentCyan)
			bar.SetMinSize(fyne.NewSize(6, 72))
			badge := listBadge(accentCyan, siteResource())
			title := widget.NewLabel("站点")
			title.TextStyle = fyne.TextStyle{Bold: true}
			subtitle := widget.NewLabel("WAF / 标题")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("地区 / 技术")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(bar, badge, container.NewVBox(title, subtitle, meta))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.filteredSites) {
				return
			}
			site := d.filteredSites[id]
			row := item.(*fyne.Container)
			effectiveWAF := d.effectiveSiteWAF(site)
			bar := row.Objects[0].(*canvas.Rectangle)
			accent := wafAccent(effectiveWAF)
			bar.FillColor = accent
			bar.Refresh()
			row.Objects[1] = listBadge(accent, siteResource())

			content := row.Objects[2].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(emptyFallback(site.Host, site.URL))
			content.Objects[1].(*widget.Label).SetText(fmt.Sprintf("%s  |  %s", emptyFallback(effectiveWAF, "未知"), emptyFallback(site.Title, site.Domain)))
			content.Objects[2].(*widget.Label).SetText(fmt.Sprintf("%s %s  |  %s", site.Country, site.City, emptyFallback(site.Server, site.Product)))
			row.Refresh()
		},
	)
	d.siteList.OnSelected = func(id widget.ListItemID) {
		d.selectedSite = id
		d.updateSiteDetails()
		d.refreshCockpit()
	}

	d.clusterList = widget.NewList(
		func() int { return len(d.clusterViews()) },
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(accentAmber)
			bar.SetMinSize(fyne.NewSize(6, 72))
			badge := listBadge(accentAmber, shieldResource())
			title := widget.NewLabel("聚类")
			title.TextStyle = fyne.TextStyle{Bold: true}
			subtitle := widget.NewLabel("签名 / 标签")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("样本 / 原始响应")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(bar, badge, container.NewVBox(title, subtitle, meta))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			clusters := d.clusterViews()
			if id < 0 || id >= len(clusters) {
				return
			}
			cluster := clusters[id]
			row := item.(*fyne.Container)
			accent := accentBlue
			if cluster.IsNew {
				accent = accentGreen
			} else if cluster.Label != "" {
				accent = color.NRGBA{R: 255, G: 164, B: 182, A: 255}
			}
			bar := row.Objects[0].(*canvas.Rectangle)
			bar.FillColor = accent
			bar.Refresh()
			row.Objects[1] = listBadge(accent, shieldResource())

			content := row.Objects[2].(*fyne.Container)
			title := clusterDefaultTitle(cluster)
			content.Objects[0].(*widget.Label).SetText(title)
			subtitle := cluster.Signature
			if sourceText := clusterLabelSourceText(cluster.LabelSource); sourceText != "" {
				subtitle = sourceText + "  |  " + subtitle
			}
			content.Objects[1].(*widget.Label).SetText(subtitle)
			content.Objects[2].(*widget.Label).SetText(fmt.Sprintf("样本 %d  |  代表站点 %s", cluster.Count, cluster.SampleHost))
			row.Refresh()
		},
	)
	d.clusterList.OnSelected = func(id widget.ListItemID) {
		d.selectedCluster = id
		d.updateClusterDetails()
		d.refreshCockpit()
	}

	d.pluginList = widget.NewList(
		func() int { return len(d.plugins) },
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(accentPink)
			bar.SetMinSize(fyne.NewSize(6, 72))
			badge := listBadge(accentPink, pluginResource())
			title := widget.NewLabel("插件")
			title.TextStyle = fyne.TextStyle{Bold: true}
			subtitle := widget.NewLabel("规则标签")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("方法 / 路径")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(bar, badge, container.NewVBox(title, subtitle, meta))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.plugins) {
				return
			}
			p := d.plugins[id]
			row := item.(*fyne.Container)
			bar := row.Objects[0].(*canvas.Rectangle)
			accent := pluginAccent(p)
			bar.FillColor = accent
			bar.Refresh()
			row.Objects[1] = listBadge(accent, pluginResource())

			content := row.Objects[2].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(p.Name)
			content.Objects[1].(*widget.Label).SetText(emptyFallback(strings.Join(p.Tags, ", "), "未分类"))
			content.Objects[2].(*widget.Label).SetText(fmt.Sprintf("%s  %s", p.Method, p.RequestURI))
			row.Refresh()
		},
	)
	d.pluginList.OnSelected = func(id widget.ListItemID) {
		d.selectedPlugin = id
		d.updatePluginDetails()
		d.refreshCockpit()
	}

	d.resultList = widget.NewList(
		func() int { return len(d.results) },
		func() fyne.CanvasObject {
			bar := canvas.NewRectangle(accentGreen)
			bar.SetMinSize(fyne.NewSize(6, 72))
			badge := listBadge(accentGreen, resultResource())
			title := widget.NewLabel("结果")
			title.TextStyle = fyne.TextStyle{Bold: true}
			verdict := verdictChip("需要复核")
			subtitle := widget.NewLabel("状态码 000")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("规则 / 延迟")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(bar, badge, container.NewVBox(
				title,
				container.NewHBox(verdict, subtitle),
				meta,
			))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.results) {
				return
			}
			r := d.results[id]
			row := item.(*fyne.Container)
			bar := row.Objects[0].(*canvas.Rectangle)
			accent := verdictAccent(r.Verdict)
			bar.FillColor = accent
			bar.Refresh()
			row.Objects[1] = listBadge(accent, resultResource())

			content := row.Objects[2].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(fmt.Sprintf("%s ｜ %s", r.Plugin.Name, r.Site.Host))
			infoRow := content.Objects[1].(*fyne.Container)
			infoRow.Objects[0] = verdictChip(r.Verdict)
			infoRow.Objects[1].(*widget.Label).SetText(fmt.Sprintf("状态码 %d", r.StatusCode))
			content.Objects[2].(*widget.Label).SetText(fmt.Sprintf("%s  |  %s", emptyFallback(r.MatchedRule, "-"), r.Duration.Round(time.Millisecond)))
			row.Refresh()
		},
	)
	d.resultList.OnSelected = func(id widget.ListItemID) {
		d.selectedResult = id
		d.updateResultDetails()
		d.refreshCockpit()
	}

	d.syncingFilter = true
	d.filterSelect.SetSelected("全部")
	d.syncingFilter = false

	header := d.buildWorkflowHeader()
	workflowBar := d.buildWorkflowTopBar()
	d.workflowBody = container.NewMax()
	d.workflowBody.Objects = []fyne.CanvasObject{d.buildCurrentStep()}
	detailDrawer := d.buildDetailDrawer()

	mainSplit := container.NewHSplit(d.workflowBody, detailDrawer)
	mainSplit.Offset = 0.58

	return container.NewStack(
		d.buildBackdrop(),
		container.NewBorder(
			container.NewVBox(workflowBar, header, d.buildConsolePanel()),
			nil,
			nil,
			nil,
			container.NewPadded(mainSplit),
		),
	)
}

func (d *dashboard) buildBackdrop() fyne.CanvasObject {
	base := canvas.NewLinearGradient(
		color.NRGBA{R: 5, G: 7, B: 12, A: 255},
		color.NRGBA{R: 14, G: 10, B: 22, A: 255},
		22,
	)
	trackFade := canvas.NewLinearGradient(
		color.NRGBA{R: 0, G: 242, B: 255, A: 24},
		color.NRGBA{R: 255, G: 71, B: 136, A: 8},
		320,
	)
	topGlow := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 18},
		color.NRGBA{R: 0, G: 242, B: 255, A: 12},
		90,
	)
	topGlow.SetMinSize(fyne.NewSize(0, 110))
	bottomGlow := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 71, B: 136, A: 18},
		color.NRGBA{R: 255, G: 168, B: 56, A: 8},
		90,
	)
	bottomGlow.SetMinSize(fyne.NewSize(0, 92))
	leftGlow := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 168, B: 56, A: 24},
		color.NRGBA{R: 255, G: 168, B: 56, A: 0},
		180,
	)
	leftGlow.SetMinSize(fyne.NewSize(22, 0))
	rightGlow := canvas.NewLinearGradient(
		color.NRGBA{R: 0, G: 242, B: 255, A: 22},
		color.NRGBA{R: 0, G: 242, B: 255, A: 0},
		0,
	)
	rightGlow.SetMinSize(fyne.NewSize(18, 0))
	cyanOrb := canvas.NewRadialGradient(
		color.NRGBA{R: 0, G: 242, B: 255, A: 34},
		color.NRGBA{R: 0, G: 242, B: 255, A: 0},
	)
	pinkOrb := canvas.NewRadialGradient(
		color.NRGBA{R: 255, G: 71, B: 136, A: 28},
		color.NRGBA{R: 255, G: 71, B: 136, A: 0},
	)
	core := canvas.NewRectangle(color.NRGBA{R: 9, G: 12, B: 19, A: 168})
	return container.NewStack(
		base,
		trackFade,
		cyanOrb,
		pinkOrb,
		container.NewBorder(topGlow, bottomGlow, leftGlow, rightGlow, core),
	)
}

func (d *dashboard) buildHeader() fyne.CanvasObject {
	title := canvas.NewText("WAF Killer", accentCyan)
	title.TextSize = 30
	title.TextStyle = fyne.TextStyle{Bold: true}
	titleGlow := canvas.NewText("WAF Killer", color.NRGBA{R: 255, G: 255, B: 255, A: 54})
	titleGlow.TextSize = 30
	titleGlow.TextStyle = fyne.TextStyle{Bold: true}

	subtitle := widget.NewLabel("赛博霓虹驾驶舱，用于 FOFA 目标采集、WAF 标签筛选与原始请求绕过验证")
	subtitle.Wrapping = fyne.TextWrapWord
	sparkline := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 0},
		color.NRGBA{R: 255, G: 255, B: 255, A: 96},
		270,
	)
	sparkline.SetMinSize(fyne.NewSize(180, 3))
	accentLine := canvas.NewLinearGradient(
		accentPink,
		accentCyan,
		270,
	)
	accentLine.SetMinSize(fyne.NewSize(220, 4))

	queryForm := container.NewGridWithColumns(
		4,
		widget.NewLabel("FOFA 语句"),
		d.queryEntry,
		widget.NewLabel("数量"),
		d.sizeEntry,
	)

	searchBtn := widget.NewButtonWithIcon("开始采集", radarResource(), func() {
		d.fetchSites("search")
	})
	reloadBtn := widget.NewButtonWithIcon("重载插件", boltResource(), func() {
		d.reloadPlugins()
	})
	settingsBtn := widget.NewButtonWithIcon("配置中心", shieldResource(), func() {
		d.openSettingsDialog()
	})

	actions := container.NewHBox(searchBtn, reloadBtn, settingsBtn)
	stats := container.NewGridWithColumns(
		4,
		metricCard("采集站点", d.siteCountValue, accentCyan),
		metricCard("筛选结果", d.filteredValue, accentAmber),
		metricCard("插件数量", d.pluginCountValue, accentPink),
		metricCard("测试结果", d.resultCountValue, accentGreen),
	)
	heroImage := themedImage(heroResource(), 320, 150)
	heroCaption := widget.NewLabel("高速霓虹赛道 / 目标锁定 / 绕过攻坚")
	heroCaption.Wrapping = fyne.TextWrapWord
	heroMeta := widget.NewLabel("视觉模块 // 杀阵引擎已点火")
	heroMeta.Wrapping = fyne.TextWrapWord
	heroLamps := container.NewHBox(
		animatedSignalLamp(16, accentCyan),
		widget.NewLabel("采集回路"),
		animatedSignalLamp(16, accentPink),
		widget.NewLabel("绕过引擎"),
		animatedSignalLamp(16, accentGreen),
		widget.NewLabel("判定脉冲"),
	)
	heroSignals := container.NewGridWithColumns(
		3,
		iconChip(accentAmber, radarResource(), "采集波束", "FOFA 目标正在等待扫描"),
		iconChip(accentPink, boltResource(), "绕过引擎", "原始请求插件已挂载"),
		iconChip(accentGreen, shieldResource(), "防护判定", "拦截与绕过结果并行显示"),
	)
	heroCard := neonPanel(accentPink, container.NewVBox(heroImage, heroLamps, heroSignals, heroCaption, heroMeta))

	headerRow := container.NewHBox(
		container.NewVBox(
			container.NewStack(titleGlow, title),
			subtitle,
			container.NewHBox(accentLine, sparkline),
			widget.NewLabel("赛道编码 // FOFA-采集 / WAF-筛选 / 原始请求-验证"),
			container.NewGridWithColumns(
				3,
				iconChip(accentCyan, siteResource(), "目标矩阵", "站点、标题、地区与产品画像"),
				iconChip(accentPink, pluginResource(), "插件车库", "规则库按标签快速检索"),
				iconChip(accentGreen, resultResource(), "结果脉冲", "判定、状态码与规则命中联动"),
			),
		),
		layout.NewSpacer(),
		container.NewVBox(themedIcon(resultResource(), 18), heroCard),
	)
	hudItem := widget.NewAccordionItem("扫描控制台 / 仪表盘", container.NewVBox(
		queryForm,
		actions,
		widget.NewSeparator(),
		stats,
	))
	hudItem.Open = false
	accordion := widget.NewAccordion(hudItem)
	return neonPanel(accentCyan, container.NewVBox(headerRow, accordion))
}

func (d *dashboard) buildSidebar() fyne.CanvasObject {
	filterControls := container.NewVBox(
		sectionHeading(accentAmber, shieldResource(), "WAF 标签筛选", "按防护品牌快速缩小赛道"),
		d.filterSelect,
		sectionHeading(accentCyan, radarResource(), "关键字筛选", "结合主机、标题和域名进行锁定"),
		d.filterKeywordEntry,
	)
	verdictGrid := container.NewGridWithColumns(
		2,
		metricCard("可能绕过", d.possibleValue, accentGreen),
		metricCard("已拦截", d.blockedValue, accentPink),
		metricCard("需要复核", d.reviewValue, accentAmber),
		metricCard("热点 WAF", d.topWAFValue, accentBlue),
	)

	telemetry := widget.NewLabel("选择站点、插件或结果后，这里会显示对应的驾驶舱遥测信息。")
	telemetry.Wrapping = fyne.TextWrapWord
	d.currentFilterInfo.SetText("筛选 // 全部")

	legend := widget.NewRichTextFromMarkdown(strings.Join([]string{
		"### 操作路线",
		"- `开始采集`：从 FOFA 拉取目标",
		"- `重载插件`：重新扫描原始请求规则",
		"- `运行当前`：执行单条插件验证",
		"- `批量验证`：按站点 WAF 批量执行规则",
	}, "\n"))
	emblemImage := themedImage(emblemResource(), 128, 128)
	emblemTitle := widget.NewLabel("杀阵徽章")
	emblemTitle.Wrapping = fyne.TextWrapWord
	emblemText := widget.NewLabel("图像模块 // 用于强化控制台氛围与品牌辨识度")
	emblemText.Wrapping = fyne.TextWrapWord
	emblemSignals := container.NewGridWithColumns(
		2,
		iconChip(accentPink, pluginResource(), "规则上膛", "插件标签与验证结果联动"),
		iconChip(accentBlue, siteResource(), "目标热区", "当前筛选可见站点实时变化"),
	)
	emblemCard := neonPanel(accentPink, container.NewVBox(emblemImage, emblemSignals, emblemTitle, emblemText))

	navItem := widget.NewAccordionItem("导航面板", filterControls)
	navItem.Open = true
	pulseItem := widget.NewAccordionItem("脉冲 / 热度", container.NewVBox(emblemCard, widget.NewSeparator(), verdictGrid, widget.NewSeparator(), d.pulseLabel, d.currentFilterInfo))
	pulseItem.Open = false
	cockpitItem := widget.NewAccordionItem("驾驶舱信息", container.NewVBox(d.cockpitLabel, widget.NewSeparator(), d.selectionLabel, widget.NewSeparator(), telemetry))
	cockpitItem.Open = false
	guideItem := widget.NewAccordionItem("操作路线", legend)
	guideItem.Open = false

	return neonPanel(accentAmber, widget.NewAccordion(navItem, pulseItem, cockpitItem, guideItem))
}

func (d *dashboard) buildTargetPanel() fyne.CanvasObject {
	clearBtn := widget.NewButton("清空缓存", func() {
		d.sites = nil
		d.filteredSites = nil
		d.selectedSite = -1
		d.siteDetails.SetText("")
		d.refreshWAFOptions()
		d.applyFilters()
		d.setStatus("本地缓存已清空")
	})

	header := container.NewHBox(
		sectionHeading(accentCyan, siteResource(), "目标列表", "互联网站点画像与 WAF 标签"),
		layout.NewSpacer(),
		clearBtn,
	)

	listCard := neonPanel(accentCyan, container.NewBorder(
		header,
		nil,
		nil,
		nil,
		d.siteList,
	))
	detailCard := neonPanel(accentBlue, container.NewBorder(
		sectionHeading(accentBlue, radarResource(), "目标详情", "主机、地区、标题与指纹细节"),
		nil,
		nil,
		nil,
		d.siteDetails,
	))

	gridItem := widget.NewAccordionItem("目标列表", listCard)
	gridItem.Open = true
	detailItem := widget.NewAccordionItem("目标详情", detailCard)
	detailItem.Open = false
	accordion := widget.NewAccordion(gridItem, detailItem)
	accordion.MultiOpen = true
	return accordion
}

func (d *dashboard) buildOpsPanel() fyne.CanvasObject {
	runSelected := widget.NewButtonWithIcon("运行当前", boltResource(), func() {
		d.runSelectedPlugin()
	})
	runAll := widget.NewButtonWithIcon("批量验证", radarResource(), func() {
		d.runAllPlugins()
	})
	exportJSONBtn := widget.NewButtonWithIcon("导出 JSON", resultResource(), func() {
		d.exportResults("json")
	})
	exportHTMLBtn := widget.NewButtonWithIcon("导出 HTML", resultResource(), func() {
		d.exportResults("html")
	})
	clearResultsBtn := widget.NewButtonWithIcon("清空结果", shieldResource(), func() {
		d.results = nil
		d.bypassStatsResults = nil
		d.sessionBypassSites = map[string]bool{}
		d.sessionBypassResults = map[string]model.TestResult{}
		d.selectedResult = -1
		if d.resultList != nil {
			d.resultList.Refresh()
		}
		d.updateResultDetails()
		d.refreshDashboard()
		d.setStatus("测试结果已清空")
	})

	pluginHeader := container.NewHBox(
		sectionHeading(accentPink, pluginResource(), "插件车库", "原始请求规则与标签检索"),
		layout.NewSpacer(),
		runSelected,
		runAll,
	)
	pluginCard := neonPanel(accentPink, container.NewBorder(
		pluginHeader,
		d.pluginDetails,
		nil,
		nil,
		d.pluginList,
	))

	resultHeader := container.NewHBox(
		sectionHeading(accentGreen, resultResource(), "结果分析器", "状态码、命中规则与响应预览"),
		layout.NewSpacer(),
		exportJSONBtn,
		exportHTMLBtn,
		clearResultsBtn,
	)
	resultCard := neonPanel(accentGreen, container.NewBorder(
		resultHeader,
		d.resultDetails,
		nil,
		nil,
		d.resultList,
	))

	pluginItem := widget.NewAccordionItem("插件车库", pluginCard)
	pluginItem.Open = true
	resultItem := widget.NewAccordionItem("结果分析器", resultCard)
	resultItem.Open = false
	accordion := widget.NewAccordion(pluginItem, resultItem)
	accordion.MultiOpen = true
	return accordion
}

func (d *dashboard) openSelectedBypassClusterDetail() {
	if d.selectedBypassCluster < 0 || d.selectedBypassCluster >= len(d.bypassStatsRows) {
		dialog.ShowInformation("选择聚类", "请先在绕过统计中选择一个聚类分组。", d.window)
		return
	}
	d.showBypassClusterDetailViewer(d.bypassStatsRows[d.selectedBypassCluster].Key)
}

func (d *dashboard) buildAgentLauncherCard() fyne.CanvasObject {
	last := "智能体已待命，可执行一键采样、提取指纹、规则验证、规则对比分析，以及结构化生成 bypass 规则。"
	for i := len(d.agentMessages) - 1; i >= 0; i-- {
		if d.agentMessages[i].Role != "assistant" {
			continue
		}
		last = d.agentMessages[i].Text
		break
	}
	last = strings.TrimSpace(last)
	if len([]rune(last)) > 96 {
		runes := []rune(last)
		last = string(runes[:96]) + "..."
	}

	title := widget.NewLabelWithStyle("智能体助手", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	title.Wrapping = fyne.TextWrapOff
	summary := widget.NewLabel("通过对话完成一键执行采样、自动提取指纹、规则验证、规则对比，以及结构化编写 bypass 规则。")
	summary.Wrapping = fyne.TextWrapWord
	preview := widget.NewLabel("最近回复: " + emptyFallback(last, "待命"))
	preview.Wrapping = fyne.TextWrapWord

	openBtn := widget.NewButtonWithIcon("打开对话", compareResource(), func() {
		d.openAgentAssistant()
	})
	openBtn.SetIcon(agentResource())
	openBtn.Importance = widget.LowImportance

	return neonPanel(accentBlue, container.NewBorder(
		container.NewHBox(
			themedIcon(agentResource(), 18),
			title,
			layout.NewSpacer(),
			openBtn,
		),
		nil,
		nil,
		nil,
		container.NewVBox(
			summary,
			preview,
			widget.NewLabel("规则验证进行中时，这里会自动切换为绕过统计。"),
		),
	))
}

func (d *dashboard) buildBypassStatsCard() fyne.CanvasObject {
	if d.bypassStatsEmpty == nil {
		d.bypassStatsEmpty = widget.NewLabel("当前没有绕过统计。")
		d.bypassStatsEmpty.Wrapping = fyne.TextWrapWord
	}
	if d.isRuleValidationRunning() {
		d.bypassStatsEmpty.SetText("规则验证进行中，正在统计绕过数据...")
	} else {
		d.bypassStatsEmpty.SetText("当前没有绕过统计。")
	}
	if d.bypassStatsList == nil {
		d.bypassStatsList = widget.NewList(
			func() int { return len(d.bypassStatsRows) },
			func() fyne.CanvasObject {
				bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 228})
				tint := canvas.NewLinearGradient(
					color.NRGBA{R: accentBlue.R, G: accentBlue.G, B: accentBlue.B, A: 10},
					color.NRGBA{R: accentGreen.R, G: accentGreen.G, B: accentGreen.B, A: 16},
					0,
				)
				selectionGlow := canvas.NewLinearGradient(
					color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 0},
					color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 0},
					0,
				)
				selectionBorder := canvas.NewRectangle(color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 0})
				leftBar := canvas.NewRectangle(accentBlue)
				leftBar.SetMinSize(fyne.NewSize(5, 0))
				title := widget.NewLabel("聚类")
				title.TextStyle = fyne.TextStyle{Bold: true}
				title.Wrapping = fyne.TextWrapOff
				meta := widget.NewLabel("0/0 | 组内 0")
				meta.Wrapping = fyne.TextWrapOff
				track := canvas.NewRectangle(color.NRGBA{R: 20, G: 29, B: 45, A: 255})
				track.CornerRadius = 5
				track.StrokeColor = color.NRGBA{R: 96, G: 118, B: 154, A: 180}
				track.StrokeWidth = 1
				track.SetMinSize(fyne.NewSize(180, 7))
				fillGlow := canvas.NewRectangle(color.NRGBA{R: accentGreen.R, G: accentGreen.G, B: accentGreen.B, A: 34})
				fillGlow.CornerRadius = 5
				fillGlow.StrokeColor = color.NRGBA{R: 220, G: 236, B: 255, A: 150}
				fillGlow.StrokeWidth = 1
				fill := canvas.NewLinearGradient(
					color.NRGBA{R: 74, G: 143, B: 255, A: 255},
					color.NRGBA{R: 73, G: 255, B: 150, A: 255},
					0,
				)
				rateText := canvas.NewText("0%", color.NRGBA{R: 220, G: 235, B: 255, A: 230})
				rateText.TextSize = 11
				rateText.TextStyle = fyne.TextStyle{Bold: true}
				progress := container.NewWithoutLayout(track, fillGlow, fill)
				progress.Resize(fyne.NewSize(180, 7))
				titleWrap := container.NewGridWrap(fyne.NewSize(150, 18), title)
				metaWrap := container.NewGridWrap(fyne.NewSize(92, 18), meta)
				progressWrap := container.NewGridWrap(fyne.NewSize(260, 12), container.NewCenter(progress))
				rateWrap := container.NewGridWrap(fyne.NewSize(42, 18), container.NewCenter(rateText))
				contentRow := container.NewHBox(
					leftBar,
					titleWrap,
					metaWrap,
					progressWrap,
					rateWrap,
				)
				return container.NewStack(
					bg,
					tint,
					selectionGlow,
					selectionBorder,
					container.NewPadded(contentRow),
				)
			},
			func(id widget.ListItemID, item fyne.CanvasObject) {
				if id < 0 || id >= len(d.bypassStatsRows) {
					return
				}
				rowData := d.bypassStatsRows[id]
				row := item.(*fyne.Container)
				bg := row.Objects[0].(*canvas.Rectangle)
				if id%2 == 0 {
					bg.FillColor = color.NRGBA{R: 11, G: 17, B: 28, A: 232}
				} else {
					bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 232}
				}
				bg.Refresh()

				selectionGlow := row.Objects[2].(*canvas.LinearGradient)
				selectionBorder := row.Objects[3].(*canvas.Rectangle)
				if id == d.selectedBypassCluster && id >= 0 {
					selectionGlow.StartColor = color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 42}
					selectionGlow.EndColor = color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 24}
					selectionBorder.FillColor = color.NRGBA{R: 118, G: 208, B: 255, A: 52}
				} else {
					selectionGlow.StartColor = color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 0}
					selectionGlow.EndColor = color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 0}
					selectionBorder.FillColor = color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 0}
				}
				selectionGlow.Refresh()
				selectionBorder.Refresh()

				padded := row.Objects[4].(*fyne.Container)
				content := padded.Objects[0].(*fyne.Container)
				leftBar := content.Objects[0].(*canvas.Rectangle)
				barAccent := bypassStatAccent(rowData.Key)
				leftBar.FillColor = barAccent
				leftBar.Refresh()

				titleWrap := content.Objects[1].(*fyne.Container)
				title := titleWrap.Objects[0].(*widget.Label)
				title.SetText(rowData.Title)

				metaWrap := content.Objects[2].(*fyne.Container)
				meta := metaWrap.Objects[0].(*widget.Label)
				meta.SetText(fmt.Sprintf("%d/%d | 组内 %d", rowData.Successes, rowData.Attempts, rowData.GroupCount))

				progressHost := content.Objects[3].(*fyne.Container)
				progressCenter := progressHost.Objects[0].(*fyne.Container)
				progress := progressCenter.Objects[0].(*fyne.Container)
				rateWrap := content.Objects[4].(*fyne.Container)
				rateCenter := rateWrap.Objects[0].(*fyne.Container)
				rateText := rateCenter.Objects[0].(*canvas.Text)
				rateText.Text = fmt.Sprintf("%.0f%%", rowData.Rate*100)
				rateText.Color = barAccent
				rateText.Refresh()

				track := progress.Objects[0].(*canvas.Rectangle)
				fillGlow := progress.Objects[1].(*canvas.Rectangle)
				fill := progress.Objects[2].(*canvas.LinearGradient)
				size := progress.Size()
				if size.Width <= 0 {
					size = fyne.NewSize(180, 7)
				}
				track.Resize(size)
				width := float32(rowData.Rate) * size.Width
				if rowData.Attempts > 0 && width < 8 {
					width = 8
				}
				if width > size.Width {
					width = size.Width
				}
				fillSize := fyne.NewSize(width, size.Height)
				fillGlow.Resize(fillSize)
				fill.Resize(fillSize)
				fillGlow.FillColor = color.NRGBA{R: barAccent.R, G: barAccent.G, B: barAccent.B, A: 34}
				fillGlow.StrokeColor = color.NRGBA{R: 255, G: 255, B: 255, A: 132}
				fill.StartColor = color.NRGBA{R: 255, G: 255, B: 255, A: 210}
				fill.EndColor = barAccent
				fill.Refresh()
				fillGlow.Refresh()
				track.Refresh()
				row.Refresh()
			},
		)
		d.bypassStatsList.OnSelected = func(id widget.ListItemID) {
			if id < 0 || id >= len(d.bypassStatsRows) {
				return
			}
			now := time.Now()
			doubleTap := d.selectedBypassCluster == id && d.bypassStatsLastTapID == id && !d.bypassStatsLastTapAt.IsZero() && now.Sub(d.bypassStatsLastTapAt) <= 450*time.Millisecond
			d.selectedBypassCluster = id
			d.bypassStatsLastTapID = id
			d.bypassStatsLastTapAt = now
			d.bypassStatsList.Refresh()
			if doubleTap {
				d.openSelectedBypassClusterDetail()
			}
		}
	}
	for i := range d.bypassStatsRows {
		d.bypassStatsList.SetItemHeight(i, 34)
	}
	content := fyne.CanvasObject(d.bypassStatsEmpty)
	if len(d.bypassStatsRows) > 0 {
		content = d.bypassStatsList
	}
	headerIcon := themedIcon(resultResource(), 18)
	headerTitle := widget.NewLabelWithStyle("绕过统计", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	headerTitle.Wrapping = fyne.TextWrapOff
	header := container.NewHBox(
		container.NewCenter(headerIcon),
		headerTitle,
		layout.NewSpacer(),
		func() fyne.CanvasObject {
			viewBtn := widget.NewButton("查看", func() {
				d.openSelectedBypassClusterDetail()
			})
			viewBtn.Importance = widget.LowImportance
			return viewBtn
		}(),
	)
	return neonPanel(accentCyan, container.NewBorder(
		header,
		nil,
		nil,
		nil,
		content,
	))
}

func (d *dashboard) openAgentAssistant() {
	d.ensureAgentGreeting()
	if d.agentWindow != nil {
		d.agentWindow.Show()
		d.agentWindow.RequestFocus()
		return
	}

	transcript := widget.NewLabel("")
	transcript.Wrapping = fyne.TextWrapWord
	transcriptScroll := container.NewVScroll(transcript)
	transcriptScroll.SetMinSize(fyne.NewSize(0, 420))
	prompt := widget.NewMultiLineEntry()
	prompt.SetPlaceHolder("输入指令，例如：一键执行采样 / 提取指纹 / 用全部规则做规则验证 / 对比 规则A 和 规则B / 编写规则")
	prompt.SetMinRowsVisible(4)

	send := func() {
		message := strings.TrimSpace(prompt.Text)
		if message == "" {
			return
		}
		prompt.SetText("")
		d.handleAgentPrompt(message)
	}

	viewer := d.app.NewWindow("智能体助手")
	viewer.Resize(fyne.NewSize(960, 700))
	viewer.SetOnClosed(func() {
		d.agentWindow = nil
		d.agentTranscript = nil
		d.agentTranscriptScroll = nil
		d.agentPromptEntry = nil
	})

	sendBtn := widget.NewButtonWithIcon("发送", playResource(), send)
	sendBtn.Importance = widget.LowImportance
	quickRow := container.NewHBox(
		widget.NewButton("一键执行", func() { d.handleAgentPrompt("一键执行采样") }),
		widget.NewButton("提取指纹", func() { d.handleAgentPrompt("提取指纹") }),
		widget.NewButton("验证全部规则", func() { d.handleAgentPrompt("用全部规则做规则验证") }),
		widget.NewButton("帮助", func() { d.handleAgentPrompt("帮助") }),
	)

	d.agentWindow = viewer
	d.agentTranscript = transcript
	d.agentTranscriptScroll = transcriptScroll
	d.agentPromptEntry = prompt
	d.refreshAgentTranscript()

	viewer.SetContent(container.NewBorder(
		neonPanel(accentBlue, container.NewVBox(
			container.NewHBox(
				themedIcon(agentResource(), 18),
				widget.NewLabelWithStyle("智能体助手", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			),
			widget.NewLabel("可通过对话完成一键执行采样、提取指纹、规则验证、规则对比分析，以及结构化生成 bypass 规则。"),
			quickRow,
		)),
		neonPanel(accentAmber, container.NewBorder(
			nil,
			nil,
			nil,
			container.NewPadded(sendBtn),
			prompt,
		)),
		nil,
		nil,
		neonPanel(accentCyan, transcriptScroll),
	))
	viewer.Show()
}

func (d *dashboard) ensureAgentGreeting() {
	if len(d.agentMessages) > 0 {
		return
	}
	d.agentMessages = append(d.agentMessages, agentChatMessage{
		Role: "assistant",
		At:   time.Now(),
		Text: "我已接入当前工作流。你可以直接对我说：一键执行采样、提取指纹、用全部规则做规则验证、对比 某规则A 和 某规则B、或者按模板编写 bypass 规则。",
	})
}

func (d *dashboard) appendAgentMessage(role string, text string) {
	d.agentMessages = append(d.agentMessages, agentChatMessage{
		Role: role,
		Text: strings.TrimSpace(text),
		At:   time.Now(),
	})
	d.refreshAgentTranscript()
	d.runOnUI(func() {
		if d.workflowBody != nil && d.currentStep <= 4 && !d.isRuleValidationRunning() {
			d.refreshCurrentStepView()
		}
	})
}

func (d *dashboard) appendAgentMessageIndex(role string, text string) int {
	d.agentMessages = append(d.agentMessages, agentChatMessage{
		Role: role,
		Text: strings.TrimSpace(text),
		At:   time.Now(),
	})
	index := len(d.agentMessages) - 1
	d.refreshAgentTranscript()
	d.runOnUI(func() {
		if d.workflowBody != nil && d.currentStep <= 4 && !d.isRuleValidationRunning() {
			d.refreshCurrentStepView()
		}
	})
	return index
}

func (d *dashboard) updateAgentMessage(index int, role string, text string) {
	if index < 0 || index >= len(d.agentMessages) {
		d.appendAgentMessage(role, text)
		return
	}
	d.agentMessages[index].Role = role
	d.agentMessages[index].Text = strings.TrimSpace(text)
	d.agentMessages[index].At = time.Now()
	d.refreshAgentTranscript()
	d.runOnUI(func() {
		if d.workflowBody != nil && d.currentStep <= 4 && !d.isRuleValidationRunning() {
			d.refreshCurrentStepView()
		}
	})
}

func (d *dashboard) refreshAgentTranscript() {
	if d.agentTranscript == nil {
		return
	}
	lines := make([]string, 0, len(d.agentMessages)*3)
	for _, msg := range d.agentMessages {
		prefix := "你"
		if msg.Role == "assistant" {
			prefix = "助手"
		}
		lines = append(lines, fmt.Sprintf("[%s] %s", prefix, msg.Text), "")
	}
	text := strings.TrimSpace(strings.Join(lines, "\n"))
	d.runOnUI(func() {
		if d.agentTranscript == nil {
			return
		}
		d.agentTranscript.SetText(text)
		if d.agentTranscriptScroll != nil {
			d.agentTranscriptScroll.Offset.Y = 1e9
			d.agentTranscriptScroll.Refresh()
		}
	})
}

func (d *dashboard) agentSettings() agent.Settings {
	proxyURL := strings.TrimSpace(d.proxyUpstreamURL())
	provider := strings.ToLower(strings.TrimSpace(d.cfg.LLMProvider))
	switch provider {
	case "zhipu":
		return agent.Settings{
			Provider:        "zhipu",
			APIKey:          strings.TrimSpace(d.cfg.Zhipu.APIKey),
			BaseURL:         strings.TrimSpace(d.cfg.Zhipu.BaseURL),
			ProxyURL:        proxyURL,
			Model:           strings.TrimSpace(d.cfg.Zhipu.Model),
			ReasoningEffort: strings.TrimSpace(d.cfg.Zhipu.ReasoningEffort),
			TimeoutSeconds:  d.cfg.Zhipu.TimeoutSeconds,
		}
	default:
		return agent.Settings{
			Provider:        "openai",
			APIKey:          strings.TrimSpace(d.cfg.OpenAI.APIKey),
			BaseURL:         strings.TrimSpace(d.cfg.OpenAI.BaseURL),
			ProxyURL:        proxyURL,
			Model:           strings.TrimSpace(d.cfg.OpenAI.Model),
			ReasoningEffort: strings.TrimSpace(d.cfg.OpenAI.ReasoningEffort),
			TimeoutSeconds:  d.cfg.OpenAI.TimeoutSeconds,
		}
	}
}

func (d *dashboard) activeLLMProviderLabel() string {
	switch strings.ToLower(strings.TrimSpace(d.cfg.LLMProvider)) {
	case "zhipu":
		return "智谱AI"
	default:
		return "OpenAI"
	}
}

func (d *dashboard) activeLLMProviderEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(d.cfg.LLMProvider)) {
	case "zhipu":
		return d.cfg.Zhipu.Enabled
	default:
		return d.cfg.OpenAI.Enabled
	}
}

func (d *dashboard) agentInstructions() string {
	lines := []string{
		"你是 wafbps 内置的真实智能体助手，需要通过工具调用来执行任务，而不是假装完成。",
		"你的工作目标：帮助用户完成一键执行采样、自动提取 WAF 指纹、规则验证、两条规则对比分析，以及结构化编写 bypass 规则。",
		"当用户要求执行动作时，优先调用工具，不要只给建议。",
		"当用户要求对比两条规则的关键绕过点时，先调用 compare_rules，再基于返回结果给出简洁结论。",
		"当用户要求编写 bypass 规则时，优先调用 draft_bypass_rule，并给出已经写入的文件名与规则要点。",
		"编写 bypass 规则时必须遵守：只使用规则模板支持的元信息字段；Host 必须使用 {{TARGET_HOST_HEADER}}；User-Agent 建议使用 {{USER_AGENT}}；HTTP 报文必须是真实多行格式，绝对不能输出单行 \\r\\n 拼接字符串。",
		"除非绕过技巧明确依赖，否则不要无故添加 Accept、Origin、Referer；请求应尽量贴近原始请求，只做必要变形。",
		"如果是 multipart/form-data，Content-Type 里的 boundary 必须和 body 一致；如果是 chunked，chunk 长度和数据必须自洽。",
		"如果缺少必要信息，例如规则名不明确，可以先调用 get_workspace_status 获取规则列表，再向用户追问最少的问题。",
		"回答默认使用简体中文，尽量简洁直接。",
	}
	if strings.EqualFold(strings.TrimSpace(d.cfg.LLMProvider), "zhipu") {
		lines = append(lines,
			"",
			"下面是 wafbps 项目为智谱规则开发专门准备的完整规范，请严格遵守：",
			d.ruleAuthoringPrompt(),
		)
	}
	return strings.Join(lines, "\n")
}

func (d *dashboard) agentConversationHistory() []agent.Message {
	history := make([]agent.Message, 0, len(d.agentMessages))
	for _, msg := range d.agentMessages {
		role := strings.TrimSpace(msg.Role)
		text := strings.TrimSpace(msg.Text)
		if role == "" || text == "" {
			continue
		}
		history = append(history, agent.Message{Role: role, Content: text})
	}
	if len(history) > 12 {
		history = append([]agent.Message(nil), history[len(history)-12:]...)
	}
	return history
}

func (d *dashboard) setAgentBusy(busy bool) {
	d.agentBusy = busy
	d.runOnUI(func() {
		if d.agentPromptEntry != nil {
			d.agentPromptEntry.Disable()
			if !busy {
				d.agentPromptEntry.Enable()
			}
		}
	})
}

func agentJSONString(payload any) string {
	data, err := json.Marshal(payload)
	if err != nil {
		return `{"ok":false,"error":"json marshal failed"}`
	}
	return string(data)
}

func (d *dashboard) buildAgentTools() []agent.FunctionTool {
	return []agent.FunctionTool{
		{
			Name:        "get_workspace_status",
			Description: "获取当前工作区运行状态、计数器、规则列表与验证情况。",
			Parameters: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"required":             []string{},
				"additionalProperties": false,
			},
			Handler: d.agentToolGetWorkspaceStatus,
		},
		{
			Name:        "start_pipeline_sampling",
			Description: "启动一键执行采样流水线，可指定采样轮次。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rounds": map[string]any{
						"type":        "integer",
						"description": "一键执行采样轮次，1 到 100。",
						"minimum":     1,
						"maximum":     100,
					},
				},
				"required":             []string{"rounds"},
				"additionalProperties": false,
			},
			Handler: d.agentToolStartPipeline,
		},
		{
			Name:        "extract_waf_fingerprints",
			Description: "从当前已标记聚类中提取并固化 WAF 指纹。",
			Parameters: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"required":             []string{},
				"additionalProperties": false,
			},
			Handler: d.agentToolExtractFingerprints,
		},
		{
			Name:        "run_rule_validation",
			Description: "对指定规则或全部正式规则执行规则验证。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"all_rules": map[string]any{
						"type":        []string{"boolean", "null"},
						"description": "是否对全部正式规则执行验证。",
					},
					"rule_names": map[string]any{
						"type":        []string{"array", "null"},
						"description": "要验证的规则名称列表。",
						"items": map[string]any{
							"type": "string",
						},
					},
				},
				"required":             []string{"all_rules", "rule_names"},
				"additionalProperties": false,
			},
			Handler: d.agentToolRunRuleValidation,
		},
		{
			Name:        "compare_rules",
			Description: "对比两条规则，查看哪条拦截哪条绕过，并给出关键差异摘要。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_a": map[string]any{
						"type":        "string",
						"description": "规则 A 的名称。",
					},
					"rule_b": map[string]any{
						"type":        "string",
						"description": "规则 B 的名称。",
					},
				},
				"required":             []string{"rule_a", "rule_b"},
				"additionalProperties": false,
			},
			Handler: d.agentToolCompareRules,
		},
		{
			Name:        "draft_bypass_rule",
			Description: "根据结构化字段生成 bypass 规则文件，并自动重载规则库。",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "规则名称。",
					},
					"color": map[string]any{
						"type":        []string{"string", "null"},
						"description": "规则颜色，例如 yellow、cyan、purple。",
					},
					"validation_mode": map[string]any{
						"type":        []string{"string", "null"},
						"description": "验证模式，例如 baseline_similarity。",
					},
					"similarity_threshold": map[string]any{
						"type":        []string{"number", "null"},
						"description": "相似度阈值，例如 0.92。",
					},
					"notes": map[string]any{
						"type":        []string{"string", "null"},
						"description": "附加备注或标签，可选。",
					},
					"intent": map[string]any{
						"type":        []string{"string", "null"},
						"description": "规则意图，例如 replace_space。",
					},
					"intent_replace_from": map[string]any{
						"type":        []string{"string", "null"},
						"description": "替换类意图的原始字符，例如空格。",
					},
					"intent_replace_to": map[string]any{
						"type":        []string{"string", "null"},
						"description": "替换类意图的目标编码，例如 %0f。",
					},
					"request": map[string]any{
						"type":        "string",
						"description": "完整 HTTP 请求模板。",
					},
				},
				"required":             []string{"name", "color", "validation_mode", "similarity_threshold", "notes", "intent", "intent_replace_from", "intent_replace_to", "request"},
				"additionalProperties": false,
			},
			Handler: d.agentToolDraftRule,
		},
	}
}

func (d *dashboard) handleAgentPrompt(prompt string) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return
	}
	d.ensureAgentGreeting()
	if d.agentBusy {
		d.appendAgentMessage("assistant", "智能体正在处理中，请稍等当前这轮回答完成。")
		return
	}
	settings := d.agentSettings()
	if !d.activeLLMProviderEnabled() {
		d.appendAgentMessage("user", prompt)
		d.appendAgentMessage("assistant", fmt.Sprintf("当前启用的大模型供应商是 %s，但它还没有开启。请先打开“大模型配置”启用后再试。", d.activeLLMProviderLabel()))
		return
	}
	if strings.TrimSpace(settings.APIKey) == "" {
		d.appendAgentMessage("user", prompt)
		d.appendAgentMessage("assistant", fmt.Sprintf("当前启用的大模型供应商是 %s，但还没有配置 API Key。请先打开“大模型配置”补上对应 Key、Base URL 和模型。", d.activeLLMProviderLabel()))
		return
	}

	history := d.agentConversationHistory()
	d.appendAgentMessage("user", prompt)
	pendingIndex := d.appendAgentMessageIndex("assistant", fmt.Sprintf("正在思考中，当前使用 %s，准备调用大模型并分析是否需要执行本地工具...", d.activeLLMProviderLabel()))
	d.setAgentBusy(true)
	d.setStatus(fmt.Sprintf("智能体 // 正在通过 %s 思考并调度本地工具", d.activeLLMProviderLabel()))

	go func(userPrompt string, previous []agent.Message, thinkingIndex int) {
		defer d.setAgentBusy(false)
		client := agent.New(settings)
		result, err := client.RunTurn(context.Background(), agent.TurnRequest{
			Instructions: d.agentInstructions(),
			Messages:     previous,
			UserInput:    userPrompt,
			Tools:        d.buildAgentTools(),
		})
		if err != nil {
			d.updateAgentMessage(thinkingIndex, "assistant", "智能体调用失败："+err.Error())
			d.setStatus("错误 // 智能体调用失败")
			return
		}
		d.updateAgentMessage(thinkingIndex, "assistant", emptyFallback(result.AssistantText, "我已经完成这轮处理。"))
		d.setStatus("智能体 // 已完成当前对话操作")
	}(prompt, history, pendingIndex)
}

func (d *dashboard) agentToolGetWorkspaceStatus(ctx context.Context, _ json.RawMessage) (string, error) {
	rules := make([]map[string]any, 0, len(d.ruleStatsRows))
	for _, row := range d.ruleStatsRows {
		rules = append(rules, map[string]any{
			"name":      row.Name,
			"tested":    row.Tested,
			"attempts":  row.Attempts,
			"successes": row.Successes,
			"rate":      row.Rate,
		})
	}
	payload := map[string]any{
		"ok":                 true,
		"site_total":         d.siteTotalCount,
		"suspected_waf":      d.suspectedSiteCount(),
		"cluster_total":      d.totalClusterGroupCount(),
		"fingerprint_total":  d.labeledFingerprintCount(),
		"bypass_success":     len(d.sessionBypassSites),
		"rule_validation_on": d.isRuleValidationRunning(),
		"pipeline_on":        d.pipelineRunning,
		"fingerprint_on":     d.fingerprintRunning,
		"rules":              rules,
	}
	return agentJSONString(payload), nil
}

func (d *dashboard) agentToolStartPipeline(ctx context.Context, raw json.RawMessage) (string, error) {
	args := struct {
		Rounds int `json:"rounds"`
	}{}
	_ = json.Unmarshal(raw, &args)
	if args.Rounds <= 0 {
		args.Rounds = 1
	}
	if args.Rounds > 100 {
		args.Rounds = 100
	}

	started := false
	d.runOnUISync(func() {
		if d.pipelineRunning || d.searchRunning || d.detectRunning || d.clusterRunning {
			return
		}
		if d.pipelineCountEntry != nil {
			d.pipelineCountEntry.SetText(strconv.Itoa(args.Rounds))
		}
		d.runPipeline()
		started = d.pipelineRunning
	})
	if !started {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "当前已有搜索、识别、聚类或一键执行任务在运行，无法启动新的采样流水线。",
		}), nil
	}
	return agentJSONString(map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("已启动一键执行采样，共 %d 轮。", args.Rounds),
		"rounds":  args.Rounds,
	}), nil
}

func (d *dashboard) agentToolExtractFingerprints(ctx context.Context, _ json.RawMessage) (string, error) {
	started := false
	d.runOnUISync(func() {
		if d.fingerprintRunning || d.searchRunning || d.detectRunning || d.clusterRunning || d.pipelineRunning {
			return
		}
		d.extractClusterFingerprints()
		started = d.fingerprintRunning
	})
	if !started {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "当前有任务进行中，或没有可提取的已标记聚类。",
		}), nil
	}
	return agentJSONString(map[string]any{
		"ok":      true,
		"message": "已启动自动提取 WAF 指纹。",
	}), nil
}

func (d *dashboard) agentFindValidationPluginsByNames(names []string) []model.Plugin {
	if len(names) == 0 {
		return nil
	}
	visible := filterVisibleValidationPlugins(d.plugins)
	out := make([]model.Plugin, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		target := strings.TrimSpace(name)
		if target == "" {
			continue
		}
		for _, pluginItem := range visible {
			current := strings.TrimSpace(pluginItem.Name)
			if current == "" || seen[current] {
				continue
			}
			if strings.EqualFold(current, target) || strings.Contains(strings.ToLower(current), strings.ToLower(target)) {
				seen[current] = true
				out = append(out, pluginItem)
				break
			}
		}
	}
	return out
}

func (d *dashboard) agentToolRunRuleValidation(ctx context.Context, raw json.RawMessage) (string, error) {
	args := struct {
		AllRules  bool     `json:"all_rules"`
		RuleNames []string `json:"rule_names"`
	}{}
	_ = json.Unmarshal(raw, &args)

	var plugins []model.Plugin
	if args.AllRules || len(args.RuleNames) == 0 {
		plugins = filterVisibleValidationPlugins(d.plugins)
	} else {
		plugins = d.agentFindValidationPluginsByNames(args.RuleNames)
	}
	if len(plugins) == 0 {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "没有匹配到可验证的正式规则。",
		}), nil
	}

	started := false
	names := make([]string, 0, len(plugins))
	for _, item := range plugins {
		names = append(names, item.Name)
	}
	d.runOnUISync(func() {
		if d.isRuleValidationRunning() {
			return
		}
		d.runRuleValidation(plugins)
		started = d.isRuleValidationRunning()
	})
	if !started {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "规则验证已经在运行中，或当前条件不允许启动新的验证。",
			"rules":   names,
		}), nil
	}
	return agentJSONString(map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("已启动规则验证，共 %d 条规则。", len(names)),
		"rules":   names,
	}), nil
}

func (d *dashboard) agentToolCompareRules(ctx context.Context, raw json.RawMessage) (string, error) {
	args := struct {
		RuleA string `json:"rule_a"`
		RuleB string `json:"rule_b"`
	}{}
	_ = json.Unmarshal(raw, &args)
	ruleA := strings.TrimSpace(args.RuleA)
	ruleB := strings.TrimSpace(args.RuleB)
	if ruleA == "" || ruleB == "" {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "规则对比需要明确提供 rule_a 和 rule_b。",
		}), nil
	}

	summary := d.agentCompareSummary(ruleA, ruleB)
	d.runOnUISync(func() {
		d.showRuleCompareViewer(ruleA, ruleB)
	})
	return agentJSONString(map[string]any{
		"ok":      true,
		"rule_a":  ruleA,
		"rule_b":  ruleB,
		"summary": summary,
	}), nil
}

func (d *dashboard) agentToolDraftRule(ctx context.Context, raw json.RawMessage) (string, error) {
	args := struct {
		Name                string  `json:"name"`
		Color               string  `json:"color"`
		ValidationMode      string  `json:"validation_mode"`
		SimilarityThreshold float64 `json:"similarity_threshold"`
		Notes               string  `json:"notes"`
		Intent              string  `json:"intent"`
		IntentReplaceFrom   string  `json:"intent_replace_from"`
		IntentReplaceTo     string  `json:"intent_replace_to"`
		Request             string  `json:"request"`
	}{}
	_ = json.Unmarshal(raw, &args)
	if strings.TrimSpace(args.Name) == "" || strings.TrimSpace(args.Request) == "" {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": "编写规则至少需要提供 name 和 request。",
		}), nil
	}

	threshold := "0.92"
	if args.SimilarityThreshold > 0 {
		threshold = strconv.FormatFloat(args.SimilarityThreshold, 'f', 2, 64)
	}
	builder := strings.Builder{}
	builder.WriteString("名称：" + strings.TrimSpace(args.Name) + "\n")
	if strings.TrimSpace(args.Color) != "" {
		builder.WriteString("颜色：" + strings.TrimSpace(args.Color) + "\n")
	}
	if strings.TrimSpace(args.ValidationMode) != "" {
		builder.WriteString("验证模式：" + strings.TrimSpace(args.ValidationMode) + "\n")
	}
	builder.WriteString("阈值：" + threshold + "\n")
	if strings.TrimSpace(args.Notes) != "" {
		builder.WriteString("标签：" + strings.TrimSpace(args.Notes) + "\n")
	}
	if strings.TrimSpace(args.Intent) != "" {
		builder.WriteString("意图：" + strings.TrimSpace(args.Intent) + "\n")
	}
	if strings.TrimSpace(args.IntentReplaceFrom) != "" {
		builder.WriteString("意图替换源：" + strings.TrimSpace(args.IntentReplaceFrom) + "\n")
	}
	if strings.TrimSpace(args.IntentReplaceTo) != "" {
		builder.WriteString("意图替换目标：" + strings.TrimSpace(args.IntentReplaceTo) + "\n")
	}
	builder.WriteString("请求：\n")
	builder.WriteString(strings.TrimSpace(args.Request))

	path, err := d.writeAgentRule(builder.String())
	if err != nil {
		return agentJSONString(map[string]any{
			"ok":      false,
			"message": err.Error(),
		}), nil
	}
	d.runOnUISync(func() {
		d.reloadPlugins()
	})
	return agentJSONString(map[string]any{
		"ok":      true,
		"message": "规则已写入并重载完成。",
		"path":    path,
	}), nil
}

func (d *dashboard) agentHelpText() string {
	return strings.Join([]string{
		"我当前支持这些对话动作：",
		"1. 一键执行采样",
		"2. 提取指纹",
		"3. 规则验证：可直接说“用全部规则做规则验证”或在一句话里带上规则名",
		"4. 规则对比：例如“对比 规则A 和 规则B，评价关键绕过点”",
		"5. 编写规则：建议按这个模板发给我",
		"名称：规则名",
		"颜色：yellow",
		"验证模式：baseline_similarity",
		"阈值：0.92",
		"意图：replace_space",
		"意图替换源：空格",
		"意图替换目标：%0f",
		"请求：",
		"POST / HTTP/1.1",
		"Host: {{TARGET_HOST_HEADER}}",
		"",
		"body=example",
	}, "\n")
}

func (d *dashboard) handleAgentRuleValidation(prompt string) {
	if d.isRuleValidationRunning() {
		d.appendAgentMessage("assistant", "规则验证已经在运行中了。你可以先等待完成，或使用顶部停止按钮终止当前验证。")
		return
	}
	plugins := []model.Plugin{}
	if strings.Contains(prompt, "全部规则") || strings.Contains(prompt, "所有规则") || strings.Contains(prompt, "全部正式规则") {
		plugins = filterVisibleValidationPlugins(d.plugins)
	} else {
		plugins = d.agentMentionedPlugins(prompt, true)
	}
	if len(plugins) == 0 {
		d.appendAgentMessage("assistant", "我还没识别到要验证的规则。你可以直接说“用全部规则做规则验证”，或者在一句话里带上 1 到多条正式规则名。")
		return
	}
	names := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		names = append(names, plugin.Name)
	}
	d.runRuleValidation(plugins)
	d.appendAgentMessage("assistant", fmt.Sprintf("已开始规则验证，共 %d 条规则：%s", len(plugins), strings.Join(names, "、")))
}

func (d *dashboard) handleAgentRuleCompare(prompt string) {
	plugins := d.agentMentionedPlugins(prompt, true)
	if len(plugins) < 2 {
		d.appendAgentMessage("assistant", "规则对比需要在一句话里明确提到两条已检测过的正式规则。你可以直接说：对比 规则A 和 规则B。")
		return
	}
	ruleA := plugins[0].Name
	ruleB := plugins[1].Name
	d.showRuleCompareViewer(ruleA, ruleB)
	d.appendAgentMessage("assistant", d.agentCompareSummary(ruleA, ruleB))
}

func (d *dashboard) handleAgentRuleDraft(prompt string) {
	path, err := d.writeAgentRule(prompt)
	if err != nil {
		d.appendAgentMessage("assistant", err.Error())
		return
	}
	d.reloadPlugins()
	d.appendAgentMessage("assistant", fmt.Sprintf("规则已写入：%s\n我已经同步重载了规则库。", path))
}

func (d *dashboard) agentMentionedPlugins(text string, validationOnly bool) []model.Plugin {
	options := append([]model.Plugin(nil), d.plugins...)
	if validationOnly {
		options = filterVisibleValidationPlugins(options)
	}
	sort.Slice(options, func(i, j int) bool {
		left := strings.TrimSpace(options[i].Name)
		right := strings.TrimSpace(options[j].Name)
		if len([]rune(left)) == len([]rune(right)) {
			return strings.ToLower(left) < strings.ToLower(right)
		}
		return len([]rune(left)) > len([]rune(right))
	})

	lower := strings.ToLower(text)
	type hit struct {
		Index  int
		Plugin model.Plugin
	}
	hits := make([]hit, 0)
	seen := map[string]bool{}
	for _, option := range options {
		name := strings.TrimSpace(option.Name)
		if name == "" || seen[name] {
			continue
		}
		idx := strings.Index(lower, strings.ToLower(name))
		if idx < 0 {
			continue
		}
		seen[name] = true
		hits = append(hits, hit{Index: idx, Plugin: option})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Index == hits[j].Index {
			return hits[i].Plugin.Name < hits[j].Plugin.Name
		}
		return hits[i].Index < hits[j].Index
	})
	out := make([]model.Plugin, 0, len(hits))
	for _, hit := range hits {
		out = append(out, hit.Plugin)
	}
	return out
}

func (d *dashboard) agentCompareSummary(ruleA string, ruleB string) string {
	aBlockedBBypass := d.buildRuleCompareDiffGroups(ruleA, ruleB, true)
	aBypassBBlocked := d.buildRuleCompareDiffGroups(ruleA, ruleB, false)
	lines := []string{
		fmt.Sprintf("已打开规则对比。A=%s，B=%s。", ruleA, ruleB),
		fmt.Sprintf("A拦截B绕过: %d 个URL / %d 个分组", totalRuleCompareDiffRows(aBlockedBBypass), len(aBlockedBBypass)),
		fmt.Sprintf("A绕过B拦截: %d 个URL / %d 个分组", totalRuleCompareDiffRows(aBypassBBlocked), len(aBypassBBlocked)),
	}
	if summary := summarizeCompareGroups(aBlockedBBypass); summary != "" {
		lines = append(lines, "A拦截B绕过主要集中: "+summary)
	}
	if summary := summarizeCompareGroups(aBypassBBlocked); summary != "" {
		lines = append(lines, "A绕过B拦截主要集中: "+summary)
	}
	if points := d.compareRuleRequestKeyPoints(ruleA, ruleB); len(points) > 0 {
		lines = append(lines, "关键请求差异:")
		lines = append(lines, points...)
	}
	return strings.Join(lines, "\n")
}

func summarizeCompareGroups(groups []ruleCompareDiffGroup) string {
	if len(groups) == 0 {
		return ""
	}
	type wafCount struct {
		Name  string
		Count int
	}
	counts := map[string]int{}
	for _, group := range groups {
		counts[group.WAF] += len(group.Rows)
	}
	rows := make([]wafCount, 0, len(counts))
	for name, count := range counts {
		rows = append(rows, wafCount{Name: name, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].Count > rows[j].Count
	})
	limit := 3
	if len(rows) < limit {
		limit = len(rows)
	}
	parts := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		parts = append(parts, fmt.Sprintf("%s(%d)", rows[i].Name, rows[i].Count))
	}
	return strings.Join(parts, "、")
}

func (d *dashboard) compareRuleRequestKeyPoints(ruleA string, ruleB string) []string {
	find := func(name string) (model.Plugin, bool) {
		for _, plugin := range d.plugins {
			if strings.EqualFold(strings.TrimSpace(plugin.Name), strings.TrimSpace(name)) {
				return plugin, true
			}
		}
		return model.Plugin{}, false
	}
	a, okA := find(ruleA)
	b, okB := find(ruleB)
	if !okA || !okB {
		return nil
	}

	lines := []string{}
	if !strings.EqualFold(strings.TrimSpace(a.Method), strings.TrimSpace(b.Method)) {
		lines = append(lines, fmt.Sprintf("- A 使用 %s，B 使用 %s", emptyFallback(a.Method, "-"), emptyFallback(b.Method, "-")))
	}
	if !strings.EqualFold(strings.TrimSpace(a.RequestURI), strings.TrimSpace(b.RequestURI)) {
		lines = append(lines, fmt.Sprintf("- A 路径 %s，B 路径 %s", emptyFallback(a.RequestURI, "-"), emptyFallback(b.RequestURI, "-")))
	}
	aCT := strings.TrimSpace(a.Headers["Content-Type"])
	bCT := strings.TrimSpace(b.Headers["Content-Type"])
	if !strings.EqualFold(aCT, bCT) {
		lines = append(lines, fmt.Sprintf("- Content-Type 不同：A=%s | B=%s", emptyFallback(aCT, "-"), emptyFallback(bCT, "-")))
	}
	aRaw := strings.ToLower(a.Raw + "\n" + a.Body)
	bRaw := strings.ToLower(b.Raw + "\n" + b.Body)
	if strings.Contains(aRaw, "multipart/form-data") != strings.Contains(bRaw, "multipart/form-data") {
		lines = append(lines, "- 只有其中一条规则使用 multipart/form-data 封装")
	}
	if strings.Contains(aRaw, "filename=") != strings.Contains(bRaw, "filename=") {
		lines = append(lines, "- 只有其中一条规则在 multipart 字段里加入了 filename")
	}
	aHasNull := strings.Contains(a.Raw, "\x00") || strings.Contains(a.Raw, `\x00`) || strings.Contains(a.Body, "\x00") || strings.Contains(a.Body, `\x00`)
	bHasNull := strings.Contains(b.Raw, "\x00") || strings.Contains(b.Raw, `\x00`) || strings.Contains(b.Body, "\x00") || strings.Contains(b.Body, `\x00`)
	if aHasNull != bHasNull {
		lines = append(lines, "- 只有其中一条规则携带了 0x00 截断字符")
	}
	if len(lines) == 0 {
		lines = append(lines, "- 两条规则的请求骨架接近，差异可能更集中在 body 细节、boundary 或 header 值上")
	}
	return lines
}

func (d *dashboard) writeAgentRule(prompt string) (string, error) {
	name := extractAgentField(prompt, []string{"名称", "规则名称"})
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("我还没拿到规则名称。请用“名称：xxx”告诉我。")
	}
	request := extractAgentRequestBlock(prompt)
	if strings.TrimSpace(request) == "" {
		return "", fmt.Errorf("我还没拿到规则请求包。请按模板提供“请求：”和完整 HTTP 报文。")
	}

	colorName := emptyFallback(extractAgentField(prompt, []string{"颜色", "展示颜色"}), "yellow")
	validate := emptyFallback(extractAgentField(prompt, []string{"验证模式", "validate"}), "baseline_similarity")
	threshold := emptyFallback(extractAgentField(prompt, []string{"阈值", "threshold"}), "0.92")
	tags := extractAgentField(prompt, []string{"标签", "tags"})
	intentName := extractAgentField(prompt, []string{"意图", "intent"})
	intentReplaceFrom := extractAgentField(prompt, []string{"意图替换源", "替换源", "intent.replace_from"})
	intentReplaceTo := extractAgentField(prompt, []string{"意图替换目标", "替换目标", "intent.replace_to"})

	lines := []string{
		"# @name: " + name,
		"# @color: " + colorName,
		"# @validate: " + validate,
		"# @threshold: " + threshold,
	}
	if strings.TrimSpace(tags) != "" {
		lines = append(lines, "# @tags: "+tags)
	}
	if strings.TrimSpace(intentName) != "" {
		lines = append(lines, "# @intent: "+intentName)
	}
	if strings.TrimSpace(intentReplaceFrom) != "" {
		lines = append(lines, "# @intent.replace_from: "+quoteIntentMetaValue(normalizeIntentMetaValue(intentReplaceFrom)))
	}
	if strings.TrimSpace(intentReplaceTo) != "" {
		lines = append(lines, "# @intent.replace_to: "+quoteIntentMetaValue(normalizeIntentMetaValue(intentReplaceTo)))
	}
	lines = append(lines, request)
	raw := strings.Join(lines, "\n")
	parsed, err := plugin.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("规则草稿未通过解析：%v", err)
	}
	if issues := plugin.Lint(raw, parsed); plugin.HasBlockingIssues(issues) {
		return "", fmt.Errorf("规则静态检查未通过：\n%s", strings.Join(plugin.RenderLintWarnings(issues), "\n"))
	}

	dir := strings.TrimSpace(d.cfg.Plugin.Dir)
	if dir == "" {
		dir = "plugins"
	}
	fileName := sanitizeRuleFileName(name) + ".http"
	path := filepath.Join(dir, fileName)
	for _, existing := range d.plugins {
		if strings.EqualFold(strings.TrimSpace(existing.Name), strings.TrimSpace(name)) && strings.TrimSpace(existing.Path) != "" {
			path = existing.Path
			break
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func normalizeIntentMetaValue(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "空格", "space", "<space>":
		return " "
	default:
		return value
	}
}

func quoteIntentMetaValue(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t'\"") {
		return strconv.Quote(value)
	}
	return value
}

func extractAgentField(prompt string, keys []string) string {
	lines := strings.Split(strings.ReplaceAll(prompt, "\r\n", "\n"), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, key := range keys {
			for _, prefix := range []string{key + ":", key + "："} {
				if strings.HasPrefix(trimmed, prefix) {
					return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
				}
			}
		}
	}
	return ""
}

func extractAgentRequestBlock(prompt string) string {
	normalized := strings.ReplaceAll(prompt, "\r\n", "\n")
	for _, marker := range []string{"请求：", "请求:", "HTTP请求：", "HTTP请求:", "HTTP 请求：", "HTTP 请求:"} {
		if idx := strings.Index(normalized, marker); idx >= 0 {
			return strings.TrimSpace(normalized[idx+len(marker):])
		}
	}
	lines := strings.Split(normalized, "\n")
	for i, line := range lines {
		upper := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upper, "GET ") || strings.HasPrefix(upper, "POST ") || strings.HasPrefix(upper, "PUT ") || strings.HasPrefix(upper, "PATCH ") || strings.HasPrefix(upper, "DELETE ") || strings.HasPrefix(upper, "HEAD ") || strings.HasPrefix(upper, "OPTIONS ") {
			return strings.TrimSpace(strings.Join(lines[i:], "\n"))
		}
	}
	return ""
}

func sanitizeRuleFileName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	replacer := strings.NewReplacer(
		" ", "-",
		"/", "-",
		"\\", "-",
		":", "-",
		"\"", "",
		"'", "",
		"|", "-",
		"?", "",
		"*", "",
		"<", "",
		">", "",
	)
	name = replacer.Replace(name)
	name = strings.Trim(name, "-.")
	if name == "" {
		name = "agent-rule"
	}
	return name
}

func (d *dashboard) selectClusterByKey(clusterKey string) {
	if strings.TrimSpace(clusterKey) == "" {
		return
	}
	clusters := d.clusterViews()
	for i, cluster := range clusters {
		if cluster.Key != clusterKey {
			continue
		}
		d.selectedCluster = i
		d.updateClusterDetails()
		d.refreshCockpit()
		if d.detailTabs != nil {
			d.detailTabs.SelectIndex(1)
		}
		return
	}
}

func (d *dashboard) setBypassStatsScope(plugins []model.Plugin) {
	scope := map[string]bool{}
	names := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		name := strings.TrimSpace(plugin.Name)
		if name == "" || scope[name] {
			continue
		}
		scope[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	d.bypassStatsPluginSet = scope
	switch len(names) {
	case 0:
		d.bypassStatsPluginText = "范围 // 未选择规则"
	case 1:
		d.bypassStatsPluginText = "范围 // " + names[0]
	default:
		d.bypassStatsPluginText = fmt.Sprintf("范围 // %d 条规则", len(names))
	}
}

func (d *dashboard) resetBypassStatsSession(plugins []model.Plugin) {
	d.setBypassStatsScope(plugins)
	d.bypassStatsResults = nil
	d.updateBypassStatsRows(nil, d.bypassStatsPluginText)
}

func (d *dashboard) resetRuleValidationSession(plugins []model.Plugin) {
	d.resetBypassStatsSession(plugins)
	removeSet := map[string]bool{}
	for _, plugin := range plugins {
		name := strings.TrimSpace(plugin.Name)
		if name == "" {
			continue
		}
		removeSet[name] = true
	}
	if len(removeSet) > 0 {
		filtered := d.results[:0]
		for _, result := range d.results {
			if removeSet[strings.TrimSpace(result.Plugin.Name)] {
				continue
			}
			filtered = append(filtered, result)
		}
		d.results = filtered
	}
	d.sessionBypassSites = map[string]bool{}
	d.sessionBypassResults = map[string]model.TestResult{}
	d.rememberSessionBypass(d.results...)
	d.selectedResult = -1
	d.runOnUI(func() {
		if d.resultList != nil {
			d.resultList.UnselectAll()
			d.resultList.Refresh()
		}
		d.updateResultDetails()
	})
	d.refreshDashboard()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ResultCount = len(d.results)
	})
	d.persistDatabase()
}

func (d *dashboard) screenRuleValidationTargets(ctx context.Context, plugin model.Plugin, targets []model.Site, detections []model.DetectionResult) ([]model.Site, []model.DetectionResult, int) {
	if len(targets) == 0 || len(detections) == 0 {
		return targets, detections, 0
	}

	service := tester.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
	defer service.CloseIdleConnections()
	workers := d.currentDetectConcurrency()
	if workers <= 0 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers <= 0 {
		workers = 1
	}

	type job struct {
		index     int
		site      model.Site
		detection model.DetectionResult
	}
	type output struct {
		index     int
		site      model.Site
		detection model.DetectionResult
		result    model.TestResult
	}

	jobs := make(chan job)
	outputs := make(chan output, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				detectionCopy := item.detection
				result := service.RunWithDetectionContext(ctx, item.site, plugin, &detectionCopy)
				select {
				case outputs <- output{index: item.index, site: item.site, detection: detectionCopy, result: result}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		for i := range targets {
			select {
			case jobs <- job{index: i, site: targets[i], detection: detections[i]}:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(outputs)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(outputs)
	}()

	keptTargets := make([]model.Site, 0, len(targets))
	keptDetections := make([]model.DetectionResult, 0, len(detections))
	removed := map[string]string{}
	pendingRemoved := map[string]string{}
	checked := 0
	startedAt := time.Now()
	lastFlushAt := time.Now()
	lastProgressUpdate := time.Now()
	lastTransportCleanup := time.Now()
	flushRemoved := func(force bool) {
		if len(pendingRemoved) == 0 {
			return
		}
		if !force {
			return
		}
		if !force && len(pendingRemoved) < 24 && time.Since(lastFlushAt) < 250*time.Millisecond {
			return
		}
		batch := make(map[string]string, len(pendingRemoved))
		for key, reason := range pendingRemoved {
			batch[key] = reason
		}
		pendingRemoved = map[string]string{}
		lastFlushAt = time.Now()
		runOnUI := d.runOnUI
		if force {
			runOnUI = d.runOnUISync
		}
		runOnUI(func() {
			d.pruneRuleValidationSites(batch)
		})
	}
	refreshProgress := func(force bool) {
		if !force && time.Since(lastProgressUpdate) < 200*time.Millisecond {
			return
		}
		lastProgressUpdate = time.Now()
		d.setConsoleStatus(fmt.Sprintf("筛查规则进行中... %d/%d | 已移除 %d | %s", checked, len(targets), len(removed), formatScanRate(checked, time.Since(startedAt))))
		d.setConsoleProgress(checked, len(targets))
	}

	d.appendConsoleLog(fmt.Sprintf("[init] 筛查规则预检 | 规则=%s | 目标=%d | 并发=%d", emptyFallback(plugin.Name, "get-id-baseline-bypass"), len(targets), workers))

	for item := range outputs {
		if ctx.Err() != nil {
			break
		}
		checked++
		if strings.Contains(item.result.Verdict, "可能绕过") {
			keptTargets = append(keptTargets, item.site)
			keptDetections = append(keptDetections, item.detection)
		} else {
			siteKey := d.siteKey(item.site)
			if siteKey == "" {
				siteKey = d.siteKey(item.detection.Site)
			}
			if siteKey != "" {
				removed[siteKey] = "筛查规则未通过"
				pendingRemoved[siteKey] = "筛查规则未通过"
				flushRemoved(false)
			}
		}
		if time.Since(lastTransportCleanup) >= 15*time.Second {
			service.CloseIdleConnections()
			lastTransportCleanup = time.Now()
		}
		refreshProgress(false)
	}
	flushRemoved(true)
	refreshProgress(true)
	service.CloseIdleConnections()
	if len(removed) > 0 {
		d.rebuildClusterState()
		d.persistDatabase()
	}

	return keptTargets, keptDetections, len(removed)
}

func validationPreflightMode(plugins []model.Plugin) string {
	for _, plugin := range plugins {
		if strings.EqualFold(strings.TrimSpace(plugin.PreflightMode), "skip") {
			return "skip"
		}
	}
	return "builtin"
}

func validationPreflightPrune(plugins []model.Plugin) bool {
	for _, plugin := range plugins {
		if plugin.PreflightPrune != nil && !*plugin.PreflightPrune {
			return false
		}
	}
	return true
}

func (d *dashboard) buildBypassStatsRows(filter map[string]bool) []bypassClusterStat {
	sourceResults := d.bypassStatsResults
	if len(sourceResults) == 0 {
		return nil
	}
	clusterMap := map[string]bypassClusterStat{}
	for _, cluster := range d.clusterViews() {
		if cluster.Count <= 5 {
			continue
		}
		clusterMap[cluster.Key] = bypassClusterStat{
			Key:        cluster.Key,
			Title:      clusterDefaultTitle(cluster),
			GroupCount: cluster.Count,
		}
	}

	for _, result := range sourceResults {
		if len(filter) > 0 && !filter[strings.TrimSpace(result.Plugin.Name)] {
			continue
		}
		detection, ok := d.detectionForSite(result.Site)
		if !ok || !detection.HasWAF {
			continue
		}
		stat, ok := clusterMap[detection.ClusterKey]
		if !ok {
			continue
		}
		stat.Attempts++
		if strings.Contains(result.Verdict, "可能绕过") {
			stat.Successes++
		}
		if stat.Attempts > 0 {
			stat.Rate = float64(stat.Successes) / float64(stat.Attempts)
		}
		clusterMap[detection.ClusterKey] = stat
	}

	rows := make([]bypassClusterStat, 0, len(clusterMap))
	for _, stat := range clusterMap {
		if stat.Attempts == 0 {
			continue
		}
		rows = append(rows, stat)
	}
	sortBypassStatsRows(rows)
	return rows
}

func sortBypassStatsRows(rows []bypassClusterStat) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Rate == rows[j].Rate {
			if rows[i].Successes == rows[j].Successes {
				if rows[i].Attempts == rows[j].Attempts {
					return rows[i].GroupCount > rows[j].GroupCount
				}
				return rows[i].Attempts > rows[j].Attempts
			}
			return rows[i].Successes > rows[j].Successes
		}
		return rows[i].Rate > rows[j].Rate
	})
}

func (d *dashboard) updateBypassStatsRows(rows []bypassClusterStat, _ string) {
	running := d.isRuleValidationRunning()
	d.runOnUI(func() {
		previousLen := len(d.bypassStatsRows)
		d.bypassStatsRows = append([]bypassClusterStat(nil), rows...)
		if d.bypassStatsList != nil {
			d.bypassStatsList.Refresh()
			if previousLen != len(d.bypassStatsRows) {
				for i := range d.bypassStatsRows {
					d.bypassStatsList.SetItemHeight(i, 34)
				}
			}
		}
		if running {
			return
		}
		if d.workflowBody != nil && d.currentStep <= 4 {
			d.refreshCurrentStepView()
		}
		d.updateClusterDetails()
	})
}

func (d *dashboard) refreshBypassStatsFromResults() {
	if d.isRuleValidationRunning() {
		return
	}
	rows := d.buildBypassStatsRows(d.bypassStatsPluginSet)
	d.updateBypassStatsRows(rows, d.bypassStatsPluginText)
}

func (d *dashboard) isRuleValidationRunning() bool {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	return d.ruleValidationRunning
}

func isScreeningPlugin(plugin model.Plugin) bool {
	return strings.EqualFold(filepath.Base(strings.TrimSpace(plugin.Path)), "get-id-baseline-bypass.http")
}

func isTemplatePlugin(plugin model.Plugin) bool {
	base := filepath.Base(strings.TrimSpace(plugin.Path))
	if strings.EqualFold(base, "template.http") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(plugin.Name), "template")
}

func (d *dashboard) screeningPlugin() (model.Plugin, bool) {
	for _, plugin := range d.plugins {
		if isScreeningPlugin(plugin) {
			return plugin, true
		}
	}
	return model.Plugin{}, false
}

func filterVisibleValidationPlugins(plugins []model.Plugin) []model.Plugin {
	filtered := make([]model.Plugin, 0, len(plugins))
	for _, plugin := range plugins {
		if isScreeningPlugin(plugin) || isTemplatePlugin(plugin) {
			continue
		}
		filtered = append(filtered, plugin)
	}
	return filtered
}

func (d *dashboard) buildRuleStatsRows() []ruleStatsRow {
	if len(d.plugins) == 0 {
		return nil
	}
	counts := map[string]*ruleStatsRow{}
	for _, plugin := range d.plugins {
		if isScreeningPlugin(plugin) || isTemplatePlugin(plugin) {
			continue
		}
		name := strings.TrimSpace(plugin.Name)
		if name == "" {
			continue
		}
		counts[name] = &ruleStatsRow{
			Name:  name,
			Color: pluginAccent(plugin),
		}
	}
	for _, result := range d.results {
		name := strings.TrimSpace(result.Plugin.Name)
		row, ok := counts[name]
		if !ok {
			continue
		}
		row.Tested = true
		row.Attempts++
		if strings.Contains(result.Verdict, "可能绕过") {
			row.Successes++
		}
	}
	rows := make([]ruleStatsRow, 0, len(counts))
	for _, row := range counts {
		if row.Attempts > 0 {
			row.Rate = float64(row.Successes) / float64(row.Attempts)
		}
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tested != rows[j].Tested {
			return rows[i].Tested && !rows[j].Tested
		}
		if rows[i].Rate != rows[j].Rate {
			return rows[i].Rate > rows[j].Rate
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

func (d *dashboard) buildRuleCompareGroups(firstRule string, secondRule string) []ruleCompareGroup {
	firstRule = strings.TrimSpace(firstRule)
	secondRule = strings.TrimSpace(secondRule)
	if firstRule == "" || secondRule == "" || firstRule == secondRule {
		return nil
	}

	firstBySite := map[string]model.TestResult{}
	secondBySite := map[string]model.TestResult{}
	for _, result := range d.results {
		ruleName := strings.TrimSpace(result.Plugin.Name)
		if ruleName != firstRule && ruleName != secondRule {
			continue
		}
		siteKey := d.siteKey(result.Site)
		if siteKey == "" {
			siteKey = strings.TrimSpace(emptyFallback(result.Site.URL, emptyFallback(result.Site.OriginalURL, result.Site.Host)))
		}
		if siteKey == "" {
			continue
		}
		target := firstBySite
		if ruleName == secondRule {
			target = secondBySite
		}
		if existing, ok := target[siteKey]; ok && !result.RunAt.After(existing.RunAt) {
			continue
		}
		target[siteKey] = result
	}

	grouped := map[string]*ruleCompareGroup{}
	for siteKey, first := range firstBySite {
		second, ok := secondBySite[siteKey]
		if !ok {
			continue
		}
		if strings.Contains(first.Verdict, "可能绕过") || !strings.Contains(second.Verdict, "可能绕过") {
			continue
		}
		detection, ok := d.detectionForSite(second.Site)
		if !ok || !detection.HasWAF {
			continue
		}

		clusterKey := strings.TrimSpace(detection.ClusterKey)
		clusterTitle := ""
		if cluster, ok := d.clusterViewByKey(clusterKey); ok {
			clusterTitle = clusterDefaultTitle(cluster)
		}
		if strings.TrimSpace(clusterTitle) == "" || clusterTitle == "待标注聚类" {
			clusterTitle = strings.TrimSpace(d.clusterLabelForDetection(detection))
		}
		wafName := strings.TrimSpace(d.effectiveSiteWAF(second.Site))
		if wafName == "" {
			wafName = strings.TrimSpace(d.effectiveSiteWAF(first.Site))
		}
		if wafName == "" {
			wafName = "未知WAF"
		}
		if strings.TrimSpace(clusterTitle) == "" {
			clusterTitle = wafName
		}

		groupKey := clusterKey
		if groupKey == "" {
			groupKey = "waf:" + wafName
		}
		group, ok := grouped[groupKey]
		if !ok {
			group = &ruleCompareGroup{
				Key:   groupKey,
				Title: clusterTitle,
				WAF:   wafName,
			}
			grouped[groupKey] = group
		}
		group.Rows = append(group.Rows, ruleCompareSiteRow{
			SiteKey:      siteKey,
			ClusterKey:   clusterKey,
			ClusterTitle: clusterTitle,
			WAF:          wafName,
			Title:        emptyFallback(second.Site.Host, emptyFallback(second.Site.Domain, emptyFallback(second.Site.OriginalURL, second.Site.URL))),
			URL:          d.clusterSiteURL(second.Site),
			First:        first,
			Second:       second,
		})
	}

	groups := make([]ruleCompareGroup, 0, len(grouped))
	for _, group := range grouped {
		sort.Slice(group.Rows, func(i, j int) bool {
			if group.Rows[i].Second.BaselineSim != group.Rows[j].Second.BaselineSim {
				return group.Rows[i].Second.BaselineSim > group.Rows[j].Second.BaselineSim
			}
			return group.Rows[i].Title < group.Rows[j].Title
		})
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].Rows) == len(groups[j].Rows) {
			return groups[i].Title < groups[j].Title
		}
		return len(groups[i].Rows) > len(groups[j].Rows)
	})
	return groups
}

func formatRuleCompareResult(result model.TestResult) []string {
	lines := []string{
		"判定: " + emptyFallback(result.Verdict, "-"),
		"命中规则: " + emptyFallback(result.MatchedRule, "-"),
		fmt.Sprintf("状态码: %d", result.StatusCode),
		fmt.Sprintf("相似度: 基线 %.2f | 拦截 %.2f | 差异 %.0f%%", result.BaselineSim, result.BlockedSim, result.DiffRatio*100),
	}
	if strings.TrimSpace(result.Error) != "" {
		lines = append(lines, "错误: "+result.Error)
	}
	lines = append(lines,
		"",
		"HTTP 请求:",
		emptyFallback(visiblePacketText(result.SentRequest), "暂无请求包"),
		"",
		"HTTP 响应:",
		emptyFallback(sourcePreviewText(testResultRawResponse(result)), "暂无响应包"),
	)
	return lines
}

func (d *dashboard) buildRuleCompareDiffGroups(ruleA string, ruleB string, aBlockedBBypass bool) []ruleCompareDiffGroup {
	base := []ruleCompareGroup{}
	swap := false
	if aBlockedBBypass {
		base = d.buildRuleCompareGroups(ruleA, ruleB)
	} else {
		base = d.buildRuleCompareGroups(ruleB, ruleA)
		swap = true
	}
	out := make([]ruleCompareDiffGroup, 0, len(base))
	for _, group := range base {
		diffGroup := ruleCompareDiffGroup{
			Key:   group.Key,
			Title: group.Title,
			WAF:   group.WAF,
			Rows:  make([]ruleCompareDiffRow, 0, len(group.Rows)),
		}
		for _, row := range group.Rows {
			aResult := row.First
			bResult := row.Second
			if swap {
				aResult = row.Second
				bResult = row.First
			}
			diffGroup.Rows = append(diffGroup.Rows, ruleCompareDiffRow{
				SiteKey:      row.SiteKey,
				ClusterKey:   row.ClusterKey,
				ClusterTitle: row.ClusterTitle,
				WAF:          row.WAF,
				Title:        row.Title,
				URL:          row.URL,
				AResult:      aResult,
				BResult:      bResult,
			})
		}
		out = append(out, diffGroup)
	}
	return out
}

func totalRuleCompareDiffRows(groups []ruleCompareDiffGroup) int {
	total := 0
	for _, group := range groups {
		total += len(group.Rows)
	}
	return total
}

func (d *dashboard) refreshRuleStatsPanel() {
	rows := d.buildRuleStatsRows()
	d.runOnUI(func() {
		d.ruleStatsRows = rows
		testedRules := 0
		totalAttempts := 0
		totalSuccesses := 0
		for _, row := range rows {
			if !row.Tested {
				continue
			}
			testedRules++
			totalAttempts += row.Attempts
			totalSuccesses += row.Successes
		}
		if d.ruleStatsSummary != nil {
			if testedRules == 0 || totalAttempts == 0 {
				d.ruleStatsSummary.SetText(fmt.Sprintf("规则绕过率 // 已检测 0/%d 条规则 | 整体绕过率 未检测", len(rows)))
			} else {
				rate := float64(totalSuccesses) / float64(totalAttempts) * 100
				d.ruleStatsSummary.SetText(fmt.Sprintf("规则绕过率 // 已检测 %d/%d 条规则 | 整体绕过率 %.0f%%", testedRules, len(rows), rate))
			}
		}
		if d.ruleStatsList != nil {
			d.ruleStatsList.Refresh()
			for i := range d.ruleStatsRows {
				d.ruleStatsList.SetItemHeight(i, 40)
			}
		}
	})
}

func (d *dashboard) buildFooter() fyne.CanvasObject {
	timestamp := widget.NewLabel(time.Now().Format("2006-01-02 15:04:05"))
	timestamp.Wrapping = fyne.TextWrapOff

	selection := widget.NewLabel("赛道 // 尚未锁定目标")
	selection.Wrapping = fyne.TextWrapOff

	content := container.NewHBox(
		animatedSignalLamp(18, accentGreen),
		d.statusText,
		layout.NewSpacer(),
		selection,
		layout.NewSpacer(),
		timestamp,
	)

	d.footerTrackLabel = selection
	return neonPanel(accentGreen, content)
}

func (d *dashboard) buildConsolePanel() fyne.CanvasObject {
	actions := container.NewHBox(
		d.consoleToggleBtn,
		d.consoleClearBtn,
	)
	statusRow := container.NewHBox(
		d.consoleStatus,
		layout.NewSpacer(),
		d.consoleProgressText,
		actions,
	)
	progressRow := container.NewPadded(d.consoleProgress)
	summary := container.NewVBox(statusRow, progressRow)
	return neonPanel(accentGreen, container.NewVBox(summary, d.consoleDetailBox))
}

func (d *dashboard) fetchSites(trigger string) bool {
	d.detectMu.Lock()
	if d.pipelineRunning && trigger != "pipeline" {
		d.detectMu.Unlock()
		return false
	}
	if d.searchRunning {
		activeTrigger := d.searchTrigger
		cancel := d.searchCancel
		d.detectMu.Unlock()
		if activeTrigger != "" && activeTrigger != trigger {
			return false
		}
		if cancel != nil {
			cancel()
		}
		return false
	}
	d.detectMu.Unlock()

	page := d.cfg.FOFA.DefaultPage
	if page <= 0 {
		page = 1
	}
	size, _ := strconv.Atoi(strings.TrimSpace(d.sizeEntry.Text))
	query := normalizeFOFAQuery(strings.TrimSpace(d.queryEntry.Text), d.chinaOnlyEnabled())

	if d.needsFOFAConfig() {
		d.setStatus("配置 // 请先填写 FOFA 邮箱和接口密钥")
		dialog.ShowInformation("配置 FOFA", "请先填写有效的 FOFA 邮箱和 API Key。", d.window)
		d.openSettingsDialog()
		return false
	}

	client := fofa.NewClient(d.cfg.FOFA, d.cfg.WAFSignatures, d.proxyUpstreamURL())
	ctx, cancel := context.WithCancel(context.Background())
	d.detectMu.Lock()
	d.searchCancel = cancel
	d.searchRunning = true
	d.searchTrigger = trigger
	d.searchOutcome = "running"
	d.detectMu.Unlock()
	d.updateSearchButtons()
	d.setStatus("同步中 // 正在请求 FOFA API")
	d.resetConsole("目标采集", fmt.Sprintf("准备从 FOFA 拉取 %d 条 URL", size))

	go func() {
		defer func() {
			d.detectMu.Lock()
			d.searchCancel = nil
			d.searchRunning = false
			d.searchTrigger = ""
			d.detectMu.Unlock()
			d.updateSearchButtons()
			cancel()
		}()

		pipelinePrefix := d.pipelineRoundText()
		pipelineStatusPrefix := d.pipelineRoundStatusText()
		if pipelinePrefix == "" {
			d.appendConsoleLog(fmt.Sprintf("[init] 查询=%s | 起始页=%d | 目标量=%d", emptyFallback(query, normalizeFOFAQuery(d.cfg.FOFA.Query, d.chinaOnlyEnabled())), page, size))
		} else {
			d.appendConsoleLog(fmt.Sprintf("[init %s] 查询=%s | 起始页=%d | 目标量=%d", pipelinePrefix, emptyFallback(query, normalizeFOFAQuery(d.cfg.FOFA.Query, d.chinaOnlyEnabled())), page, size))
		}
		initialCount := d.siteTotalCount
		liveSeen := make(map[string]bool, len(d.seenSiteKeys)+size)
		liveUniqueAdded := 0
		for key := range d.seenSiteKeys {
			liveSeen[key] = true
		}
		detectAddedBase := 0
		if trigger == "pipeline" {
			d.detectMu.Lock()
			detectAddedBase = d.pipelineAddedSites
			d.detectMu.Unlock()
		}
		sites, err := client.SearchSitesBatch(ctx, query, page, size, 500, func(progress fofa.BatchProgress) {
			if d.siteCountValue != nil {
				for _, site := range progress.Sites {
					digest := siteKeyDigest(d.siteKey(site))
					if digest == "" {
						liveUniqueAdded++
						continue
					}
					if liveSeen[digest] {
						continue
					}
					liveSeen[digest] = true
					liveUniqueAdded++
				}
				d.siteCountValue.Text = strconv.Itoa(initialCount + liveUniqueAdded)
				d.siteCountValue.Refresh()
			}
			d.setMetricDelta(d.siteDeltaValue, detectAddedBase+liveUniqueAdded)
			if pipelinePrefix == "" {
				d.setConsoleStatus(fmt.Sprintf("搜索进行中... 第 %d 页，本轮新增 %d", progress.Page, liveUniqueAdded))
			} else {
				d.setConsoleStatus(fmt.Sprintf("搜索进行中 %s... 第 %d 页，本轮新增 %d", pipelineStatusPrefix, progress.Page, liveUniqueAdded))
			}
			d.setConsoleProgress(progress.TotalCount, size)
		})
		if err != nil {
			if ctx.Err() == context.Canceled {
				d.detectMu.Lock()
				d.searchOutcome = "stopped"
				d.detectMu.Unlock()
				d.appendConsoleLog("[stop] 搜索已停止")
				d.setConsoleStatus("搜索已停止")
				d.setStatus("同步已停止 // 已中断当前 FOFA 搜索任务")
				return
			}
			d.detectMu.Lock()
			d.searchOutcome = "failed"
			d.detectMu.Unlock()
			d.appendConsoleLog("[error] " + err.Error())
			d.setConsoleStatus("搜索失败")
			dialog.ShowError(err, d.window)
			if d.shouldPromptFOFAConfig(err) {
				d.openSettingsDialog()
			}
			d.setStatus("错误 // FOFA 拉取失败")
			d.finishSearchConsole(false)
			return
		}

		beforeCount := d.siteTotalCount
		addedCount := d.mergeSites(sites)
		totalAddedCount := addedCount
		if trigger == "pipeline" {
			d.detectMu.Lock()
			d.pipelineAddedSites += addedCount
			totalAddedCount = d.pipelineAddedSites
			d.detectMu.Unlock()
		}
		d.setMetricDelta(d.siteDeltaValue, totalAddedCount)
		d.selectedCluster = -1
		d.selectedSite = -1
		d.currentScanID = time.Now().Format("20060102-150405.000000000")
		d.appendScanRecord(store.ScanRecord{
			ID:        d.currentScanID,
			Query:     query,
			ChinaOnly: d.chinaOnlyEnabled(),
			Page:      page,
			Size:      size,
			StartedAt: time.Now(),
			SiteCount: d.siteTotalCount,
		})
		d.refreshWAFOptions()
		d.applyFilters()
		d.persistDatabase()
		d.detectMu.Lock()
		d.searchOutcome = "completed"
		d.detectMu.Unlock()
		if pipelinePrefix == "" {
			d.appendConsoleLog(fmt.Sprintf("[done] 采集完成 | 新增 %d 条 | 原有 %d 条 | 当前总计 %d 条 URL", addedCount, beforeCount, d.siteTotalCount))
			d.setConsoleStatus(fmt.Sprintf("搜索完成，新增 %d 条，当前共 %d 条 URL", addedCount, d.siteTotalCount))
			d.setStatus(fmt.Sprintf("同步完成 // 新增 %d 个站点，当前共 %d 个", addedCount, d.siteTotalCount))
		} else {
			d.appendConsoleLog(fmt.Sprintf("[done %s] 本轮新增 %d 条 | 累计新增 %d 条 | 原有 %d 条 | 当前总计 %d 条 URL", pipelinePrefix, addedCount, totalAddedCount, beforeCount, d.siteTotalCount))
			d.setConsoleStatus(fmt.Sprintf("搜索完成 %s，本轮新增 %d 条，累计新增 %d 条", pipelineStatusPrefix, addedCount, totalAddedCount))
			d.setStatus(fmt.Sprintf("一键执行 %s // 本轮新增 %d 个站点，累计新增 %d 个", pipelineStatusPrefix, addedCount, totalAddedCount))
		}
		d.setConsoleProgress(size, size)
		d.finishSearchConsole(true)
	}()

	return true
}

func (d *dashboard) detectSites() bool {
	d.detectMu.Lock()
	if d.pipelineRunning && d.pipelineStage != "" && d.pipelineStage != "detect" {
		d.detectMu.Unlock()
		return false
	}
	if d.detectRunning {
		d.detectMu.Unlock()
		dialog.ShowInformation("识别进行中", "当前已有识别任务在运行，请先等待完成或点击停止识别。", d.window)
		return false
	}
	d.detectMu.Unlock()

	targets := d.nextDetectTargets()
	if len(targets) == 0 && len(d.sites) == 0 {
		dialog.ShowInformation("没有目标", "请先采集站点，再执行 WAF 识别。", d.window)
		return false
	}
	if len(targets) == 0 {
		dialog.ShowInformation("没有新增URL", "当前可见目标都已经识别过了。只有新增 URL 会进入本次识别。", d.window)
		return false
	}

	service := detector.New(d.cfg.Tester, d.cfg.Variables, d.proxyUpstreamURL())
	defer service.CloseIdleConnections()
	workers := d.currentDetectConcurrency()
	if workers <= 0 {
		workers = 100
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers <= 0 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.detectMu.Lock()
	d.detectCancel = cancel
	d.detectRunning = true
	d.detectStopReason = ""
	d.detectOutcome = "running"
	d.detectMu.Unlock()
	d.updateDetectButtons()

	d.setStatus(fmt.Sprintf("识别中 // 正在分析 %d 个目标站点", len(targets)))
	d.resetConsole("WAF识别", fmt.Sprintf("准备分析 %d 个新增目标站点，并发 %d", len(targets), workers))
	initialSuspected := d.suspectedSiteCount()

	go func() {
		defer func() {
			d.detectMu.Lock()
			d.detectCancel = nil
			d.detectRunning = false
			d.detectStopReason = ""
			d.detectMu.Unlock()
			d.updateDetectButtons()
		}()

		type detectJob struct {
			index int
			site  model.Site
		}
		type detectOutput struct {
			index  int
			site   model.Site
			result model.DetectionResult
		}

		jobs := make(chan detectJob)
		outputs := make(chan detectOutput, workers)
		var wg sync.WaitGroup

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					if ctx.Err() != nil {
						return
					}
					result := detectOutput{
						index:  job.index,
						site:   job.site,
						result: service.AnalyzeContext(ctx, job.site),
					}
					select {
					case outputs <- result:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		go func() {
			for idx, site := range targets {
				select {
				case <-ctx.Done():
					close(jobs)
					wg.Wait()
					close(outputs)
					return
				case jobs <- detectJob{index: idx, site: site}:
				}
			}
			close(jobs)
			wg.Wait()
			close(outputs)
		}()

		completed := 0
		withWAF := 0
		noWAF := 0
		errors := 0
		stopped := false

		for item := range outputs {
			if item.result.Error == "已停止" {
				stopped = true
				continue
			}
			result := item.result
			key := d.siteKey(item.site)
			if label := d.clusterLabels[result.ClusterKey]; label != "" {
				result.ClusterLabel = label
			}
			d.detections[key] = result

			completed++
			switch {
			case result.Error != "":
				errors++
			case result.HasWAF:
				withWAF++
			default:
				noWAF++
			}
			if d.suspectedValue != nil {
				d.suspectedValue.Text = strconv.Itoa(initialSuspected + withWAF)
				d.suspectedValue.Refresh()
			}
			d.setMetricDelta(d.suspectedDeltaValue, withWAF)

			d.setConsoleStatus(fmt.Sprintf("识别进行中... %d/%d | 并发 %d", completed, len(targets), workers))
			d.setConsoleProgress(completed, len(targets))
		}
		if ctx.Err() != nil {
			stopped = true
		}

		d.refreshWAFOptions()
		d.applyFilters()
		d.setMetricDelta(d.suspectedDeltaValue, withWAF)
		d.updateActiveScanRecord(func(record *store.ScanRecord) {
			record.CompletedAt = time.Now()
			record.SiteCount = d.siteTotalCount
			record.SuspectedCount = d.suspectedSiteCount()
			record.ClusterCount = d.totalClusterGroupCount()
			record.ResultCount = len(d.results)
		})
		d.persistDatabase()
		if stopped {
			stopReason := "内部取消"
			d.detectMu.Lock()
			if strings.TrimSpace(d.detectStopReason) != "" {
				stopReason = d.detectStopReason
			}
			d.detectOutcome = "stopped"
			d.detectMu.Unlock()
			d.appendConsoleLog(fmt.Sprintf("[stop] 识别已停止 | 原因=%s | 已完成=%d/%d | 有WAF=%d | 无WAF=%d | 异常=%d", stopReason, completed, len(targets), withWAF, noWAF, errors))
			d.setConsoleStatus(fmt.Sprintf("识别已停止，原因：%s，已完成 %d/%d", stopReason, completed, len(targets)))
			d.setStatus(fmt.Sprintf("识别已停止 // %s | 已完成 %d/%d 个新增目标", stopReason, completed, len(targets)))
			return
		}
		d.detectMu.Lock()
		d.detectOutcome = "completed"
		d.detectMu.Unlock()
		d.appendConsoleLog(fmt.Sprintf("[done] 识别完成 | 总计=%d | 有WAF=%d | 无WAF=%d | 异常=%d", len(targets), withWAF, noWAF, errors))
		d.setConsoleStatus(fmt.Sprintf("识别完成，共分析 %d 个新增目标", len(targets)))
		d.setConsoleProgress(len(targets), len(targets))
		d.setStatus(fmt.Sprintf("识别完成 // 已生成 %d 条新增 WAF 判定结果", len(targets)))
	}()

	return true
}

func (d *dashboard) stopDetectSites() {
	d.detectMu.Lock()
	cancel := d.detectCancel
	running := d.detectRunning
	d.detectMu.Unlock()

	if !running || cancel == nil {
		dialog.ShowInformation("没有识别任务", "当前没有正在运行的识别任务。", d.window)
		return
	}
	d.detectMu.Lock()
	d.detectStopReason = "用户手动停止"
	d.detectMu.Unlock()
	d.updateDetectButtons()
	cancel()
	d.appendConsoleLog("[ctrl] 已发送停止指令，原因=用户手动停止，正在终止识别任务")
	d.setConsoleStatus("正在停止识别...")
}

func (d *dashboard) reloadPlugins() {
	plugins, err := plugin.Load(d.cfg.Plugin.Dir)
	if err != nil {
		d.plugins = nil
		if d.pluginList != nil {
			d.pluginList.Refresh()
		}
		d.pluginDetails.SetText("")
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 无法加载插件目录")
		return
	}

	d.plugins = plugins
	d.selectedPlugin = -1
	d.pluginDetails.SetText("")
	if d.pluginList != nil {
		d.pluginList.Refresh()
	}
	d.refreshDashboard()
	d.setStatus(fmt.Sprintf("插件就绪 // 已载入 %d 条规则", len(plugins)))
}

func (d *dashboard) runSelectedPlugin() {
	if d.currentSite() == nil {
		dialog.ShowInformation("选择站点", "请先在站点列表中选中一个目标站点。", d.window)
		return
	}
	if d.currentPlugin() == nil {
		dialog.ShowInformation("选择插件", "请先在插件列表中选中一个插件。", d.window)
		return
	}
	if isTemplatePlugin(*d.currentPlugin()) {
		dialog.ShowInformation("模板规则", "template 是内置模板规则，仅用于保留规则编写格式，不参与绕过检测。", d.window)
		return
	}

	d.setStatus("运行中 // 正在执行当前插件")
	service := tester.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
	target := d.effectiveSite(*d.currentSite())
	d.resetBypassStatsSession([]model.Plugin{*d.currentPlugin()})
	var detectionPtr *model.DetectionResult
	if detection, ok := d.detectionForSite(target); ok {
		detectionCopy := detection
		detectionPtr = &detectionCopy
	}
	result := service.RunWithDetection(target, *d.currentPlugin(), detectionPtr)
	d.results = append([]model.TestResult{result}, d.results...)
	d.bypassStatsResults = []model.TestResult{result}
	d.rememberSessionBypass(result)
	d.resultList.Refresh()
	d.selectedResult = 0
	d.resultList.Select(0)
	d.refreshDashboard()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ResultCount = len(d.results)
	})
	d.persistDatabase()
	d.refreshBypassStatsFromResults()
	d.setStatus(fmt.Sprintf("结果 // %s", result.Verdict))
}

func (d *dashboard) runAllPlugins() {
	target := d.currentSite()
	if target == nil {
		dialog.ShowInformation("选择站点", "请先在站点列表中选中一个目标站点。", d.window)
		return
	}
	if len(d.plugins) == 0 {
		dialog.ShowInformation("插件为空", "当前没有可运行的原始请求插件。", d.window)
		return
	}

	resolvedTarget := d.effectiveSite(*target)
	validationPlugins := filterVisibleValidationPlugins(d.plugins)
	if len(validationPlugins) == 0 {
		dialog.ShowInformation("没有可运行规则", "当前没有可用于绕过检测的规则，template 不参与检测。", d.window)
		return
	}
	d.setStatus(fmt.Sprintf("批量运行 // 正在执行 %d 条插件规则", len(validationPlugins)))
	service := tester.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
	d.resetBypassStatsSession(validationPlugins)

	batch := make([]model.TestResult, 0, len(validationPlugins))
	var detectionPtr *model.DetectionResult
	if detection, ok := d.detectionForSite(resolvedTarget); ok {
		detectionCopy := detection
		detectionPtr = &detectionCopy
	}
	for _, p := range validationPlugins {
		batch = append(batch, service.RunWithDetection(resolvedTarget, p, detectionPtr))
	}

	d.results = append(batch, d.results...)
	d.bypassStatsResults = append([]model.TestResult(nil), batch...)
	d.rememberSessionBypass(batch...)
	d.resultList.Refresh()
	if len(batch) > 0 {
		d.selectedResult = 0
		d.resultList.Select(0)
	}
	d.refreshDashboard()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ResultCount = len(d.results)
	})
	d.persistDatabase()
	d.refreshBypassStatsFromResults()
	d.setStatus(fmt.Sprintf("批量完成 // 生成 %d 条测试结果", len(batch)))
}

func (d *dashboard) runRuleValidation(plugins []model.Plugin) {
	if len(plugins) == 0 {
		dialog.ShowInformation("选择规则", "请先选择至少一条规则。", d.window)
		return
	}
	validationPlugins := filterVisibleValidationPlugins(plugins)
	screeningPlugin, hasScreeningPlugin := d.screeningPlugin()
	d.detectMu.Lock()
	if d.ruleValidationRunning {
		d.detectMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.ruleValidationCancel = cancel
	d.ruleValidationRunning = true
	d.ruleValidationStopReason = ""
	d.detectMu.Unlock()
	d.updateRuleValidationButton()
	d.runOnUI(func() {
		d.refreshCurrentStepView()
	})

	d.resetRuleValidationSession(validationPlugins)
	initialTargets, initialDetections := d.suspectedTargets()

	if len(initialTargets) == 0 {
		d.detectMu.Lock()
		d.ruleValidationCancel = nil
		d.ruleValidationRunning = false
		d.ruleValidationStopReason = ""
		d.detectMu.Unlock()
		d.updateRuleValidationButton()
		dialog.ShowInformation("没有目标", "当前没有可用于规则验证的疑似 WAF 站点。", d.window)
		return
	}

	service := tester.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
	ruleLabel := fmt.Sprintf("%d 条规则", len(validationPlugins))
	if len(validationPlugins) == 1 {
		ruleLabel = validationPlugins[0].Name
	}
	if len(validationPlugins) == 0 {
		ruleLabel = "无正式规则"
	}
	preflightMode := validationPreflightMode(validationPlugins)
	preflightPrune := validationPreflightPrune(validationPlugins)

	d.setStatus(fmt.Sprintf("规则验证 // 正在预探测 %d 个疑似 WAF 站点", len(initialTargets)))
	d.resetConsole("规则验证", fmt.Sprintf("准备为 %s 预探测 %d 个疑似 WAF 站点", ruleLabel, len(initialTargets)))

	go func() {
		defer func() {
			d.detectMu.Lock()
			d.ruleValidationCancel = nil
			d.ruleValidationRunning = false
			d.ruleValidationStopReason = ""
			d.detectMu.Unlock()
			d.updateRuleValidationButton()
			d.runOnUI(func() {
				d.refreshCurrentStepView()
			})
		}()

		preflightStartedAt := time.Now()
		targets := initialTargets
		detections := initialDetections
		removed := 0
		preflightRate := "跳过"
		if preflightMode == "skip" {
			d.appendConsoleLog(fmt.Sprintf("[init] 规则验证已按规则配置跳过系统预探测 | 规则=%s | 目标=%d", ruleLabel, len(initialTargets)))
			d.setConsoleStatus(fmt.Sprintf("规则验证已跳过系统预探测... 0/%d", len(initialTargets)))
			d.setConsoleProgress(0, len(initialTargets))
		} else {
			targets, detections, removed = d.preflightRuleValidationTargets(ctx, initialTargets, initialDetections, ruleLabel, preflightPrune)
			preflightRate = formatScanRate(len(initialTargets), time.Since(preflightStartedAt))
		}
		if ctx.Err() != nil {
			stopReason := "用户手动停止"
			d.detectMu.Lock()
			if strings.TrimSpace(d.ruleValidationStopReason) != "" {
				stopReason = d.ruleValidationStopReason
			}
			d.detectMu.Unlock()
			d.appendConsoleLog(fmt.Sprintf("[stop] 规则验证已停止 | 原因=%s", stopReason))
			d.setConsoleStatus(fmt.Sprintf("规则验证已停止，原因：%s", stopReason))
			d.setStatus(fmt.Sprintf("规则验证 // 已停止 | %s", stopReason))
			return
		}
		if len(targets) == 0 {
			d.appendConsoleLog(fmt.Sprintf("[done] 预探测完成 | 已移除 %d 个失效目标 | 速率=%s | 当前无可验证站点", removed, preflightRate))
			d.setConsoleStatus(fmt.Sprintf("预探测完成，当前没有可验证的疑似 WAF 站点 | %s", preflightRate))
			d.setConsoleProgress(1, 1)
			d.setStatus(fmt.Sprintf("规则验证 // 预探测移除了 %d 个目标，当前无可验证站点", removed))
			d.runOnUI(func() {
				dialog.ShowInformation("没有可验证目标", "预探测后没有剩余的疑似 WAF 站点可用于规则验证。", d.window)
			})
			return
		}

		screenRemoved := 0
		if hasScreeningPlugin {
			d.appendConsoleLog(fmt.Sprintf("[screen] 使用筛查规则 %s 预检剩余目标", emptyFallback(screeningPlugin.Name, "get-id-baseline-bypass")))
			targets, detections, screenRemoved = d.screenRuleValidationTargets(ctx, screeningPlugin, targets, detections)
			if ctx.Err() != nil {
				stopReason := "用户手动停止"
				d.detectMu.Lock()
				if strings.TrimSpace(d.ruleValidationStopReason) != "" {
					stopReason = d.ruleValidationStopReason
				}
				d.detectMu.Unlock()
				d.appendConsoleLog(fmt.Sprintf("[stop] 规则验证已停止 | 原因=%s", stopReason))
				d.setConsoleStatus(fmt.Sprintf("规则验证已停止，原因：%s", stopReason))
				d.setStatus(fmt.Sprintf("规则验证 // 已停止 | %s", stopReason))
				return
			}
			if len(targets) == 0 {
				d.appendConsoleLog(fmt.Sprintf("[done] 筛查规则完成 | 预探测移除=%d | 筛查移除=%d | 当前无可验证站点", removed, screenRemoved))
				d.setConsoleStatus("筛查完成，当前没有可验证的疑似 WAF 站点")
				d.setConsoleProgress(1, 1)
				d.setStatus(fmt.Sprintf("规则验证 // 预探测移除 %d 个，筛查移除 %d 个，当前无可验证站点", removed, screenRemoved))
				d.runOnUI(func() {
					dialog.ShowInformation("没有可验证目标", "筛查规则执行后，没有剩余的疑似 WAF 站点可用于正式规则验证。", d.window)
				})
				return
			}
		}

		if len(validationPlugins) == 0 {
			d.appendConsoleLog(fmt.Sprintf("[done] 筛查完成 | 预探测移除=%d | 筛查移除=%d | 未选择正式验证规则", removed, screenRemoved))
			d.setConsoleStatus("筛查完成，未选择正式验证规则")
			d.setConsoleProgress(1, 1)
			d.setStatus(fmt.Sprintf("规则验证 // 筛查后保留 %d 个目标，未选择正式验证规则", len(targets)))
			return
		}

		totalJobs := len(validationPlugins) * len(targets)
		if totalJobs == 0 {
			d.appendConsoleLog(fmt.Sprintf("[done] 筛查完成 | 剩余目标=%d，但所选正式规则没有匹配到可验证站点", len(targets)))
			d.setConsoleStatus("规则与剩余站点不匹配")
			d.setConsoleProgress(1, 1)
			d.setStatus(fmt.Sprintf("规则验证 // %s 没有匹配到可验证目标", ruleLabel))
			d.runOnUI(func() {
				dialog.ShowInformation("没有匹配目标", "预探测完成后，所选规则没有匹配到可验证的疑似 WAF 站点。", d.window)
			})
			return
		}

		workers := d.currentDetectConcurrency()
		if workers <= 0 {
			workers = 1
		}
		if workers > totalJobs {
			workers = totalJobs
		}
		if workers <= 0 {
			workers = 1
		}
		validationStartedAt := time.Now()

		probeService := detector.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
		defer probeService.CloseIdleConnections()
		defer service.CloseIdleConnections()
		liveStats := map[string]bypassClusterStat{}
		for _, cluster := range d.clusterViews() {
			if cluster.Count <= 5 {
				continue
			}
			liveStats[cluster.Key] = bypassClusterStat{
				Key:        cluster.Key,
				Title:      clusterDefaultTitle(cluster),
				GroupCount: cluster.Count,
			}
		}
		d.appendConsoleLog(fmt.Sprintf("[init] 预探测完成 | 保留=%d | 移除=%d | 速率=%s | 规则=%d | 任务=%d | 并发=%d", len(targets), removed, preflightRate, len(plugins), totalJobs, workers))
		d.setConsoleStatus(fmt.Sprintf("规则验证进行中... 0/%d | 并发 %d | %s | 可能绕过 0", totalJobs, workers, formatScanRate(0, 0)))
		d.setConsoleProgress(0, totalJobs)
		d.setStatus(fmt.Sprintf("规则验证 // 正在用 %s 验证 %d 个目标", ruleLabel, len(targets)))

		type job struct {
			index     int
			plugin    model.Plugin
			site      model.Site
			detection model.DetectionResult
		}
		type output struct {
			index     int
			result    model.TestResult
			detection model.DetectionResult
		}
		type recheckJob struct {
			siteKey   string
			site      model.Site
			detection model.DetectionResult
			kind      string
		}
		type recheckOutput struct {
			siteKey string
			site    model.Site
			remove  bool
			reason  string
			kind    string
		}

		jobs := make(chan job)
		outputs := make(chan output, workers)
		recheckWorkers := workers / 2
		if recheckWorkers < 1 {
			recheckWorkers = 1
		}
		if recheckWorkers > len(targets) {
			recheckWorkers = len(targets)
		}
		recheckBuffer := recheckWorkers * 4
		if len(targets) > recheckBuffer {
			recheckBuffer = len(targets)
		}
		if recheckBuffer < 1 {
			recheckBuffer = 1
		}
		recheckJobs := make(chan recheckJob, recheckBuffer)
		recheckOutputs := make(chan recheckOutput, recheckBuffer)
		var submittedJobs int64
		var completedJobs int64
		var activeJobs int64
		var submittedRechecks int64
		var completedRechecks int64
		var activeRechecks int64
		var statsRefreshes int64
		var pruneFlushes int64
		var diagnosticWrites int64
		metricsDone := make(chan struct{})
		defer close(metricsDone)
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			lastDone := int64(0)
			lastAt := time.Now()
			for {
				select {
				case <-ticker.C:
					now := time.Now()
					done := atomic.LoadInt64(&completedJobs)
					elapsed := now.Sub(lastAt).Seconds()
					windowRate := 0.0
					if elapsed > 0 {
						windowRate = float64(done-lastDone) / elapsed
					}
					submitted := atomic.LoadInt64(&submittedJobs)
					d.appendConsoleLog(fmt.Sprintf(
						"[perf] 规则验证 | 窗口=%.1f/s | 平均=%s | 提交=%d | 完成=%d/%d | 活跃=%d | 待提交=%d | 复核活跃=%d | 复核队列=%d | 复核=%d/%d | UI刷新=%d | 裁剪=%d | 诊断=%d",
						windowRate,
						formatScanRate(int(done), time.Since(validationStartedAt)),
						submitted,
						done,
						totalJobs,
						atomic.LoadInt64(&activeJobs),
						int64(totalJobs)-submitted,
						atomic.LoadInt64(&activeRechecks),
						len(recheckJobs),
						atomic.LoadInt64(&completedRechecks),
						atomic.LoadInt64(&submittedRechecks),
						atomic.LoadInt64(&statsRefreshes),
						atomic.LoadInt64(&pruneFlushes),
						atomic.LoadInt64(&diagnosticWrites),
					))
					lastDone = done
					lastAt = now
				case <-metricsDone:
					return
				}
			}
		}()
		var wg sync.WaitGroup
		var recheckWG sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range jobs {
					detectionCopy := item.detection
					if ctx.Err() != nil {
						return
					}
					atomic.AddInt64(&activeJobs, 1)
					result := service.RunWithDetectionContext(ctx, item.site, item.plugin, &detectionCopy)
					atomic.AddInt64(&activeJobs, -1)
					select {
					case outputs <- output{index: item.index, result: result, detection: detectionCopy}:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		for i := 0; i < recheckWorkers; i++ {
			recheckWG.Add(1)
			go func() {
				defer recheckWG.Done()
				for item := range recheckJobs {
					if ctx.Err() != nil {
						return
					}
					atomic.AddInt64(&activeRechecks, 1)
					switch item.kind {
					case "availability":
						_, _, err := probeValidationBaseline(ctx, probeService, item.site, item.detection)
						select {
						case recheckOutputs <- recheckOutput{
							siteKey: item.siteKey,
							site:    item.site,
							remove:  err != nil,
							reason:  "规则验证时原始请求也无响应",
							kind:    item.kind,
						}:
						case <-ctx.Done():
							atomic.AddInt64(&activeRechecks, -1)
							return
						}
					case "dynamic":
						_, latestBaseline, err := probeValidationBaseline(ctx, probeService, item.site, item.detection)
						remove, reason := shouldPruneDynamicBaseline(item.detection.Baseline, latestBaseline, err)
						select {
						case recheckOutputs <- recheckOutput{
							siteKey: item.siteKey,
							site:    item.site,
							remove:  remove,
							reason:  reason,
							kind:    item.kind,
						}:
						case <-ctx.Done():
							atomic.AddInt64(&activeRechecks, -1)
							return
						}
					}
					atomic.AddInt64(&activeRechecks, -1)
				}
			}()
		}

		go func() {
			jobIndex := 0
			for _, plugin := range validationPlugins {
				for i := range targets {
					if ctx.Err() != nil {
						close(jobs)
						wg.Wait()
						close(outputs)
						return
					}
					target := targets[i]
					select {
					case jobs <- job{index: jobIndex, plugin: plugin, site: target, detection: detections[i]}:
						atomic.AddInt64(&submittedJobs, 1)
					case <-ctx.Done():
						close(jobs)
						wg.Wait()
						close(outputs)
						return
					}
					jobIndex++
				}
			}
			close(jobs)
			wg.Wait()
			close(outputs)
		}()

		batch := make([]model.TestResult, 0, totalJobs)
		siteBatch := map[string][]model.TestResult{}
		deadSites := map[string]string{}
		baselineReachable := map[string]bool{}
		availabilityChecked := map[string]bool{}
		dynamicChecked := map[string]bool{}
		diagnosticLoggedSites := map[string]bool{}
		pendingAvailabilityChecks := map[string]struct{}{}
		pendingDynamicChecks := map[string]struct{}{}
		pendingPrunes := map[string]string{}
		completed := 0
		bypass := 0
		blocked := 0
		review := 0
		lastProgressUpdate := time.Now()
		lastStatsUpdate := time.Now()
		lastPruneFlush := time.Now()
		lastTransportCleanup := time.Now()
		rowsDirty := false
		for _, target := range targets {
			siteKey := d.siteKey(target)
			if siteKey != "" {
				baselineReachable[siteKey] = true
			}
		}
		refreshProgress := func(force bool) {
			if !force && time.Since(lastProgressUpdate) < 200*time.Millisecond {
				return
			}
			lastProgressUpdate = time.Now()
			d.setConsoleStatus(fmt.Sprintf("规则验证进行中... %d/%d | 并发 %d | %s | 可能绕过 %d", completed, totalJobs, workers, formatScanRate(completed, time.Since(validationStartedAt)), bypass))
			d.setConsoleProgress(completed, totalJobs)
		}
		refreshLiveStats := func(force bool) {
			if !rowsDirty {
				return
			}
			if !force && time.Since(lastStatsUpdate) < 350*time.Millisecond {
				return
			}
			rows := make([]bypassClusterStat, 0, len(liveStats))
			for _, stat := range liveStats {
				if stat.Attempts == 0 {
					continue
				}
				rows = append(rows, stat)
			}
			sortBypassStatsRows(rows)
			d.updateBypassStatsRows(rows, "范围 // "+ruleLabel)
			atomic.AddInt64(&statsRefreshes, 1)
			lastStatsUpdate = time.Now()
			rowsDirty = false
		}
		flushPendingPrunes := func(force bool) {
			if len(pendingPrunes) == 0 {
				return
			}
			if !force {
				return
			}
			if !force && len(pendingPrunes) < 12 && time.Since(lastPruneFlush) < 250*time.Millisecond {
				return
			}
			batchPrunes := make(map[string]string, len(pendingPrunes))
			for key, reason := range pendingPrunes {
				batchPrunes[key] = reason
			}
			pendingPrunes = map[string]string{}
			lastPruneFlush = time.Now()
			atomic.AddInt64(&pruneFlushes, 1)
			runOnUI := d.runOnUI
			if force {
				runOnUI = d.runOnUISync
			}
			runOnUI(func() {
				d.pruneRuleValidationSites(batchPrunes)
			})
		}
		applyDeadSite := func(siteKey string, site model.Site, reason string, logPrefix string) {
			if siteKey == "" {
				return
			}
			if _, dead := deadSites[siteKey]; dead {
				return
			}
			deadSites[siteKey] = reason
			for _, previous := range siteBatch[siteKey] {
				bypass, blocked, review = adjustRuleValidationCounters(previous, bypass, blocked, review, -1)
				d.adjustLiveBypassStat(liveStats, previous, -1)
				rowsDirty = true
			}
			delete(siteBatch, siteKey)
			pendingPrunes[siteKey] = reason
			flushPendingPrunes(false)
			_ = logPrefix
		}
		handleRecheckOutput := func(item recheckOutput) {
			atomic.AddInt64(&completedRechecks, 1)
			switch item.kind {
			case "availability":
				delete(pendingAvailabilityChecks, item.siteKey)
				availabilityChecked[item.siteKey] = true
				baselineReachable[item.siteKey] = !item.remove
				if item.remove {
					applyDeadSite(item.siteKey, item.site, item.reason, fmt.Sprintf("[rule %d/%d]", completed, totalJobs))
				}
			case "dynamic":
				delete(pendingDynamicChecks, item.siteKey)
				dynamicChecked[item.siteKey] = true
				if item.remove {
					applyDeadSite(item.siteKey, item.site, item.reason, fmt.Sprintf("[rule %d/%d]", completed, totalJobs))
				}
			}
		}
		drainRecheckOutputs := func(force bool) {
			if force {
				for item := range recheckOutputs {
					handleRecheckOutput(item)
				}
				return
			}
			for {
				select {
				case item := <-recheckOutputs:
					handleRecheckOutput(item)
				default:
					return
				}
			}
		}
		for item := range outputs {
			if ctx.Err() != nil {
				break
			}
			_ = item.index
			completed++
			atomic.AddInt64(&completedJobs, 1)
			drainRecheckOutputs(false)
			siteKey := d.siteKey(item.result.Site)
			if _, dead := deadSites[siteKey]; dead {
				refreshProgress(false)
				continue
			}

			if isUnavailableValidationResult(item.result) {
				if checked := availabilityChecked[siteKey]; checked && baselineReachable[siteKey] {
					refreshProgress(false)
					continue
				}
				if _, queued := pendingAvailabilityChecks[siteKey]; !queued {
					pendingAvailabilityChecks[siteKey] = struct{}{}
					select {
					case recheckJobs <- recheckJob{siteKey: siteKey, site: item.result.Site, detection: item.detection, kind: "availability"}:
						atomic.AddInt64(&submittedRechecks, 1)
					case <-ctx.Done():
						break
					}
				}
				if !diagnosticLoggedSites[siteKey] {
					diagnosticLoggedSites[siteKey] = true
					baselinePacket := emptyFallback(visiblePacketText(d.baselineRequestPacketForDetection(item.result.Site, &item.detection)), "暂无原始请求包")
					rulePacket := emptyFallback(visiblePacketText(item.result.SentRequest), "暂无规则请求包")
					d.appendDiagnosticLog(
						fmt.Sprintf("目标: %s", emptyFallback(item.result.Site.URL, emptyFallback(item.result.Site.OriginalURL, item.result.Site.Host))),
						fmt.Sprintf("规则: %s", emptyFallback(item.result.Plugin.Name, "-")),
						"原始请求:",
						baselinePacket,
						"",
						"规则请求:",
						rulePacket,
					)
					atomic.AddInt64(&diagnosticWrites, 1)
				}
				refreshProgress(false)
				continue
			}

			if shouldReprobeDynamicBaseline(item.result) {
				if _, checked := dynamicChecked[siteKey]; checked {
					siteBatch[siteKey] = append(siteBatch[siteKey], item.result)
					batch = append(batch, item.result)
					bypass, blocked, review = adjustRuleValidationCounters(item.result, bypass, blocked, review, 1)
					d.adjustLiveBypassStat(liveStats, item.result, 1)
					rowsDirty = true
					refreshLiveStats(false)
					flushPendingPrunes(false)
					refreshProgress(false)
					continue
				}
				if _, queued := pendingDynamicChecks[siteKey]; !queued {
					pendingDynamicChecks[siteKey] = struct{}{}
					select {
					case recheckJobs <- recheckJob{siteKey: siteKey, site: item.result.Site, detection: item.detection, kind: "dynamic"}:
						atomic.AddInt64(&submittedRechecks, 1)
					case <-ctx.Done():
						break
					}
				}
			}

			siteBatch[siteKey] = append(siteBatch[siteKey], item.result)
			batch = append(batch, item.result)
			bypass, blocked, review = adjustRuleValidationCounters(item.result, bypass, blocked, review, 1)
			d.adjustLiveBypassStat(liveStats, item.result, 1)
			rowsDirty = true
			refreshLiveStats(false)
			flushPendingPrunes(false)
			if time.Since(lastTransportCleanup) >= 15*time.Second {
				service.CloseIdleConnections()
				probeService.CloseIdleConnections()
				lastTransportCleanup = time.Now()
			}
			refreshProgress(false)
		}
		close(recheckJobs)
		recheckWG.Wait()
		close(recheckOutputs)
		drainRecheckOutputs(true)
		flushPendingPrunes(true)
		refreshLiveStats(true)
		refreshProgress(true)
		if ctx.Err() != nil {
			stopReason := "用户手动停止"
			d.detectMu.Lock()
			if strings.TrimSpace(d.ruleValidationStopReason) != "" {
				stopReason = d.ruleValidationStopReason
			}
			d.detectMu.Unlock()
			d.appendConsoleLog(fmt.Sprintf("[stop] 规则验证已停止 | 原因=%s | 已完成=%d/%d | 可能绕过=%d | 已拦截=%d | 复核=%d | 速率=%s", stopReason, completed, totalJobs, bypass, blocked, review, formatScanRate(completed, time.Since(validationStartedAt))))
			d.setConsoleStatus(fmt.Sprintf("规则验证已停止，原因：%s，已完成 %d/%d | %s", stopReason, completed, totalJobs, formatScanRate(completed, time.Since(validationStartedAt))))
			d.setStatus(fmt.Sprintf("规则验证 // 已停止 | %s | 已完成 %d/%d", stopReason, completed, totalJobs))
			return
		}

		if len(deadSites) > 0 {
			filtered := batch[:0]
			for _, result := range batch {
				if _, removed := deadSites[d.siteKey(result.Site)]; removed {
					continue
				}
				filtered = append(filtered, result)
			}
			batch = filtered
			d.rebuildClusterState()
		}

		sort.Slice(batch, func(i, j int) bool {
			if batch[i].Verdict == batch[j].Verdict {
				return batch[i].Site.Host < batch[j].Site.Host
			}
			return batch[i].Verdict < batch[j].Verdict
		})

		d.results = append(batch, d.results...)
		d.bypassStatsResults = append([]model.TestResult(nil), batch...)
		d.rememberSessionBypass(batch...)
		finalRows := d.buildBypassStatsRows(d.bypassStatsPluginSet)
		d.updateBypassStatsRows(finalRows, d.bypassStatsPluginText)
		d.runOnUI(func() {
			if d.resultList != nil {
				d.resultList.Refresh()
			}
			if len(batch) > 0 && d.resultList != nil {
				d.selectedResult = 0
				d.resultList.Select(0)
			}
		})
		d.refreshDashboard()
		d.updateActiveScanRecord(func(record *store.ScanRecord) {
			record.ResultCount = len(d.results)
		})
		d.persistDatabase()
		service.CloseIdleConnections()
		probeService.CloseIdleConnections()
		d.appendConsoleLog(fmt.Sprintf("[done] 规则验证完成 | 正式规则=%d | 目标=%d | 任务=%d | 可能绕过=%d | 已拦截=%d | 复核=%d | 速率=%s", len(validationPlugins), len(targets), totalJobs, bypass, blocked, review, formatScanRate(completed, time.Since(validationStartedAt))))
		d.setConsoleStatus(fmt.Sprintf("规则验证完成，可能绕过 %d/%d | 并发 %d | %s", bypass, totalJobs, workers, formatScanRate(completed, time.Since(validationStartedAt))))
		d.setConsoleProgress(totalJobs, totalJobs)
		d.setStatus(fmt.Sprintf("规则验证 // %s 产生 %d 条结果，其中可能绕过 %d 条", ruleLabel, len(batch), bypass))
	}()
}

func (d *dashboard) preflightRuleValidationTargets(ctx context.Context, targets []model.Site, detections []model.DetectionResult, ruleLabel string, pruneInvalid bool) ([]model.Site, []model.DetectionResult, int) {
	if len(targets) == 0 || len(detections) == 0 {
		return targets, detections, 0
	}
	startedAt := time.Now()
	initialSuspected := d.suspectedSiteCount()
	initialClusters := d.totalClusterGroupCount()
	d.setMetricDelta(d.suspectedDeltaValue, 0)
	d.setMetricDelta(d.clusterDeltaValue, 0)

	service := detector.New(d.fastValidationTesterSettings(), d.cfg.Variables, d.proxyUpstreamURL())
	workers := d.currentDetectConcurrency()
	if workers <= 0 {
		workers = 1
	}
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers <= 0 {
		workers = 1
	}

	type job struct {
		index     int
		site      model.Site
		detection model.DetectionResult
	}
	type output struct {
		index     int
		site      model.Site
		detection model.DetectionResult
		baseline  model.ResponseSnapshot
		err       error
	}

	jobs := make(chan job)
	outputs := make(chan output, workers)
	var submittedPreflight int64
	var completedPreflight int64
	var activePreflight int64
	preflightMetricsDone := make(chan struct{})
	defer close(preflightMetricsDone)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		lastDone := int64(0)
		lastAt := time.Now()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				done := atomic.LoadInt64(&completedPreflight)
				elapsed := now.Sub(lastAt).Seconds()
				windowRate := 0.0
				if elapsed > 0 {
					windowRate = float64(done-lastDone) / elapsed
				}
				submitted := atomic.LoadInt64(&submittedPreflight)
				d.appendConsoleLog(fmt.Sprintf(
					"[perf] 预探测 | 窗口=%.1f/s | 平均=%s | 提交=%d | 完成=%d/%d | 活跃=%d | 待提交=%d",
					windowRate,
					formatScanRate(int(done), time.Since(startedAt)),
					submitted,
					done,
					len(targets),
					atomic.LoadInt64(&activePreflight),
					int64(len(targets))-submitted,
				))
				lastDone = done
				lastAt = now
			case <-preflightMetricsDone:
				return
			}
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				atomic.AddInt64(&activePreflight, 1)
				baselineURL, baseline, err := probeValidationBaseline(ctx, service, item.site, item.detection)
				atomic.AddInt64(&activePreflight, -1)
				if err == nil && strings.TrimSpace(baselineURL) != "" {
					baseline.URL = baselineURL
				}
				select {
				case outputs <- output{
					index:     item.index,
					site:      item.site,
					detection: item.detection,
					baseline:  baseline,
					err:       err,
				}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		for i := range targets {
			select {
			case jobs <- job{index: i, site: targets[i], detection: detections[i]}:
				atomic.AddInt64(&submittedPreflight, 1)
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(outputs)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(outputs)
	}()

	keptTargets := make([]model.Site, 0, len(targets))
	keptDetections := make([]model.DetectionResult, 0, len(detections))
	removedKeys := map[string]string{}
	pendingRemoved := map[string]string{}
	checked := 0
	lastFlushAt := time.Now()
	lastTransportCleanup := time.Now()
	currentRateText := func(done int) string {
		return formatScanRate(done, time.Since(startedAt))
	}
	lastProgressUpdate := time.Now()
	refreshPreflightProgress := func(force bool) {
		if !force && time.Since(lastProgressUpdate) < 200*time.Millisecond {
			return
		}
		lastProgressUpdate = time.Now()
		d.setConsoleStatus(fmt.Sprintf("预探测进行中... %d/%d | 已移除 %d | %s", checked, len(targets), len(removedKeys), currentRateText(checked)))
		d.setConsoleProgress(checked, len(targets))
		d.runOnUI(func() {
			if d.suspectedValue != nil {
				current := initialSuspected - len(removedKeys)
				if current < 0 {
					current = 0
				}
				d.suspectedValue.Text = strconv.Itoa(current)
				d.suspectedValue.Refresh()
			}
			d.setMetricDelta(d.suspectedDeltaValue, -len(removedKeys))
		})
	}

	d.appendConsoleLog(fmt.Sprintf("[init] 规则验证预探测 | 规则=%s | 目标=%d | 并发=%d", ruleLabel, len(targets), workers))
	d.setConsoleStatus(fmt.Sprintf("预探测进行中... 0/%d | 已移除 0 | %s", len(targets), currentRateText(0)))
	d.setConsoleProgress(0, len(targets))

	flushRemoved := func(force bool) {
		if len(pendingRemoved) == 0 {
			return
		}
		if !force {
			return
		}
		if !force && len(pendingRemoved) < 24 && time.Since(lastFlushAt) < 250*time.Millisecond {
			return
		}
		batch := make(map[string]string, len(pendingRemoved))
		for key, reason := range pendingRemoved {
			batch[key] = reason
		}
		pendingRemoved = map[string]string{}
		lastFlushAt = time.Now()
		runOnUI := d.runOnUI
		if force {
			runOnUI = d.runOnUISync
		}
		runOnUI(func() {
			d.pruneRuleValidationSites(batch)
			d.updatePreflightReductionDeltas(initialSuspected, initialClusters)
		})
	}

	for item := range outputs {
		if ctx.Err() != nil {
			break
		}
		checked++
		atomic.AddInt64(&completedPreflight, 1)
		remove, reason := shouldPruneRuleValidationTarget(item.detection, item.baseline, item.err)
		if remove && pruneInvalid {
			siteKey := d.siteKey(item.site)
			if siteKey == "" {
				siteKey = d.siteKey(item.detection.Site)
			}
			if siteKey != "" {
				removedKeys[siteKey] = reason
				pendingRemoved[siteKey] = reason
				flushRemoved(false)
			}
		} else {
			if !remove {
				item.detection.Baseline = item.baseline
				if strings.TrimSpace(item.detection.DetectedURL) == "" {
					item.detection.DetectedURL = item.baseline.URL
				}
			}
			keptTargets = append(keptTargets, item.site)
			keptDetections = append(keptDetections, item.detection)
		}
		refreshPreflightProgress(false)
		if time.Since(lastTransportCleanup) >= 15*time.Second {
			service.CloseIdleConnections()
			lastTransportCleanup = time.Now()
		}
	}
	if pruneInvalid {
		flushRemoved(true)
	}
	refreshPreflightProgress(true)
	service.CloseIdleConnections()

	if pruneInvalid && len(removedKeys) > 0 {
		d.rebuildClusterState()
		d.persistDatabase()
	}
	return keptTargets, keptDetections, len(removedKeys)
}

func probeValidationBaseline(ctx context.Context, service *detector.Service, site model.Site, detection model.DetectionResult) (string, model.ResponseSnapshot, error) {
	if hasStoredBaselineReference(detection) {
		return service.ProbeStoredBaselineContext(ctx, detection)
	}
	detectionCopy := detection
	return service.ProbeBaselineWithDetectionContext(ctx, site, &detectionCopy)
}

func hasStoredBaselineReference(detection model.DetectionResult) bool {
	return strings.TrimSpace(detection.DetectedURL) != "" || strings.TrimSpace(detection.Baseline.URL) != ""
}

func shouldPruneRuleValidationTarget(stored model.DetectionResult, baseline model.ResponseSnapshot, err error) (bool, string) {
	if err != nil {
		return true, "站点不可访问"
	}
	if baseline.StatusCode == 0 || strings.TrimSpace(baseline.Raw) == "" {
		return true, "基线响应缺失"
	}
	if stored.Baseline.StatusCode > 0 && baseline.StatusCode != stored.Baseline.StatusCode {
		return true, "基线状态码已变化"
	}
	if stored.Baseline.StatusCode > 0 {
		score := detector.ResponseSimilarity(stored.Baseline, baseline)
		if score < 0.95 {
			return true, fmt.Sprintf("基线已变化(%.2f)", score)
		}
	}
	return false, ""
}

func formatScanRate(done int, elapsed time.Duration) string {
	if done <= 0 || elapsed <= 0 {
		return "0.0/s"
	}
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return "0.0/s"
	}
	return fmt.Sprintf("%.1f/s", float64(done)/seconds)
}

func baselineResponseMissing(baseline model.ResponseSnapshot) bool {
	return baseline.StatusCode == 0 || strings.TrimSpace(baseline.Raw) == ""
}

func shouldReprobeDynamicBaseline(result model.TestResult) bool {
	if isUnavailableValidationResult(result) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(result.Plugin.ValidationMode), "baseline_similarity") {
		return false
	}
	return !strings.Contains(strings.TrimSpace(result.Verdict), "可能绕过")
}

func shouldPruneDynamicBaseline(previous model.ResponseSnapshot, latest model.ResponseSnapshot, err error) (bool, string) {
	if err != nil {
		return true, "原始页面复探无响应"
	}
	if baselineResponseMissing(latest) {
		return true, "原始页面复探缺失"
	}
	if previous.StatusCode > 0 && latest.StatusCode != previous.StatusCode {
		return true, "原始页面状态码变化"
	}
	score := detector.ResponseSimilarity(previous, latest)
	if score < 0.95 {
		return true, fmt.Sprintf("原始页面动态变化(%.2f)", score)
	}
	return false, ""
}

func isBaselineReplayRule(p model.Plugin) bool {
	if !strings.EqualFold(strings.TrimSpace(p.Method), "GET") {
		return false
	}
	uri := strings.TrimSpace(p.RequestURI)
	return uri == "/?id=1" || uri == "?id=1"
}

func (d *dashboard) baselineReplayResult(site model.Site, plugin model.Plugin, detection model.DetectionResult) model.TestResult {
	result := model.TestResult{
		Site:         site,
		Plugin:       plugin,
		RunAt:        time.Now(),
		StatusCode:   detection.Baseline.StatusCode,
		SentRequest:  d.baselineRequestPacket(site),
		ResponseHead: detection.Baseline.Headers,
		ResponseBody: detection.Baseline.Body,
		BaselineSim:  1,
		DiffRatio:    0,
	}
	if detection.HasWAF {
		result.BlockedSim = detector.ResponseSimilarity(detection.BlockedResponse, detection.Baseline)
	}
	result.Verdict = "可能绕过"
	result.MatchedRule = "基线回放 | 直接复用预探测成功结果"
	return result
}

func isUnavailableValidationResult(result model.TestResult) bool {
	if result.StatusCode == 0 && strings.TrimSpace(result.ResponseHead) == "" && strings.TrimSpace(result.ResponseBody) == "" {
		return true
	}
	return shouldRecheckUnavailableResult(result)
}

func shouldRecheckUnavailableResult(result model.TestResult) bool {
	verdict := strings.TrimSpace(result.Verdict)
	if strings.Contains(verdict, "无响应") {
		return true
	}
	if strings.Contains(verdict, "请求异常") && strings.TrimSpace(result.ResponseHead) == "" && strings.TrimSpace(result.ResponseBody) == "" {
		return true
	}
	return false
}

func adjustRuleValidationCounters(result model.TestResult, bypass int, blocked int, review int, delta int) (int, int, int) {
	switch {
	case strings.Contains(result.Verdict, "可能绕过"):
		bypass += delta
	case strings.Contains(result.Verdict, "已拦截"):
		blocked += delta
	default:
		review += delta
	}
	if bypass < 0 {
		bypass = 0
	}
	if blocked < 0 {
		blocked = 0
	}
	if review < 0 {
		review = 0
	}
	return bypass, blocked, review
}

func (d *dashboard) adjustLiveBypassStat(liveStats map[string]bypassClusterStat, result model.TestResult, delta int) {
	detection, ok := d.detectionForSite(result.Site)
	if !ok {
		return
	}
	stat, exists := liveStats[detection.ClusterKey]
	if !exists {
		return
	}
	stat.Attempts += delta
	if strings.Contains(result.Verdict, "可能绕过") {
		stat.Successes += delta
	}
	if stat.Attempts < 0 {
		stat.Attempts = 0
	}
	if stat.Successes < 0 {
		stat.Successes = 0
	}
	if stat.Attempts > 0 {
		stat.Rate = float64(stat.Successes) / float64(stat.Attempts)
	} else {
		stat.Rate = 0
	}
	liveStats[detection.ClusterKey] = stat
}

func (d *dashboard) pruneRuleValidationSites(removed map[string]string) {
	if len(removed) == 0 {
		return
	}
	validationRunning := d.isRuleValidationRunning()

	removedResult := false
	for key := range removed {
		delete(d.detections, key)
		delete(d.dbState.Current.Detections, key)
	}

	filteredResults := d.results[:0]
	for _, result := range d.results {
		if _, ok := removed[d.siteKey(result.Site)]; ok {
			removedResult = true
			continue
		}
		filteredResults = append(filteredResults, result)
	}
	d.results = filteredResults
	d.dbState.Current.Results = append([]model.TestResult(nil), d.results...)

	if len(removed) > 0 {
		if d.sessionBypassSites == nil {
			d.sessionBypassSites = map[string]bool{}
		}
		if d.sessionBypassResults == nil {
			d.sessionBypassResults = map[string]model.TestResult{}
		}
		for key := range removed {
			digest := siteKeyDigest(key)
			if digest == "" {
				continue
			}
			delete(d.sessionBypassSites, digest)
			delete(d.sessionBypassResults, digest)
		}
	}

	clusterCount := 0
	if validationRunning {
		clusterCount = d.lightweightClusterGroupCount()
		d.clusterViewsDirty = true
		d.dbState.Current.ClusterCount = clusterCount
	} else {
		d.rebuildClusterState()
		clusterCount = d.dbState.Current.ClusterCount
	}
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ClusterCount = clusterCount
		record.ResultCount = len(d.results)
	})
	if validationRunning {
		d.refreshDashboardCountersOnly()
	} else {
		d.refreshDashboard()
	}
	if removedResult && !validationRunning {
		d.runOnUI(func() {
			if d.resultList != nil {
				if len(d.results) == 0 {
					d.selectedResult = -1
				} else if d.selectedResult >= len(d.results) {
					d.selectedResult = 0
					d.resultList.Select(0)
				}
				d.resultList.Refresh()
			}
		})
	}
	if !validationRunning {
		d.refreshBypassStatsFromResults()
	}
}

func (d *dashboard) updatePreflightReductionDeltas(initialSuspected, initialClusters int) {
	d.setMetricDelta(d.suspectedDeltaValue, d.suspectedSiteCount()-initialSuspected)
	clusterCount := d.totalClusterGroupCount()
	if d.isRuleValidationRunning() {
		clusterCount = d.lightweightClusterGroupCount()
	}
	d.setMetricDelta(d.clusterDeltaValue, clusterCount-initialClusters)
}

func (d *dashboard) lightweightClusterGroupCount() int {
	keys := map[string]bool{}
	for _, detection := range d.detections {
		clusterKey := strings.TrimSpace(detection.ClusterKey)
		if !detection.HasWAF || clusterKey == "" {
			continue
		}
		keys[clusterKey] = true
	}
	return len(keys)
}

func (d *dashboard) rebuildClusterState() {
	d.rebuildClusterMembers()
	d.clusterBaseline = d.buildClusterBaseline()
	d.dbState.Current.ClusterBaseline = append([]store.ClusterBaselineItem(nil), d.clusterBaseline...)
	d.dbState.Current.ClusterCount = d.totalClusterGroupCount()
	d.invalidateClusterViewCache()
}

func (d *dashboard) openRuleValidationDialog() {
	if len(d.plugins) == 0 {
		dialog.ShowInformation("没有规则", "当前还没有可用于验证的规则。", d.window)
		return
	}

	options := filterVisibleValidationPlugins(d.plugins)
	if len(options) == 0 {
		dialog.ShowInformation("没有正式规则", "当前只有筛查规则，没有可选择的正式验证规则。", d.window)
		return
	}
	sort.Slice(options, func(i, j int) bool {
		return strings.ToLower(options[i].Name) < strings.ToLower(options[j].Name)
	})

	selectedName := ""
	if current := d.currentPlugin(); current != nil {
		selectedName = current.Name
	}

	allCheck := widget.NewCheck("全选所有规则", nil)
	helper := widget.NewLabel("支持同时选择两条或两条以上规则，也可以直接全选所有规则后批量验证。")
	helper.Wrapping = fyne.TextWrapWord
	selectedRules := map[string]bool{}
	if selectedName != "" {
		selectedRules[selectedName] = true
	}
	selectedCountLabel := canvas.NewText("", color.NRGBA{R: 171, G: 210, B: 255, A: 230})
	selectedCountLabel.TextSize = 11
	selectedCountLabel.TextStyle = fyne.TextStyle{Bold: true}
	updateSelectedCount := func() {
		if allCheck.Checked {
			selectedCountLabel.Text = fmt.Sprintf("已选择 %d 条", len(options))
		} else {
			selectedCountLabel.Text = fmt.Sprintf("已选择 %d 条", len(selectedRules))
		}
		selectedCountLabel.Refresh()
	}

	var list *widget.List
	list = widget.NewList(
		func() int { return len(options) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 228})
			bar := canvas.NewRectangle(accentAmber)
			bar.SetMinSize(fyne.NewSize(4, 0))
			check := widget.NewCheck("", nil)
			label := widget.NewLabel("规则")
			label.TextStyle = fyne.TextStyle{Bold: true}
			label.Wrapping = fyne.TextWrapOff
			return container.NewStack(
				bg,
				container.NewHBox(bar, check, container.NewPadded(label)),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(options) {
				return
			}
			name := options[id].Name
			accent := pluginAccent(options[id])
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if selectedRules[name] && !allCheck.Checked {
				bg.FillColor = color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 42}
			} else if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = accent
			bar.Refresh()
			check := main.Objects[1].(*widget.Check)
			check.OnChanged = nil
			check.SetChecked(allCheck.Checked || selectedRules[name])
			check.Disable()
			if !allCheck.Checked {
				check.Enable()
			}
			check.OnChanged = func(checked bool) {
				if checked {
					selectedRules[name] = true
				} else {
					delete(selectedRules, name)
				}
				updateSelectedCount()
				list.Refresh()
			}
			label := main.Objects[2].(*fyne.Container).Objects[0].(*widget.Label)
			label.SetText(options[id].Name)
		},
	)
	for i := range options {
		list.SetItemHeight(i, 38)
	}
	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(options) {
			return
		}
		if allCheck.Checked {
			list.UnselectAll()
			return
		}
		name := options[id].Name
		if selectedRules[name] {
			delete(selectedRules, name)
		} else {
			selectedRules[name] = true
		}
		updateSelectedCount()
		list.Refresh()
		list.UnselectAll()
	}

	allCheck.OnChanged = func(checked bool) {
		updateSelectedCount()
		list.Refresh()
	}

	startBtn := widget.NewButtonWithIcon("开始", playResource(), nil)
	cancelBtn := widget.NewButton("取消", nil)
	startBtn.Importance = widget.LowImportance
	cancelBtn.Importance = widget.LowImportance

	viewer := d.app.NewWindow("规则验证")
	startValidation := func() {
		if allCheck.Checked {
			plugins := append([]model.Plugin(nil), d.plugins...)
			viewer.Close()
			d.runRuleValidation(plugins)
			return
		}
		if len(selectedRules) == 0 {
			dialog.ShowInformation("选择规则", "请先选择至少一条规则，或者勾选全选所有规则。", viewer)
			return
		}
		plugins := make([]model.Plugin, 0, len(selectedRules))
		for _, plugin := range options {
			if selectedRules[plugin.Name] {
				plugins = append(plugins, plugin)
			}
		}
		if len(plugins) == 0 {
			dialog.ShowInformation("选择规则", "未找到所选规则，请重新选择。", viewer)
			return
		}
		viewer.Close()
		d.runRuleValidation(plugins)
	}
	startBtn.OnTapped = startValidation
	cancelBtn.OnTapped = func() {
		viewer.Close()
	}

	actionBar := container.NewHBox(
		layout.NewSpacer(),
		neonPanel(accentMuted, container.NewPadded(cancelBtn)),
		neonPanel(accentBlue, container.NewPadded(startBtn)),
	)

	content := container.NewBorder(
		neonPanel(accentAmber, container.NewVBox(helper, allCheck, selectedCountLabel)),
		neonPanel(accentBlue, actionBar),
		nil,
		nil,
		neonPanel(accentAmber, list),
	)

	viewer.Resize(fyne.NewSize(560, 460))
	viewer.SetContent(content)
	viewer.Show()
	updateSelectedCount()
	list.Refresh()
}

func (d *dashboard) updateSiteDetails() {
	if d.siteDetails == nil {
		return
	}
	site := d.currentSite()
	if site == nil {
		d.siteDetails.SetText("")
		return
	}

	lines := []string{
		"目标 // " + emptyFallback(site.Host, site.URL),
		"",
		"原始URL: " + emptyFallback(site.OriginalURL, "-"),
		"地址: " + emptyFallback(site.URL, "-"),
		"主机: " + site.Host,
		"域名: " + site.Domain,
		"IP: " + site.IP,
		"协议: " + site.Protocol,
		"端口: " + site.Port,
		"WAF: " + site.WAF,
		"产品: " + site.Product,
		"服务端: " + site.Server,
		"标题: " + site.Title,
		"地区: " + strings.TrimSpace(site.Country+" "+site.City),
		"请求头指纹: " + emptyFallback(site.Header, "-"),
		"最近出现: " + site.LastSeen,
	}

	if detection, ok := d.detectionForSite(*site); ok {
		lines = append(lines,
			"",
			"识别结果 //",
			"识别地址: "+emptyFallback(detection.DetectedURL, "-"),
			fmt.Sprintf("原始页状态码: %d", detection.Baseline.StatusCode),
			fmt.Sprintf("探测一相似度: %.2f", detection.SimilarityA),
			fmt.Sprintf("探测二相似度: %.2f", detection.SimilarityB),
			"变化判定: "+boolText(detection.ChangedA)+" / "+boolText(detection.ChangedB),
			"存在 WAF: "+boolText(detection.HasWAF),
		)
		if detection.HasWAF {
			lines = append(lines,
				"聚类键: "+emptyFallback(detection.ClusterKey, "-"),
				"聚类标签: "+emptyFallback(d.clusterLabelForDetection(detection), "待标注"),
				"聚类提示: "+emptyFallback(detection.ClusterHint, "-"),
			)
		} else if strings.TrimSpace(detection.ClusterHint) != "" {
			lines = append(lines, "识别说明: "+detection.ClusterHint)
		}
		if detection.Error != "" {
			lines = append(lines, "识别错误: "+detection.Error)
		}
	}

	d.siteDetails.SetText(strings.Join(lines, "\n"))
}

func (d *dashboard) updatePluginDetails() {
	if d.pluginDetails == nil {
		return
	}
	p := d.currentPlugin()
	if p == nil {
		d.pluginDetails.SetText("")
		return
	}

	headers := make([]string, 0, len(p.Headers))
	for key, value := range p.Headers {
		headers = append(headers, key+": "+value)
	}
	sort.Strings(headers)
	preflightMode := "builtin"
	if strings.TrimSpace(p.PreflightMode) != "" {
		preflightMode = strings.TrimSpace(p.PreflightMode)
	}
	preflightPrune := "默认"
	if p.PreflightPrune != nil {
		if *p.PreflightPrune {
			preflightPrune = "true"
		} else {
			preflightPrune = "false"
		}
	}

	d.pluginDetails.SetText(strings.Join([]string{
		"插件仓 // " + p.Name,
		"",
		"路径: " + p.Path,
		"协议方案: " + emptyFallback(p.Scheme, "跟随目标"),
		"标签: " + strings.Join(p.Tags, ", "),
		"预探测模式: " + preflightMode,
		"预探测删除无效URL: " + preflightPrune,
		"规则意图:\n" + pluginIntentSummary(*p),
		"方法: " + p.Method,
		"请求路径: " + p.RequestURI,
		"主机头: " + p.Host,
		"请求头:\n" + emptyFallback(strings.Join(headers, "\n"), "-"),
		"备注: " + emptyFallback(p.Notes, "-"),
		"静态检查:\n" + emptyFallback(strings.Join(p.LintWarnings, "\n"), "通过"),
		"请求体:\n" + emptyFallback(p.Body, "-"),
	}, "\n\n"))
}

func (d *dashboard) updateResultDetails() {
	if d.resultDetails == nil {
		return
	}
	r := d.currentResult()
	if r == nil {
		d.resultDetails.SetText("")
		return
	}

	d.resultDetails.SetText(strings.Join([]string{
		"分析器 // " + r.Plugin.Name,
		"",
		"站点: " + r.Site.Host,
		"判定: " + r.Verdict,
		"命中规则: " + emptyFallback(r.MatchedRule, "-"),
		func() string {
			if r.BaselineSim <= 0 && r.BlockedSim <= 0 && r.DiffRatio <= 0 {
				return "页面差异: -"
			}
			parts := []string{}
			if r.BaselineSim > 0 {
				parts = append(parts, fmt.Sprintf("与基线相似 %.2f", r.BaselineSim))
				parts = append(parts, fmt.Sprintf("差异 %.0f%%", r.DiffRatio*100))
			}
			if r.BlockedSim > 0 {
				parts = append(parts, fmt.Sprintf("与拦截页相似 %.2f", r.BlockedSim))
			}
			return "页面差异: " + strings.Join(parts, " | ")
		}(),
		"状态码: " + strconv.Itoa(r.StatusCode),
		"耗时: " + r.Duration.String(),
		"错误: " + emptyFallback(r.Error, "-"),
		"响应头:\n" + emptyFallback(r.ResponseHead, "-"),
		"响应体预览:\n" + emptyFallback(sourcePreviewText(r.ResponseBody), "-"),
	}, "\n\n"))
}

func (d *dashboard) buildClusterResultRows(clusterKey string) []clusterResultSiteDetail {
	clusterKey = strings.TrimSpace(clusterKey)
	if clusterKey == "" || len(d.bypassStatsResults) == 0 {
		return nil
	}

	rowsBySite := map[string]clusterResultSiteDetail{}
	for _, result := range d.bypassStatsResults {
		detection, ok := d.detectionForSite(result.Site)
		if !ok || !detection.HasWAF || strings.TrimSpace(detection.ClusterKey) != clusterKey {
			continue
		}

		siteKey := d.siteKey(result.Site)
		row := rowsBySite[siteKey]
		if row.SiteKey == "" {
			row = clusterResultSiteDetail{
				SiteKey:    siteKey,
				ClusterKey: clusterKey,
				Title:      emptyFallback(result.Site.Host, emptyFallback(result.Site.Domain, emptyFallback(result.Site.OriginalURL, result.Site.URL))),
				URL:        d.clusterSiteURL(result.Site),
			}
		}

		row.Attempts++
		if strings.Contains(result.Verdict, "可能绕过") {
			row.Successes++
		}

		if shouldPreferClusterResult(result, row) {
			row.RuleName = strings.TrimSpace(result.Plugin.Name)
			row.Verdict = strings.TrimSpace(result.Verdict)
			row.MatchedRule = strings.TrimSpace(result.MatchedRule)
			row.StatusCode = result.StatusCode
			row.BaselineSim = result.BaselineSim
			row.BlockedSim = result.BlockedSim
			row.DiffRatio = result.DiffRatio
			row.Passed = strings.Contains(result.Verdict, "可能绕过")
			row.ResponseHead = result.ResponseHead
			row.ResponseBody = result.ResponseBody
			row.RawResponse = testResultRawResponse(result)
			row.Snapshot = d.testResultSnapshot(result)
			if row.URL == "" {
				row.URL = emptyFallback(row.Snapshot.URL, d.clusterSiteURL(result.Site))
			}
		}

		rowsBySite[siteKey] = row
	}

	rows := make([]clusterResultSiteDetail, 0, len(rowsBySite))
	for _, row := range rowsBySite {
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Passed != rows[j].Passed {
			return !rows[i].Passed
		}
		if rows[i].BaselineSim != rows[j].BaselineSim {
			return rows[i].BaselineSim < rows[j].BaselineSim
		}
		return rows[i].Title < rows[j].Title
	})
	return rows
}

func shouldPreferClusterResult(candidate model.TestResult, current clusterResultSiteDetail) bool {
	if current.SiteKey == "" {
		return true
	}
	if strings.TrimSpace(current.RuleName) == "" && strings.TrimSpace(current.Verdict) == "" && current.StatusCode == 0 && strings.TrimSpace(current.RawResponse) == "" {
		return true
	}
	candidatePassed := strings.Contains(candidate.Verdict, "可能绕过")
	if candidatePassed != current.Passed {
		return candidatePassed
	}
	if candidate.BaselineSim != current.BaselineSim {
		return candidate.BaselineSim > current.BaselineSim
	}
	if candidate.DiffRatio != current.DiffRatio {
		return candidate.DiffRatio < current.DiffRatio
	}
	if candidate.BlockedSim != current.BlockedSim {
		return candidate.BlockedSim < current.BlockedSim
	}
	return strings.TrimSpace(candidate.Plugin.Name) < current.RuleName
}

func testResultRawResponse(result model.TestResult) string {
	parts := []string{fmt.Sprintf("HTTP/1.1 %d", result.StatusCode)}
	if head := strings.TrimSpace(result.ResponseHead); head != "" {
		parts = append(parts, head)
	}
	parts = append(parts, "", strings.TrimSpace(result.ResponseBody))
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func (d *dashboard) testResultSnapshot(result model.TestResult) model.ResponseSnapshot {
	url := d.clusterSiteURL(result.Site)
	if strings.TrimSpace(url) == "" {
		url = emptyFallback(result.Site.URL, emptyFallback(result.Site.OriginalURL, result.Site.Host))
	}
	return model.ResponseSnapshot{
		URL:        url,
		StatusCode: result.StatusCode,
		Headers:    result.ResponseHead,
		Body:       result.ResponseBody,
		Title:      result.Site.Title,
		Raw:        testResultRawResponse(result),
	}
}

func (d *dashboard) preferredClusterResultIndex(rows []clusterResultSiteDetail, previousSiteKey string) int {
	if previousSiteKey != "" {
		for i, row := range rows {
			if row.SiteKey == previousSiteKey {
				return i
			}
		}
	}
	for i, row := range rows {
		if !row.Passed {
			return i
		}
	}
	if len(rows) > 0 {
		return 0
	}
	return -1
}

func (d *dashboard) updateClusterResultDetails() {
	if d.clusterPreview == nil || d.clusterSnapshot == nil {
		return
	}
	if d.selectedClusterSite < 0 || d.selectedClusterSite >= len(d.clusterResultRows) {
		if len(d.clusterResultRows) == 0 {
			d.clusterPreview.SetText("本轮验证尚未产出该聚类的站点明细。")
		}
		return
	}

	row := d.clusterResultRows[d.selectedClusterSite]
	parts := []string{
		"站点: " + emptyFallback(row.URL, row.Title),
		"判定: " + emptyFallback(row.Verdict, "-"),
		"规则: " + emptyFallback(row.RuleName, "-"),
		"命中规则: " + emptyFallback(row.MatchedRule, "-"),
		fmt.Sprintf("相似度: 基线 %.2f | 拦截 %.2f | 差异 %.0f%%", row.BaselineSim, row.BlockedSim, row.DiffRatio*100),
		fmt.Sprintf("统计: %d/%d 命中相似度", row.Successes, row.Attempts),
		fmt.Sprintf("状态码: %d", row.StatusCode),
		"",
		"HTTP 响应原文:",
		emptyFallback(row.RawResponse, "暂无原始报文"),
	}
	d.clusterPreview.SetText(sourcePreviewText(strings.Join(parts, "\n")))
	cacheKey := "bypass-detail-" + siteKeyDigest(row.ClusterKey+"::"+row.SiteKey+"::"+row.RuleName)
	d.clusterSnapshot.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(row.Snapshot, cacheKey, false)}
	d.clusterSnapshot.Refresh()
}

func (d *dashboard) siteKey(site model.Site) string {
	if strings.TrimSpace(site.URL) != "" {
		return strings.TrimSpace(site.URL)
	}
	if strings.TrimSpace(site.Host) != "" {
		return strings.TrimSpace(site.Host)
	}
	return strings.TrimSpace(site.Domain)
}

func (d *dashboard) detectionForSite(site model.Site) (model.DetectionResult, bool) {
	item, ok := d.detections[d.siteKey(site)]
	return item, ok
}

func (d *dashboard) clusterLabelForDetection(result model.DetectionResult) string {
	if strings.TrimSpace(result.ClusterLabel) != "" {
		return result.ClusterLabel
	}
	if label := strings.TrimSpace(d.clusterLabels[result.ClusterKey]); label != "" {
		return label
	}
	if fp, ok := d.matchFingerprint(result.BlockedResponse); ok {
		return strings.TrimSpace(fp.Label)
	}
	return ""
}

func (d *dashboard) clusterLabelSource(clusterKey string, result model.DetectionResult) string {
	clusterKey = strings.TrimSpace(clusterKey)
	if clusterKey != "" {
		if source := strings.TrimSpace(d.clusterLabelSources[clusterKey]); source != "" {
			return source
		}
	}
	if strings.TrimSpace(result.ClusterLabel) != "" {
		return "manual"
	}
	if label := strings.TrimSpace(d.clusterLabels[result.ClusterKey]); label != "" {
		_ = label
		return "manual"
	}
	if fp, ok := d.matchFingerprint(result.BlockedResponse); ok && strings.TrimSpace(fp.Label) != "" {
		if source := strings.TrimSpace(fp.Source); source != "" {
			return source
		}
		return "manual"
	}
	return ""
}

func clusterLabelSourceText(source string) string {
	switch strings.TrimSpace(source) {
	case "yaml":
		return "规则识别"
	case "manual":
		return "手工标记"
	default:
		return ""
	}
}

func (d *dashboard) effectiveSiteWAF(site model.Site) string {
	if detection, ok := d.detectionForSite(site); ok {
		if label := d.clusterLabelForDetection(detection); label != "" {
			return label
		}
		if detection.HasWAF {
			return "有WAF"
		}
		return "无WAF"
	}
	value := strings.TrimSpace(site.WAF)
	if value == "" || strings.EqualFold(value, "unknown") {
		return "未识别"
	}
	return value
}

func (d *dashboard) effectiveSite(site model.Site) model.Site {
	clone := site
	clone.WAF = d.effectiveSiteWAF(site)
	return clone
}

func (d *dashboard) applyFilters() {
	if d.syncingFilter {
		return
	}
	if d.filterSelect == nil || d.filterKeywordEntry == nil {
		return
	}

	choice := d.filterSelect.Selected
	if choice == "" {
		choice = "全部"
	}
	keyword := strings.ToLower(strings.TrimSpace(d.filterKeywordEntry.Text))

	filtered := make([]model.Site, 0, len(d.sites))
	for _, site := range d.sites {
		effectiveWAF := d.effectiveSiteWAF(site)
		if choice != "全部" && effectiveWAF != choice {
			continue
		}
		if d.currentStep == 1 && d.identifyOnlyWAF && effectiveWAF != "有WAF" {
			continue
		}
		if keyword != "" {
			joined := strings.ToLower(strings.Join([]string{site.Host, site.Title, site.Domain, effectiveWAF}, " "))
			if !strings.Contains(joined, keyword) {
				continue
			}
		}
		filtered = append(filtered, site)
	}

	d.filteredSites = filtered
	if d.selectedSite >= len(d.filteredSites) {
		d.selectedSite = -1
	}
	if d.selectedCluster >= len(d.clusterViews()) {
		d.selectedCluster = -1
	}
	if d.siteList != nil {
		d.siteList.Refresh()
	}
	if d.clusterList != nil {
		d.clusterList.Refresh()
	}
	d.updateSiteDetails()
	d.updateClusterDetails()
	d.refreshDashboard()
}

func (d *dashboard) refreshWAFOptions() {
	seen := map[string]bool{"全部": true}
	options := []string{"全部"}
	for _, site := range d.sites {
		wafName := d.effectiveSiteWAF(site)
		if wafName == "" || seen[wafName] {
			continue
		}
		seen[wafName] = true
		options = append(options, wafName)
	}

	if d.filterSelect == nil {
		return
	}

	d.syncingFilter = true
	defer func() {
		d.syncingFilter = false
	}()

	current := d.filterSelect.Selected
	d.filterSelect.Options = options
	d.filterSelect.Refresh()
	if current != "" && seen[current] {
		d.filterSelect.SetSelected(current)
		return
	}
	d.filterSelect.SetSelected("全部")
}

func (d *dashboard) openSettingsDialog() {
	emailEntry := widget.NewEntry()
	emailEntry.SetText(d.cfg.FOFA.Email)

	keyEntry := widget.NewPasswordEntry()
	keyEntry.SetText(d.cfg.FOFA.APIKey)

	baseURLEntry := widget.NewEntry()
	baseURLEntry.SetText(d.cfg.FOFA.BaseURL)

	fieldsEntry := widget.NewEntry()
	fieldsEntry.SetText(strings.Join(d.cfg.FOFA.Fields, ","))

	pluginDirEntry := widget.NewEntry()
	pluginDirEntry.SetText(d.cfg.Plugin.Dir)

	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText(strconv.Itoa(d.cfg.Tester.TimeoutSeconds))

	concurrencyEntry := widget.NewEntry()
	concurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.Concurrency))

	snapshotConcurrencyEntry := widget.NewEntry()
	snapshotConcurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.SnapshotConcurrency))

	blockCodesEntry := widget.NewEntry()
	blockCodesEntry.SetText(intsToCSV(d.cfg.Tester.BlockStatusCodes))

	blockKeywordsEntry := widget.NewMultiLineEntry()
	blockKeywordsEntry.SetText(strings.Join(d.cfg.Tester.BlockKeywords, ","))

	verifyTLSCheck := widget.NewCheck("验证 TLS 证书", nil)
	verifyTLSCheck.SetChecked(d.cfg.Tester.VerifyTLS)

	form := &widget.Form{
		Items: []*widget.FormItem{
			widget.NewFormItem("FOFA 邮箱", emailEntry),
			widget.NewFormItem("FOFA 接口密钥", keyEntry),
			widget.NewFormItem("接口地址", baseURLEntry),
			widget.NewFormItem("返回字段", fieldsEntry),
			widget.NewFormItem("插件目录", pluginDirEntry),
			widget.NewFormItem("超时时间", timeoutEntry),
			widget.NewFormItem("识别并发", concurrencyEntry),
			widget.NewFormItem("快照并发", snapshotConcurrencyEntry),
			widget.NewFormItem("拦截状态码", blockCodesEntry),
			widget.NewFormItem("拦截关键字", blockKeywordsEntry),
			widget.NewFormItem("TLS 证书验证", verifyTLSCheck),
		},
	}

	formPanel := neonPanel(accentBlue, container.NewVBox(
		widget.NewLabel("请填写 FOFA、采集识别与规则验证相关配置。输入区已切换为深色高对比样式，便于阅读和录入。"),
		widget.NewSeparator(),
		form,
	))

	dialog.ShowCustomConfirm("FOFA 配置中心", "保存", "取消", formPanel, func(ok bool) {
		if !ok {
			return
		}

		timeout, _ := strconv.Atoi(strings.TrimSpace(timeoutEntry.Text))
		concurrency, _ := strconv.Atoi(strings.TrimSpace(concurrencyEntry.Text))
		snapshotConcurrency, _ := strconv.Atoi(strings.TrimSpace(snapshotConcurrencyEntry.Text))
		if concurrency <= 0 {
			concurrency = 100
		}
		if snapshotConcurrency <= 0 {
			snapshotConcurrency = 20
		}
		d.cfg.FOFA.Email = strings.TrimSpace(emailEntry.Text)
		d.cfg.FOFA.APIKey = strings.TrimSpace(keyEntry.Text)
		d.cfg.FOFA.BaseURL = strings.TrimSpace(baseURLEntry.Text)
		d.cfg.FOFA.Fields = splitCSV(fieldsEntry.Text)
		d.cfg.Plugin.Dir = strings.TrimSpace(pluginDirEntry.Text)
		d.cfg.Tester.TimeoutSeconds = timeout
		d.cfg.Tester.Concurrency = concurrency
		d.cfg.Tester.SnapshotConcurrency = snapshotConcurrency
		if d.concurrencyEntry != nil {
			d.concurrencyEntry.SetText(strconv.Itoa(concurrency))
		}
		if d.snapshotConcurrencyEntry != nil {
			d.snapshotConcurrencyEntry.SetText(strconv.Itoa(snapshotConcurrency))
		}
		d.cfg.Tester.BlockStatusCodes = csvToInts(blockCodesEntry.Text)
		d.cfg.Tester.BlockKeywords = splitCSV(blockKeywordsEntry.Text)
		d.cfg.Tester.VerifyTLS = verifyTLSCheck.Checked

		if err := config.Save(d.configPath, d.cfg); err != nil {
			dialog.ShowError(err, d.window)
			return
		}

		d.reloadPlugins()
		d.setStatus("已保存 // 配置已写入 config.json")
	}, d.window)
}

func (d *dashboard) openOpenAISettingsDialog() {
	activeProvider := widget.NewRadioGroup([]string{"OpenAI", "智谱AI"}, nil)
	activeProvider.Horizontal = true
	if strings.EqualFold(strings.TrimSpace(d.cfg.LLMProvider), "zhipu") {
		activeProvider.SetSelected("智谱AI")
	} else {
		activeProvider.SetSelected("OpenAI")
	}

	openAIKeyEntry := widget.NewPasswordEntry()
	openAIKeyEntry.SetText(d.cfg.OpenAI.APIKey)
	openAIBaseURLEntry := widget.NewEntry()
	openAIBaseURLEntry.SetText(d.cfg.OpenAI.BaseURL)
	openAIModelEntry := widget.NewEntry()
	openAIModelEntry.SetText(d.cfg.OpenAI.Model)
	openAIReasoningEntry := widget.NewEntry()
	openAIReasoningEntry.SetText(d.cfg.OpenAI.ReasoningEffort)
	openAITimeoutEntry := widget.NewEntry()
	openAITimeoutEntry.SetText(strconv.Itoa(d.cfg.OpenAI.TimeoutSeconds))

	zhipuKeyEntry := widget.NewPasswordEntry()
	zhipuKeyEntry.SetText(d.cfg.Zhipu.APIKey)
	zhipuBaseURLEntry := widget.NewEntry()
	zhipuBaseURLEntry.SetText(d.cfg.Zhipu.BaseURL)
	zhipuModelEntry := widget.NewEntry()
	zhipuModelEntry.SetText(d.cfg.Zhipu.Model)
	zhipuReasoningEntry := widget.NewEntry()
	zhipuReasoningEntry.SetText(d.cfg.Zhipu.ReasoningEffort)
	zhipuTimeoutEntry := widget.NewEntry()
	zhipuTimeoutEntry.SetText(strconv.Itoa(d.cfg.Zhipu.TimeoutSeconds))

	formPanel := neonPanel(accentPink, container.NewVBox(
		widget.NewLabel("请填写智能体使用的大模型配置。可以同时保存 OpenAI 和智谱AI 两套参数，并选择当前生效的供应商。代理统一在“配置代理”模块中维护。"),
		widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("当前启用供应商", activeProvider),
		),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("OpenAI", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("OpenAI API Key", openAIKeyEntry),
			widget.NewFormItem("OpenAI Base URL", openAIBaseURLEntry),
			widget.NewFormItem("OpenAI 模型", openAIModelEntry),
			widget.NewFormItem("OpenAI 推理强度", openAIReasoningEntry),
			widget.NewFormItem("OpenAI 超时", openAITimeoutEntry),
		),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("智谱AI", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("智谱 API Key", zhipuKeyEntry),
			widget.NewFormItem("智谱 Base URL", zhipuBaseURLEntry),
			widget.NewFormItem("智谱 模型", zhipuModelEntry),
			widget.NewFormItem("智谱 推理强度", zhipuReasoningEntry),
			widget.NewFormItem("智谱 超时", zhipuTimeoutEntry),
		),
	))

	dialog.ShowCustomConfirm("大模型配置", "保存", "取消", formPanel, func(ok bool) {
		if !ok {
			return
		}

		openAITimeout, _ := strconv.Atoi(strings.TrimSpace(openAITimeoutEntry.Text))
		if openAITimeout <= 0 {
			openAITimeout = 90
		}
		zhipuTimeout, _ := strconv.Atoi(strings.TrimSpace(zhipuTimeoutEntry.Text))
		if zhipuTimeout <= 0 {
			zhipuTimeout = 90
		}

		if activeProvider.Selected == "智谱AI" {
			d.cfg.LLMProvider = "zhipu"
			d.cfg.OpenAI.Enabled = false
			d.cfg.Zhipu.Enabled = true
		} else {
			d.cfg.LLMProvider = "openai"
			d.cfg.OpenAI.Enabled = true
			d.cfg.Zhipu.Enabled = false
		}

		d.cfg.OpenAI.APIKey = strings.TrimSpace(openAIKeyEntry.Text)
		d.cfg.OpenAI.BaseURL = strings.TrimSpace(openAIBaseURLEntry.Text)
		d.cfg.OpenAI.Model = strings.TrimSpace(openAIModelEntry.Text)
		d.cfg.OpenAI.ReasoningEffort = strings.TrimSpace(openAIReasoningEntry.Text)
		d.cfg.OpenAI.TimeoutSeconds = openAITimeout

		d.cfg.Zhipu.APIKey = strings.TrimSpace(zhipuKeyEntry.Text)
		d.cfg.Zhipu.BaseURL = strings.TrimSpace(zhipuBaseURLEntry.Text)
		d.cfg.Zhipu.Model = strings.TrimSpace(zhipuModelEntry.Text)
		d.cfg.Zhipu.ReasoningEffort = strings.TrimSpace(zhipuReasoningEntry.Text)
		d.cfg.Zhipu.TimeoutSeconds = zhipuTimeout

		if err := config.Save(d.configPath, d.cfg); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus(fmt.Sprintf("已保存 // 大模型配置已写入 config.json，当前供应商：%s", d.activeLLMProviderLabel()))
	}, d.window)
}

func (d *dashboard) refreshDashboard() {
	d.runOnUI(func() {
		summary := exporter.BuildSummary(d.results)
		if d.siteCountValue != nil {
			d.siteCountValue.Text = strconv.Itoa(d.siteTotalCount)
			d.siteCountValue.Refresh()
		}
		if d.suspectedValue != nil {
			d.suspectedValue.Text = strconv.Itoa(d.suspectedSiteCount())
			d.suspectedValue.Refresh()
		}
		if d.labeledValue != nil {
			d.labeledValue.Text = strconv.Itoa(d.labeledFingerprintCount())
			d.labeledValue.Refresh()
		}
		if d.ignoredValue != nil {
			d.ignoredValue.Text = strconv.Itoa(d.ignoredClusterCount())
			d.ignoredValue.Refresh()
		}
		if d.clusterCountValue != nil {
			clusterCount := d.totalClusterGroupCount()
			if clusterCount == 0 && d.dbState.Current.ClusterCount > 0 {
				clusterCount = d.dbState.Current.ClusterCount
			}
			d.clusterCountValue.Text = strconv.Itoa(clusterCount)
			d.clusterCountValue.Refresh()
		}
		if d.clusterDeltaValue != nil {
			d.clusterDeltaValue.Refresh()
		}
		if d.clusterSummaryLabel != nil {
			d.clusterSummaryLabel.SetText(fmt.Sprintf("共 %d 组  已标记 %d 组  已忽略 %d 组  待聚类 %d 组", d.totalClusterGroupCount(), d.labeledClusterCount(), d.ignoredClusterCount(), d.pendingClusterCount()))
		}
		if d.clusterMarkedText != nil {
			d.clusterMarkedText.Text = fmt.Sprintf("已标记 %d 组", d.labeledClusterCount())
			d.clusterMarkedText.Refresh()
		}
		if d.clusterIgnoredText != nil {
			d.clusterIgnoredText.Text = fmt.Sprintf("已忽略 %d 组", d.ignoredClusterCount())
			d.clusterIgnoredText.Refresh()
		}
		if d.clusterPendingValue != nil {
			d.clusterPendingValue.Text = strconv.Itoa(d.pendingClusterCount())
			d.clusterPendingValue.Refresh()
		}
		if d.nonWAFFingerprintText != nil {
			d.nonWAFFingerprintText.Text = fmt.Sprintf("非waf指纹 %d 个", d.unlabeledFingerprintCount())
			d.nonWAFFingerprintText.Refresh()
		}
		if d.filteredValue != nil {
			d.filteredValue.Text = strconv.Itoa(len(d.filteredSites))
			d.filteredValue.Refresh()
		}
		if d.pluginCountValue != nil {
			d.pluginCountValue.Text = strconv.Itoa(len(d.plugins))
			d.pluginCountValue.Refresh()
		}
		if d.resultCountValue != nil {
			d.resultCountValue.Text = strconv.Itoa(len(d.results))
			d.resultCountValue.Refresh()
		}
		if d.possibleValue != nil {
			d.possibleValue.Text = strconv.Itoa(d.sessionBypassCount())
			d.possibleValue.Refresh()
		}
		if d.possibleTotalValue != nil {
			d.possibleTotalValue.Text = strconv.Itoa(d.suspectedSiteCount())
			d.possibleTotalValue.Refresh()
		}
		if d.blockedValue != nil {
			d.blockedValue.Text = strconv.Itoa(summary.Blocked)
			d.blockedValue.Refresh()
		}
		if d.reviewValue != nil {
			d.reviewValue.Text = strconv.Itoa(summary.ReviewNeeded + summary.RequestErrors + summary.NoResponse)
			d.reviewValue.Refresh()
		}
		if d.topWAFValue != nil {
			top := summary.TopWAF
			if top == "暂无" || top == "" {
				top = d.topVisibleWAF()
			}
			d.topWAFValue.Text = top
			d.topWAFValue.Refresh()
		}
		if d.currentFilterInfo != nil {
			waf := d.filterSelect.Selected
			if waf == "" {
				waf = "全部"
			}
			keyword := strings.TrimSpace(d.filterKeywordEntry.Text)
			if keyword == "" {
				keyword = "-"
			}
			d.currentFilterInfo.SetText(fmt.Sprintf("筛选 // WAF=%s | 关键字=%s | 可见=%d", waf, keyword, len(d.filteredSites)))
		}
		if d.pulseLabel != nil {
			top := summary.TopWAF
			if top == "暂无" || top == "" {
				top = d.topVisibleWAF()
			}
			d.pulseLabel.SetText(fmt.Sprintf(
				"结果脉冲 // 绕过=%d | 拦截=%d | 复核=%d\n热力图 // 热点 WAF=%s | 已载入插件=%d",
				d.sessionBypassCount(),
				summary.Blocked,
				summary.ReviewNeeded+summary.RequestErrors+summary.NoResponse,
				top,
				len(d.plugins),
			))
		}
		if d.workflowList != nil {
			d.workflowList.Refresh()
		}
		if d.clusterList != nil {
			d.clusterList.Refresh()
		}
		d.syncLibraryFilterOptions()
		if d.workflowBody != nil {
			d.refreshCurrentStepView()
		}
		d.refreshCockpit()
		d.refreshRuleStatsPanel()
	})
}

func (d *dashboard) refreshDashboardCountersOnly() {
	d.runOnUI(func() {
		if d.siteCountValue != nil {
			d.siteCountValue.Text = strconv.Itoa(d.siteTotalCount)
			d.siteCountValue.Refresh()
		}
		if d.suspectedValue != nil {
			d.suspectedValue.Text = strconv.Itoa(d.suspectedSiteCount())
			d.suspectedValue.Refresh()
		}
		if d.clusterCountValue != nil {
			clusterCount := d.lightweightClusterGroupCount()
			if clusterCount == 0 && d.dbState.Current.ClusterCount > 0 {
				clusterCount = d.dbState.Current.ClusterCount
			}
			d.clusterCountValue.Text = strconv.Itoa(clusterCount)
			d.clusterCountValue.Refresh()
		}
		if d.resultCountValue != nil {
			d.resultCountValue.Text = strconv.Itoa(len(d.results))
			d.resultCountValue.Refresh()
		}
		if d.possibleValue != nil {
			d.possibleValue.Text = strconv.Itoa(d.sessionBypassCount())
			d.possibleValue.Refresh()
		}
		if d.possibleTotalValue != nil {
			d.possibleTotalValue.Text = strconv.Itoa(d.suspectedSiteCount())
			d.possibleTotalValue.Refresh()
		}
	})
}

func clampFOFASize(size int) int {
	if size <= 0 {
		return 2000
	}
	if size > config.MaxFOFASize {
		return config.MaxFOFASize
	}
	return size
}

func sanitizeFOFASizeInput(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	filtered := strings.Builder{}
	for _, r := range value {
		if r >= '0' && r <= '9' {
			filtered.WriteRune(r)
		}
	}
	clean := filtered.String()
	if clean == "" {
		return ""
	}
	size, err := strconv.Atoi(clean)
	if err != nil || size <= 0 {
		return "1"
	}
	return strconv.Itoa(clampFOFASize(size))
}

func sanitizePipelineCountInput(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	filtered := strings.Builder{}
	for _, r := range value {
		if r >= '0' && r <= '9' {
			filtered.WriteRune(r)
		}
	}
	clean := filtered.String()
	if clean == "" {
		return ""
	}
	count, err := strconv.Atoi(clean)
	if err != nil || count <= 0 {
		return "1"
	}
	if count > 100 {
		count = 100
	}
	return strconv.Itoa(count)
}

func (d *dashboard) currentPipelineCount() int {
	if d.pipelineCountEntry == nil {
		return 1
	}
	value := sanitizePipelineCountInput(d.pipelineCountEntry.Text)
	if value == "" {
		value = "1"
	}
	if value != d.pipelineCountEntry.Text {
		d.pipelineCountEntry.SetText(value)
	}
	count, err := strconv.Atoi(value)
	if err != nil || count <= 0 {
		return 1
	}
	return count
}

func (d *dashboard) pipelineRoundText() string {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	if !d.pipelineRunning || d.pipelineSampleCount <= 0 {
		return ""
	}
	if d.pipelineCurrentRun <= 0 {
		return fmt.Sprintf("×%d", d.pipelineSampleCount)
	}
	return fmt.Sprintf("×%d 第%d/%d轮", d.pipelineSampleCount, d.pipelineCurrentRun, d.pipelineSampleCount)
}

func (d *dashboard) pipelineRoundStatusText() string {
	d.detectMu.Lock()
	defer d.detectMu.Unlock()
	if !d.pipelineRunning || d.pipelineSampleCount <= 0 || d.pipelineCurrentRun <= 0 {
		return ""
	}
	return fmt.Sprintf("第 %d/%d 轮", d.pipelineCurrentRun, d.pipelineSampleCount)
}

func (d *dashboard) setMetricDelta(label *canvas.Text, delta int) {
	d.runOnUI(func() {
		if label == nil {
			return
		}
		if delta <= 0 {
			if delta == 0 {
				label.Text = ""
			} else {
				label.Text = fmt.Sprintf("%d", delta)
			}
		} else {
			label.Text = fmt.Sprintf("+%d", delta)
		}
		switch label {
		case d.suspectedDeltaValue:
			if delta < 0 {
				label.Color = color.NRGBA{R: 255, G: 143, B: 92, A: 235}
			} else {
				label.Color = color.NRGBA{R: 255, G: 196, B: 118, A: 210}
			}
		case d.clusterDeltaValue:
			if delta < 0 {
				label.Color = color.NRGBA{R: 255, G: 120, B: 120, A: 235}
			} else {
				label.Color = accentGreen
			}
		case d.siteDeltaValue:
			if delta < 0 {
				label.Color = color.NRGBA{R: 255, G: 120, B: 120, A: 235}
			} else {
				label.Color = accentCyan
			}
		case d.labeledDeltaValue:
			if delta < 0 {
				label.Color = color.NRGBA{R: 255, G: 120, B: 120, A: 235}
			} else {
				label.Color = accentPink
			}
		default:
			if delta < 0 {
				label.Color = color.NRGBA{R: 255, G: 120, B: 120, A: 235}
			}
		}
		label.Refresh()
	})
}

func (d *dashboard) currentDetectConcurrency() int {
	if d.concurrencyEntry == nil {
		if d.cfg.Tester.Concurrency > 0 {
			return d.cfg.Tester.Concurrency
		}
		return 100
	}

	value, err := strconv.Atoi(strings.TrimSpace(d.concurrencyEntry.Text))
	if err != nil || value <= 0 {
		value = 100
		d.concurrencyEntry.SetText("100")
	}
	d.cfg.Tester.Concurrency = value
	return value
}

func (d *dashboard) currentSnapshotConcurrency() int {
	if d.snapshotConcurrencyEntry == nil {
		if d.cfg.Tester.SnapshotConcurrency > 0 {
			return d.cfg.Tester.SnapshotConcurrency
		}
		return 20
	}

	value, err := strconv.Atoi(strings.TrimSpace(d.snapshotConcurrencyEntry.Text))
	if err != nil || value <= 0 {
		value = 20
		d.snapshotConcurrencyEntry.SetText("20")
	}
	d.cfg.Tester.SnapshotConcurrency = value
	return value
}

func (d *dashboard) fastValidationTesterSettings() model.TesterSettings {
	settings := d.cfg.Tester
	settings.Concurrency = d.currentDetectConcurrency()
	settings.TimeoutSeconds = 1
	return settings
}

func (d *dashboard) refreshCockpit() {
	site := d.currentSite()
	plugin := d.currentPlugin()
	result := d.currentResult()
	clusterName := "未选中聚类"
	if clusters := d.clusterViews(); d.selectedCluster >= 0 && d.selectedCluster < len(clusters) {
		cluster := clusters[d.selectedCluster]
		clusterName = emptyFallback(cluster.Label, cluster.Signature)
	}

	siteName := "未选中目标"
	wafName := "未锁定"
	if site != nil {
		siteName = emptyFallback(site.Host, site.URL)
		wafName = d.effectiveSiteWAF(*site)
	}

	pluginName := "未选中插件"
	if plugin != nil {
		pluginName = plugin.Name
	}

	verdict := "暂无结果"
	if result != nil {
		verdict = result.Verdict
	}

	if d.cockpitLabel != nil {
		d.cockpitLabel.SetText(strings.Join([]string{
			"赛道 // " + siteName,
			"聚类 // " + clusterName,
			"WAF // " + wafName,
			"插件 // " + pluginName,
			"判定 // " + verdict,
		}, "\n"))
	}
	if d.selectionLabel != nil {
		d.selectionLabel.SetText(fmt.Sprintf("锁定 // %s | %s | %s", wafName, pluginName, verdict))
	}
	if d.footerTrackLabel != nil {
		d.footerTrackLabel.SetText(fmt.Sprintf("赛道 // %s | %s | %s", siteName, pluginName, verdict))
	}
}

func (d *dashboard) refreshClusterMetrics() {
	clusterCount := d.totalClusterGroupCount()
	labeledCount := d.labeledClusterCount()
	ignoredCount := d.ignoredClusterCount()
	pendingCount := clusterCount - labeledCount - ignoredCount
	if pendingCount < 0 {
		pendingCount = 0
	}
	if d.labeledValue != nil {
		d.labeledValue.Text = strconv.Itoa(d.labeledFingerprintCount())
		d.labeledValue.Refresh()
	}
	if d.labeledDeltaValue != nil {
		delta := d.labeledFingerprintCount() - d.fingerprintBaseCount
		if delta < 0 {
			delta = 0
		}
		d.setMetricDelta(d.labeledDeltaValue, delta)
	}
	if d.clusterCountValue != nil {
		if clusterCount == 0 && d.dbState.Current.ClusterCount > 0 {
			clusterCount = d.dbState.Current.ClusterCount
		}
		d.clusterCountValue.Text = strconv.Itoa(clusterCount)
		d.clusterCountValue.Refresh()
	}
	if d.clusterSummaryLabel != nil {
		d.clusterSummaryLabel.SetText(fmt.Sprintf("共 %d 组  已标记 %d 组  已忽略 %d 组  待聚类 %d 组", clusterCount, labeledCount, ignoredCount, pendingCount))
	}
	if d.clusterMarkedText != nil {
		d.clusterMarkedText.Text = fmt.Sprintf("已标记 %d 组", labeledCount)
		d.clusterMarkedText.Refresh()
	}
	if d.clusterIgnoredText != nil {
		d.clusterIgnoredText.Text = fmt.Sprintf("已忽略 %d 组", ignoredCount)
		d.clusterIgnoredText.Refresh()
	}
	if d.clusterPendingValue != nil {
		d.clusterPendingValue.Text = strconv.Itoa(pendingCount)
		d.clusterPendingValue.Refresh()
	}
	if d.nonWAFFingerprintText != nil {
		d.nonWAFFingerprintText.Text = fmt.Sprintf("非waf指纹 %d 个", d.unlabeledFingerprintCount())
		d.nonWAFFingerprintText.Refresh()
	}
}

func (d *dashboard) currentSite() *model.Site {
	if d.selectedSite < 0 || d.selectedSite >= len(d.filteredSites) {
		return nil
	}
	return &d.filteredSites[d.selectedSite]
}

func (d *dashboard) currentPlugin() *model.Plugin {
	if d.selectedPlugin < 0 || d.selectedPlugin >= len(d.plugins) {
		return nil
	}
	return &d.plugins[d.selectedPlugin]
}

func (d *dashboard) currentResult() *model.TestResult {
	if d.selectedResult < 0 || d.selectedResult >= len(d.results) {
		return nil
	}
	return &d.results[d.selectedResult]
}

func (d *dashboard) suspectedTargets() ([]model.Site, []model.DetectionResult) {
	sites := make([]model.Site, 0, len(d.detections))
	detectionItems := make([]model.DetectionResult, 0, len(d.detections))
	if len(d.detections) == 0 {
		return sites, detectionItems
	}

	keys := make([]string, 0, len(d.detections))
	for key := range d.detections {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	seen := map[string]bool{}
	for _, key := range keys {
		detection := d.detections[key]
		if !detection.HasWAF {
			continue
		}
		site := d.effectiveSite(detection.Site)
		siteKey := d.siteKey(site)
		if siteKey == "" {
			siteKey = key
		}
		if seen[siteKey] {
			continue
		}
		seen[siteKey] = true
		sites = append(sites, site)
		detectionItems = append(detectionItems, detection)
	}
	return sites, detectionItems
}

func (d *dashboard) setStatus(message string) {
	d.runOnUI(func() {
		if d.statusText == nil {
			return
		}
		d.statusText.Text = message
		d.statusText.Color = statusColor(message)
		d.statusText.Refresh()
	})
}

func (d *dashboard) workspaceRootDir() string {
	configPath := strings.TrimSpace(d.configPath)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return "."
	}
	return filepath.Dir(absPath)
}

func (d *dashboard) resolveWorkspacePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(d.workspaceRootDir(), path)
}

func (d *dashboard) workspaceBundlePaths() exporter.WorkspaceBundlePaths {
	configPath := strings.TrimSpace(d.configPath)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	dbPath := d.resolveWorkspacePath(d.cfg.App.DatabasePath)
	return exporter.WorkspaceBundlePaths{
		ConfigPath:        d.resolveWorkspacePath(configPath),
		WAFYAMLPath:       filepath.Join(d.workspaceRootDir(), "waf.yaml"),
		DatabasePath:      dbPath,
		StartupCachePath:  dbPath + ".startup.json",
		PluginDir:         d.resolveWorkspacePath(d.cfg.Plugin.Dir),
		DiagnosticLogPath: filepath.Join(d.workspaceRootDir(), "data", "rule_validation_diagnostics.log"),
		ProxyCertPath:     d.downstreamCertAbsPath(),
		ProxyKeyPath:      d.downstreamKeyAbsPath(),
	}
}

func (d *dashboard) syncConfigFromControls() {
	if d.queryEntry != nil {
		d.cfg.FOFA.Query = strings.TrimSpace(d.queryEntry.Text)
	}
	if d.sizeEntry != nil {
		d.cfg.FOFA.Size = sanitizeFOFASizeValue(d.sizeEntry.Text, d.cfg.FOFA.Size)
	}
	if d.concurrencyEntry != nil {
		d.cfg.Tester.Concurrency = sanitizePositiveIntValue(d.concurrencyEntry.Text, d.cfg.Tester.Concurrency)
	}
	if d.snapshotConcurrencyEntry != nil {
		d.cfg.Tester.SnapshotConcurrency = sanitizePositiveIntValue(d.snapshotConcurrencyEntry.Text, d.cfg.Tester.SnapshotConcurrency)
	}
}

func sanitizeFOFASizeValue(value string, fallback int) int {
	sanitized := sanitizeFOFASizeInput(value)
	if number, err := strconv.Atoi(strings.TrimSpace(sanitized)); err == nil && number > 0 {
		return number
	}
	if fallback > 0 {
		return fallback
	}
	return config.Default().FOFA.Size
}

func sanitizePositiveIntValue(value string, fallback int) int {
	if number, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && number > 0 {
		return number
	}
	if fallback > 0 {
		return fallback
	}
	return 1
}

func (d *dashboard) exportWorkspaceBundle() {
	d.syncConfigFromControls()
	configPath := strings.TrimSpace(d.configPath)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	if err := config.Save(configPath, d.cfg); err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 导出工作区失败")
		return
	}
	d.configPath = configPath

	manifest := exporter.WorkspaceBundleManifest{
		GeneratedAt:      time.Now(),
		SiteCount:        d.siteTotalCount,
		DetectionCount:   len(d.detections),
		ResultCount:      len(d.results),
		PluginCount:      len(d.plugins),
		FingerprintCount: d.labeledFingerprintCount(),
	}
	filename := fmt.Sprintf("wafbps运行数据-%s.zip", time.Now().Format("20060102-150405"))
	path := filepath.Join(d.workspaceRootDir(), filename)
	paths := d.workspaceBundlePaths()
	virtualFiles, err := d.workspaceBundleVirtualFiles()
	if err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 导出工作区失败")
		return
	}
	paths.VirtualFiles = virtualFiles
	d.resetConsole("运行数据导出", "准备导出当前运行数据")
	d.setConsoleStatus("导出准备中...")
	d.setConsoleProgress(0, 1)
	d.setStatus("导出中 // 正在打包当前运行数据")
	go func() {
		lastLogged := 0
		err := exporter.ExportWorkspaceBundle(path, paths, manifest, func(progress exporter.WorkspaceBundleProgress) {
			entryLabel := strings.TrimSpace(progress.EntryName)
			if entryLabel == "" {
				entryLabel = "bundle"
			}
			d.setConsoleStatus(fmt.Sprintf("导出进行中... %d/%d | %s", progress.Current, progress.Total, entryLabel))
			d.setConsoleProgress(progress.Current, progress.Total)
			if progress.Current == 1 || progress.Current == progress.Total || progress.Current-lastLogged >= 3 {
				lastLogged = progress.Current
				d.appendConsoleLog(fmt.Sprintf("[export %d/%d] 已写入 %s", progress.Current, progress.Total, entryLabel))
			}
		})
		if err != nil {
			d.runOnUI(func() {
				dialog.ShowError(err, d.window)
			})
			d.setConsoleStatus("导出失败")
			d.setStatus("错误 // 导出工作区失败")
			d.appendConsoleLog("[error] 导出工作区失败: " + err.Error())
			return
		}
		d.setConsoleStatus("导出完成")
		d.setConsoleProgress(1, 1)
		d.appendConsoleLog(fmt.Sprintf("[done] 运行数据导出完成 | 文件=%s", path))
		d.setStatus(fmt.Sprintf("已保存 // %s", path))
		d.runOnUI(func() {
			dialog.ShowInformation("导出完成", fmt.Sprintf("运行数据已导出到:\n%s", path), d.window)
		})
	}()
}

func (d *dashboard) createSafetyBackup(reason string) (string, error) {
	d.syncConfigFromControls()
	configPath := strings.TrimSpace(d.configPath)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	if err := config.Save(configPath, d.cfg); err != nil {
		return "", err
	}
	d.configPath = configPath

	manifest := exporter.WorkspaceBundleManifest{
		GeneratedAt:      time.Now(),
		SiteCount:        d.siteTotalCount,
		DetectionCount:   len(d.detections),
		ResultCount:      len(d.results),
		PluginCount:      len(d.plugins),
		FingerprintCount: d.labeledFingerprintCount(),
	}
	paths := d.workspaceBundlePaths()
	virtualFiles, err := d.workspaceBundleVirtualFiles()
	if err != nil {
		return "", err
	}
	paths.VirtualFiles = virtualFiles

	safeReason := strings.TrimSpace(strings.ToLower(reason))
	if safeReason == "" {
		safeReason = "manual"
	}
	safeReason = strings.ReplaceAll(safeReason, " ", "-")
	var builder strings.Builder
	for _, r := range safeReason {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		}
	}
	safeReason = strings.Trim(builder.String(), "-_")
	if safeReason == "" {
		safeReason = "manual"
	}

	filename := fmt.Sprintf("waf工作区备份-%s-%s.zip", safeReason, time.Now().Format("20060102-150405"))
	path := filepath.Join("备份", filename)
	if err := exporter.ExportWorkspaceBundle(path, paths, manifest, nil); err != nil {
		return "", err
	}
	return path, nil
}

func (d *dashboard) resetDatabaseStateWithBackup() (string, error) {
	backupPath, err := d.createSafetyBackup("reset")
	if err != nil {
		return "", err
	}
	if err := d.resetDatabaseState(); err != nil {
		return "", err
	}
	return backupPath, nil
}

func (d *dashboard) workspaceBundleVirtualFiles() (map[string][]byte, error) {
	dbSnapshot := d.dbState
	if dbSnapshot.Version <= 0 {
		dbSnapshot.Version = store.CurrentVersion
	}
	now := time.Now()
	if dbSnapshot.CreatedAt.IsZero() {
		dbSnapshot.CreatedAt = now
	}
	dbSnapshot.UpdatedAt = now
	d.snapshotMu.Lock()
	clusterSnapshots := cloneStringMap(d.clusterSnapshots)
	d.snapshotMu.Unlock()
	dbSnapshot.Current = store.Snapshot{
		Sites:               []model.Site{},
		SiteKeys:            sortedSiteKeys(d.seenSiteKeys),
		Detections:          cloneDetections(d.detections),
		ClusterLabels:       cloneStringMap(d.clusterLabels),
		ClusterLabelSources: cloneStringMap(d.clusterLabelSources),
		ClusterRuleDetails:  cloneStringMap(d.clusterRuleDetails),
		ClusterBaseline:     append([]store.ClusterBaselineItem(nil), d.clusterBaseline...),
		ClusterSnapshots:    clusterSnapshots,
		IgnoredClusters:     cloneBoolMap(d.ignoredClusters),
		ClusterCount:        d.totalClusterGroupCount(),
		Results:             append([]model.TestResult(nil), d.results...),
	}
	dbSnapshot.Fingerprints = d.fingerprintSnapshot()
	dbSnapshot.UsedSamples = d.cloneUsedSampleWords()

	dbData, err := json.MarshalIndent(dbSnapshot, "", "  ")
	if err != nil {
		return nil, err
	}
	startupData, err := json.Marshal(d.buildStartupCache())
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"database.json":      dbData,
		"startup_cache.json": startupData,
	}, nil
}

func (d *dashboard) hasRunningJobs() bool {
	return d.searchRunning ||
		d.detectRunning ||
		d.clusterRunning ||
		d.fingerprintRunning ||
		d.ruleValidationRunning ||
		d.pipelineRunning
}

func (d *dashboard) openImportWorkspaceDialog() {
	if d.hasRunningJobs() {
		dialog.ShowInformation("请先停止任务", "导入工作区前，请先停止当前正在运行的采集、识别、聚类或规则验证任务。", d.window)
		return
	}

	fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		if reader == nil {
			return
		}
		uri := reader.URI()
		_ = reader.Close()
		if uri == nil {
			dialog.ShowInformation("选择导入包", "未读取到可用的导入文件。", d.window)
			return
		}
		d.importWorkspaceBundle(uri.Path())
	}, d.window)
	fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".zip"}))
	fileDialog.Show()
}

func (d *dashboard) importWorkspaceBundle(bundlePath string) {
	bundlePath = strings.TrimSpace(bundlePath)
	if bundlePath == "" {
		return
	}
	d.setStatus("导入中 // 正在备份当前工作区")
	go func() {
		backupPath, err := d.createSafetyBackup("import")
		if err != nil {
			d.runOnUI(func() {
				dialog.ShowError(fmt.Errorf("导入前自动备份失败: %w", err), d.window)
			})
			d.setStatus("错误 // 导入前自动备份失败")
			return
		}
		d.setStatus("导入中 // 备份完成，正在导入工作区数据包")
		manifest, _, err := exporter.ImportWorkspaceBundle(bundlePath, strings.TrimSpace(emptyFallback(d.configPath, config.DefaultConfigPath)))
		if err != nil {
			d.runOnUI(func() {
				dialog.ShowError(err, d.window)
			})
			d.setStatus("错误 // 导入工作区失败")
			return
		}
		if err := d.reloadWorkspaceFromDisk(); err != nil {
			d.runOnUI(func() {
				dialog.ShowError(err, d.window)
			})
			d.setStatus("错误 // 导入后刷新失败")
			return
		}
		d.runOnUI(func() {
			dialog.ShowInformation("导入完成", fmt.Sprintf("工作区导入完成。\n站点 %d 条 / 识别 %d 条 / 结果 %d 条 / 规则 %d 条\n\n导入前备份已保存到:\n%s", manifest.SiteCount, manifest.DetectionCount, manifest.ResultCount, manifest.PluginCount, backupPath), d.window)
		})
	}()
}

func (d *dashboard) reloadWorkspaceFromDisk() error {
	configPath := strings.TrimSpace(d.configPath)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	db := store.New(cfg.App.DatabasePath)
	dbState, err := db.Load()
	if err != nil {
		return err
	}
	plugins, err := plugin.Load(cfg.Plugin.Dir)
	if err != nil {
		return err
	}

	d.cfg = cfg
	d.configPath = configPath
	d.db = db
	d.dbState = dbState
	d.yamlMatchers = loadWAFYAMLMatchers("waf.yaml")
	d.plugins = plugins
	d.selectedSite = -1
	d.selectedCluster = -1
	d.selectedResult = -1
	d.selectedPlugin = -1
	d.selectedBypassCluster = -1
	d.selectedClusterSite = -1
	d.restoreDatabaseStateFast()

	d.runOnUI(func() {
		if d.queryEntry != nil {
			d.queryEntry.SetText(d.cfg.FOFA.Query)
		}
		if d.sizeEntry != nil {
			d.sizeEntry.SetText(strconv.Itoa(d.cfg.FOFA.Size))
		}
		if d.concurrencyEntry != nil {
			d.concurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.Concurrency))
		}
		if d.snapshotConcurrencyEntry != nil {
			d.snapshotConcurrencyEntry.SetText(strconv.Itoa(d.cfg.Tester.SnapshotConcurrency))
		}
		if d.siteList != nil {
			d.siteList.UnselectAll()
			d.siteList.Refresh()
		}
		if d.clusterList != nil {
			d.clusterList.UnselectAll()
			d.clusterList.Refresh()
		}
		if d.pluginList != nil {
			d.pluginList.UnselectAll()
			d.pluginList.Refresh()
		}
		if d.resultList != nil {
			d.resultList.UnselectAll()
			d.resultList.Refresh()
		}
		d.refreshCurrentStepView()
	})

	d.updateBypassStatsRows(nil, "")
	d.refreshWAFOptions()
	d.applyFilters()
	d.updateSiteDetails()
	d.updateClusterDetails()
	d.updateResultDetails()
	d.refreshDashboard()
	d.refreshRuleStatsPanel()
	d.refreshCockpit()
	d.setStatus(fmt.Sprintf("导入完成 // 已恢复 %d 条站点、%d 条识别、%d 条结果、%d 条规则", d.siteTotalCount, len(d.detections), len(d.results), len(d.plugins)))
	return nil
}

func (d *dashboard) exportResults(format string) {
	if len(d.results) == 0 {
		dialog.ShowInformation("没有结果", "当前还没有测试结果可以导出。", d.window)
		return
	}

	filename := fmt.Sprintf("waf测试报告-%s.%s", time.Now().Format("20060102-150405"), format)
	path := filepath.Join("导出报告", filename)

	var err error
	switch strings.ToLower(format) {
	case "json":
		err = exporter.ExportJSON(path, d.results)
	case "html":
		err = exporter.ExportHTML(path, d.results)
	default:
		err = fmt.Errorf("不支持的导出格式: %s", format)
	}
	if err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 导出失败")
		return
	}

	dialog.ShowInformation("导出完成", fmt.Sprintf("报告已导出到:\n%s", path), d.window)
	d.setStatus(fmt.Sprintf("已保存 // %s", path))
}

func (d *dashboard) exportCurrentPlugin() {
	p := d.currentPlugin()
	if p == nil {
		dialog.ShowInformation("选择规则", "请先在规则树中选择一条 HTTP 规则。", d.window)
		return
	}

	data, err := os.ReadFile(p.Path)
	if err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 规则导出失败")
		return
	}

	filename := fmt.Sprintf("规则-%s-%s.http", time.Now().Format("20060102-150405"), filepath.Base(p.Path))
	path := filepath.Join("导出报告", filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 规则导出失败")
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		dialog.ShowError(err, d.window)
		d.setStatus("错误 // 规则导出失败")
		return
	}

	dialog.ShowInformation("导出完成", fmt.Sprintf("规则已导出到:\n%s", path), d.window)
	d.setStatus(fmt.Sprintf("已保存 // %s", path))
}

func (d *dashboard) topVisibleWAF() string {
	counts := map[string]int{}
	for _, site := range d.filteredSites {
		key := strings.TrimSpace(d.effectiveSiteWAF(site))
		if key == "" || key == "未识别" {
			key = "未知"
		}
		counts[key]++
	}

	bestKey := "暂无"
	bestCount := 0
	for key, count := range counts {
		if count > bestCount || (count == bestCount && key < bestKey) {
			bestKey = key
			bestCount = count
		}
	}
	return bestKey
}

func boolText(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func normalizeFOFAQuery(query string, chinaOnly bool) string {
	query = strings.TrimSpace(query)
	if query == "" {
		query = `(port="80" || port="443")`
	}

	base := query
	lower := strings.ToLower(query)
	hasFieldSyntax := strings.ContainsAny(query, `=:"`) ||
		strings.Contains(lower, "body=") ||
		strings.Contains(lower, "title=") ||
		strings.Contains(lower, "domain=") ||
		strings.Contains(lower, "host=") ||
		strings.Contains(lower, "port=") ||
		strings.Contains(lower, "country=") ||
		strings.Contains(lower, "server=") ||
		strings.Contains(lower, "header=") ||
		strings.Contains(lower, "&&") ||
		strings.Contains(lower, "||")
	if !hasFieldSyntax {
		escaped := strings.ReplaceAll(query, `"`, `\"`)
		base = fmt.Sprintf(`body="%s"`, escaped)
	}

	has80 := strings.Contains(lower, "port=80") || strings.Contains(lower, `port="80"`)
	has443 := strings.Contains(lower, "port=443") || strings.Contains(lower, `port="443"`)

	switch {
	case has80 && has443:
		query = base
	case has80 || has443:
		query = base
	default:
		if strings.TrimSpace(base) == "" {
			query = `(port="80" || port="443")`
		} else {
			query = "(" + base + `) && (port="80" || port="443")`
		}
	}

	if chinaOnly {
		if strings.Contains(query, "||") && !(strings.HasPrefix(query, "(") && strings.HasSuffix(query, ")")) {
			query = "(" + query + ")"
		}
		lower = strings.ToLower(query)
		if !(strings.Contains(lower, `country="cn"`) || strings.Contains(lower, "country=cn")) {
			query += ` && country="CN"`
			lower = strings.ToLower(query)
		}
		if !strings.Contains(lower, `region!="hk"`) {
			query += ` && region!="HK"`
			lower = strings.ToLower(query)
		}
		if !strings.Contains(lower, `region!="tw"`) {
			query += ` && region!="TW"`
		}
	}

	return query
}

func (d *dashboard) chinaOnlyEnabled() bool {
	return d.chinaOnlyCheck != nil && d.chinaOnlyCheck.Checked
}

func (d *dashboard) needsFOFAConfig() bool {
	email := strings.TrimSpace(d.cfg.FOFA.Email)
	key := strings.TrimSpace(d.cfg.FOFA.APIKey)
	if email == "" || key == "" {
		return true
	}
	if strings.Contains(email, "your-fofa-email") || strings.Contains(key, "replace-with-your-fofa-key") {
		return true
	}
	return false
}

func (d *dashboard) shouldPromptFOFAConfig(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "missing fofa email or api key") ||
		strings.Contains(message, "账号") ||
		strings.Contains(message, "invalid") ||
		strings.Contains(message, "fofa error") ||
		strings.Contains(message, "key") ||
		strings.Contains(message, "email")
}

func (d *dashboard) refreshCurrentStepView() {
	if d.workflowBody == nil {
		return
	}
	d.workflowBody.Objects = []fyne.CanvasObject{d.buildCurrentStep()}
	d.workflowBody.Refresh()
}

func (d *dashboard) gotoStep(step int) {
	steps := workflowSteps()
	if step < 0 || step >= len(steps) {
		return
	}
	if step == 5 {
		if d.workflowList != nil && d.currentStep >= 0 && d.currentStep < len(steps) {
			d.workflowList.Select(d.currentStep)
		}
		d.openProxySettingsDialog()
		return
	}

	d.currentStep = step
	d.refreshCurrentStepView()
	d.applyFilters()
}

func (d *dashboard) restoreDatabaseStateFast() int {
	d.sites = nil
	d.filteredSites = nil
	d.seenSiteKeys = make(map[string]bool, len(d.dbState.Current.SiteKeys))
	for _, key := range d.dbState.Current.SiteKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		d.seenSiteKeys[key] = true
	}
	d.siteTotalCount = len(d.seenSiteKeys)
	if d.siteTotalCount == 0 && len(d.dbState.Scans) > 0 {
		d.siteTotalCount = d.dbState.Scans[len(d.dbState.Scans)-1].SiteCount
	}
	d.detections = cloneDetections(d.dbState.Current.Detections)
	d.clusterLabels = cloneStringMap(d.dbState.Current.ClusterLabels)
	d.clusterLabelSources = cloneStringMap(d.dbState.Current.ClusterLabelSources)
	d.clusterRuleDetails = cloneStringMap(d.dbState.Current.ClusterRuleDetails)
	d.clusterBaseline = append([]store.ClusterBaselineItem(nil), d.dbState.Current.ClusterBaseline...)
	d.rebuildClusterMembers()
	d.clusterSnapshots = cloneStringMap(d.dbState.Current.ClusterSnapshots)
	d.snapshotPresence = make(map[string]bool, len(d.clusterSnapshots))
	for key, value := range d.clusterSnapshots {
		d.snapshotPresence[key] = strings.TrimSpace(value) != ""
	}
	d.recentClusters = map[string]bool{}
	d.ignoredClusters = cloneBoolMap(d.dbState.Current.IgnoredClusters)
	d.fingerprintMu.Lock()
	d.fingerprints = cloneFingerprints(d.dbState.Fingerprints)
	fingerprintCount := len(d.fingerprints)
	d.fingerprintMu.Unlock()
	d.sampleWordMu.Lock()
	d.usedSampleWords = cloneBoolMap(d.dbState.UsedSamples)
	d.sampleWordMu.Unlock()
	d.results = append([]model.TestResult(nil), d.dbState.Current.Results...)
	d.bypassStatsResults = nil
	d.sessionBypassSites = map[string]bool{}
	d.sessionBypassResults = map[string]model.TestResult{}
	d.fingerprintBaseCount = d.labeledFingerprintCount()
	d.setMetricDelta(d.siteDeltaValue, 0)
	d.setMetricDelta(d.labeledDeltaValue, 0)
	d.setMetricDelta(d.suspectedDeltaValue, 0)
	d.setMetricDelta(d.clusterDeltaValue, 0)
	if len(d.dbState.Scans) > 0 {
		d.currentScanID = d.dbState.Scans[len(d.dbState.Scans)-1].ID
	}
	return fingerprintCount
}

func (d *dashboard) finishBootstrapRestore() {
	applied := d.applyWAFYAMLMatches()
	fingerprintCount := len(d.fingerprintSnapshot())
	for key, label := range d.clusterLabels {
		if strings.TrimSpace(label) == "" {
			continue
		}
		if strings.TrimSpace(d.clusterLabelSources[key]) == "" {
			d.clusterLabelSources[key] = "manual"
		}
	}
	for key, source := range d.clusterLabelSources {
		if strings.TrimSpace(source) == "" || strings.TrimSpace(d.clusterLabels[key]) != "" {
			continue
		}
		delete(d.clusterLabelSources, key)
	}
	d.updateBypassStatsRows(nil, "")
	if d.siteTotalCount > 0 || len(d.detections) > 0 || len(d.results) > 0 || fingerprintCount > 0 {
		status := fmt.Sprintf("数据库 // 已恢复 %d 条站点、%d 条识别、%d 条结果、%d 条指纹", d.siteTotalCount, len(d.detections), len(d.results), fingerprintCount)
		if applied > 0 {
			status += fmt.Sprintf("，waf.yaml 自动识别 %d 组", applied)
		}
		d.setStatus(status)
	}
	d.runOnUI(func() {
		d.refreshWAFOptions()
		d.applyFilters()
		d.refreshCockpit()
	})
}

func (d *dashboard) persistDatabase() {
	if d.db == nil {
		return
	}
	d.snapshotMu.Lock()
	clusterSnapshots := cloneStringMap(d.clusterSnapshots)
	d.snapshotMu.Unlock()
	ignoredClusters := cloneBoolMap(d.ignoredClusters)
	d.dbState.Current = store.Snapshot{
		Sites:               []model.Site{},
		SiteKeys:            sortedSiteKeys(d.seenSiteKeys),
		Detections:          cloneDetections(d.detections),
		ClusterLabels:       cloneStringMap(d.clusterLabels),
		ClusterLabelSources: cloneStringMap(d.clusterLabelSources),
		ClusterRuleDetails:  cloneStringMap(d.clusterRuleDetails),
		ClusterBaseline:     append([]store.ClusterBaselineItem(nil), d.clusterBaseline...),
		ClusterSnapshots:    clusterSnapshots,
		IgnoredClusters:     ignoredClusters,
		ClusterCount:        d.totalClusterGroupCount(),
		Results:             append([]model.TestResult(nil), d.results...),
	}
	d.dbState.Fingerprints = d.fingerprintSnapshot()
	d.dbState.UsedSamples = d.cloneUsedSampleWords()
	_ = d.db.Save(d.dbState)
	_ = d.db.SaveStartupCache(d.buildStartupCache())
}

func (d *dashboard) persistCurrentDBStateAsync() {
	if d.db == nil {
		return
	}
	dbCopy := d.dbState
	dbCopy.Current.Sites = []model.Site{}
	dbCopy.Current.SiteKeys = sortedSiteKeys(d.seenSiteKeys)
	dbCopy.Current.Detections = cloneDetections(d.dbState.Current.Detections)
	dbCopy.Current.ClusterLabels = cloneStringMap(d.dbState.Current.ClusterLabels)
	dbCopy.Current.ClusterLabelSources = cloneStringMap(d.dbState.Current.ClusterLabelSources)
	dbCopy.Current.ClusterRuleDetails = cloneStringMap(d.dbState.Current.ClusterRuleDetails)
	dbCopy.Current.ClusterBaseline = append([]store.ClusterBaselineItem(nil), d.dbState.Current.ClusterBaseline...)
	dbCopy.Current.ClusterSnapshots = cloneStringMap(d.dbState.Current.ClusterSnapshots)
	dbCopy.Current.IgnoredClusters = cloneBoolMap(d.dbState.Current.IgnoredClusters)
	dbCopy.Current.Results = append([]model.TestResult(nil), d.dbState.Current.Results...)
	d.fingerprintMu.RLock()
	dbCopy.Fingerprints = cloneFingerprints(d.dbState.Fingerprints)
	d.fingerprintMu.RUnlock()
	dbCopy.UsedSamples = d.cloneUsedSampleWords()
	startupCache := d.buildStartupCache()

	go func(snapshot store.Database, startup store.StartupCache) {
		_ = d.db.Save(snapshot)
		_ = d.db.SaveStartupCache(startup)
	}(dbCopy, startupCache)
}

func (d *dashboard) appendScanRecord(record store.ScanRecord) {
	d.dbState.Scans = append(d.dbState.Scans, record)
	d.persistDatabase()
}

func (d *dashboard) updateActiveScanRecord(update func(record *store.ScanRecord)) {
	if d.currentScanID == "" {
		return
	}
	for index := range d.dbState.Scans {
		if d.dbState.Scans[index].ID != d.currentScanID {
			continue
		}
		update(&d.dbState.Scans[index])
		return
	}
}

func (d *dashboard) resetDatabaseState() error {
	if d.db == nil {
		return nil
	}
	preservedFingerprints := persistentManualFingerprints(d.fingerprintSnapshot())
	if len(preservedFingerprints) == 0 {
		preservedFingerprints = persistentManualFingerprints(d.dbState.Fingerprints)
	}
	if err := d.db.ResetWithFingerprints(preservedFingerprints); err != nil {
		return err
	}
	d.dbState, _ = d.db.Load()
	d.sites = nil
	d.filteredSites = nil
	d.results = nil
	d.bypassStatsResults = nil
	d.detections = map[string]model.DetectionResult{}
	d.seenSiteKeys = map[string]bool{}
	d.siteTotalCount = 0
	d.sessionBypassSites = map[string]bool{}
	d.sessionBypassResults = map[string]model.TestResult{}
	d.fingerprintBaseCount = 0
	d.clusterLabels = map[string]string{}
	d.clusterLabelSources = map[string]string{}
	d.clusterRuleDetails = map[string]string{}
	d.clusterBaseline = []store.ClusterBaselineItem{}
	d.clusterMembers = map[string][]string{}
	d.invalidateClusterViewCache()
	d.clusterSnapshots = map[string]string{}
	d.snapshotPresence = map[string]bool{}
	d.recentClusters = map[string]bool{}
	d.ignoredClusters = map[string]bool{}
	d.fingerprintMu.Lock()
	d.fingerprints = cloneFingerprints(d.dbState.Fingerprints)
	d.fingerprintMu.Unlock()
	d.sampleWordMu.Lock()
	d.usedSampleWords = map[string]bool{}
	d.sampleWordMu.Unlock()
	d.currentScanID = ""
	d.selectedSite = -1
	d.selectedCluster = -1
	d.selectedResult = -1
	d.selectedPlugin = -1
	d.setMetricDelta(d.siteDeltaValue, 0)
	d.setMetricDelta(d.labeledDeltaValue, 0)
	d.setMetricDelta(d.suspectedDeltaValue, 0)
	d.setMetricDelta(d.clusterDeltaValue, 0)
	d.updateBypassStatsRows(nil, "")
	d.refreshWAFOptions()
	d.applyFilters()
	d.updateSiteDetails()
	d.updateClusterDetails()
	d.updateResultDetails()
	d.refreshDashboard()
	return nil
}

func cloneDetections(src map[string]model.DetectionResult) map[string]model.DetectionResult {
	if len(src) == 0 {
		return map[string]model.DetectionResult{}
	}
	dst := make(map[string]model.DetectionResult, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneBoolMap(src map[string]bool) map[string]bool {
	if len(src) == 0 {
		return map[string]bool{}
	}
	dst := make(map[string]bool, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func (d *dashboard) cloneUsedSampleWords() map[string]bool {
	d.sampleWordMu.Lock()
	defer d.sampleWordMu.Unlock()
	return cloneBoolMap(d.usedSampleWords)
}

func cloneFingerprints(src map[string]store.ClusterFingerprint) map[string]store.ClusterFingerprint {
	if len(src) == 0 {
		return map[string]store.ClusterFingerprint{}
	}
	dst := make(map[string]store.ClusterFingerprint, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func persistentManualFingerprints(src map[string]store.ClusterFingerprint) map[string]store.ClusterFingerprint {
	if len(src) == 0 {
		return map[string]store.ClusterFingerprint{}
	}
	dst := make(map[string]store.ClusterFingerprint)
	for key, value := range src {
		if strings.TrimSpace(value.Label) == "" {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(value.Source))
		if source != "" && source != "manual" {
			continue
		}
		if source == "" {
			value.Source = "manual"
		}
		dst[key] = value
	}
	return dst
}

func (d *dashboard) startupCacheWAF(site model.Site) string {
	if detection, ok := d.detections[d.siteKey(site)]; ok {
		if label := strings.TrimSpace(detection.ClusterLabel); label != "" {
			return label
		}
		if label := strings.TrimSpace(d.clusterLabels[detection.ClusterKey]); label != "" {
			return label
		}
		if detection.HasWAF {
			return "有WAF"
		}
		return "无WAF"
	}
	value := strings.TrimSpace(site.WAF)
	if value == "" {
		return "未识别"
	}
	return value
}

func (d *dashboard) buildStartupCache() store.StartupCache {
	return store.StartupCache{
		SiteCount:        d.siteTotalCount,
		SuspectedCount:   d.suspectedSiteCount(),
		ClusterCount:     d.totalClusterGroupCount(),
		FingerprintCount: d.labeledFingerprintCount(),
		UnlabeledFPCount: d.unlabeledFingerprintCount(),
	}
}

func (d *dashboard) sessionBypassCount() int {
	return len(d.sessionBypassSites)
}

func (d *dashboard) rememberSessionBypass(results ...model.TestResult) {
	if d.sessionBypassSites == nil {
		d.sessionBypassSites = map[string]bool{}
	}
	if d.sessionBypassResults == nil {
		d.sessionBypassResults = map[string]model.TestResult{}
	}
	for _, result := range results {
		if !strings.Contains(result.Verdict, "可能绕过") {
			continue
		}
		key := siteKeyDigest(d.siteKey(result.Site))
		if key == "" {
			continue
		}
		d.sessionBypassSites[key] = true
		d.sessionBypassResults[key] = result
	}
}

func (d *dashboard) applyStartupCache(cache store.StartupCache) {
	if cache.SiteCount == 0 && cache.SuspectedCount == 0 && cache.ClusterCount == 0 && cache.FingerprintCount == 0 && cache.UnlabeledFPCount == 0 {
		return
	}
	d.runOnUI(func() {
		if d.siteCountValue != nil {
			d.siteCountValue.Text = strconv.Itoa(cache.SiteCount)
			d.siteCountValue.Refresh()
		}
		if d.suspectedValue != nil {
			d.suspectedValue.Text = strconv.Itoa(cache.SuspectedCount)
			d.suspectedValue.Refresh()
		}
		if d.clusterCountValue != nil {
			d.clusterCountValue.Text = strconv.Itoa(cache.ClusterCount)
			d.clusterCountValue.Refresh()
		}
		if d.clusterPendingValue != nil {
			pending := cache.ClusterCount
			if pending < 0 {
				pending = 0
			}
			d.clusterPendingValue.Text = strconv.Itoa(pending)
			d.clusterPendingValue.Refresh()
		}
		if d.labeledValue != nil {
			d.labeledValue.Text = strconv.Itoa(cache.FingerprintCount)
			d.labeledValue.Refresh()
		}
		if d.nonWAFFingerprintText != nil {
			d.nonWAFFingerprintText.Text = fmt.Sprintf("非waf指纹 %d 个", cache.UnlabeledFPCount)
			d.nonWAFFingerprintText.Refresh()
		}
	})
	d.setStatus(fmt.Sprintf("启动中 // 已快速恢复 %d 条站点，正在载入完整数据", cache.SiteCount))
}

func (d *dashboard) showActionSuccess(title string, message string) {
	message = strings.TrimSpace(message)
	if message != "" {
		d.flashClusterNotice(message, accentGreen)
	}
	_ = title
}

func (d *dashboard) flashClusterNotice(message string, accent color.NRGBA) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	d.setStatus(message)
	if d.clusterNoticeLabel == nil {
		return
	}

	token := time.Now().UnixNano()
	d.clusterNoticeToken = token
	d.runOnUI(func() {
		if d.clusterNoticeLabel == nil {
			return
		}
		d.clusterNoticeLabel.Color = accent
		d.clusterNoticeLabel.Text = message
		d.clusterNoticeLabel.Refresh()
	})

	time.AfterFunc(2200*time.Millisecond, func() {
		if d.clusterNoticeToken != token || d.clusterNoticeLabel == nil {
			return
		}
		d.runOnUI(func() {
			if d.clusterNoticeToken != token || d.clusterNoticeLabel == nil {
				return
			}
			d.clusterNoticeLabel.Text = ""
			d.clusterNoticeLabel.Refresh()
		})
	})
}

func sortedSiteKeys(keys map[string]bool) []string {
	if len(keys) == 0 {
		return []string{}
	}
	items := make([]string, 0, len(keys))
	for key := range keys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		items = append(items, key)
	}
	sort.Strings(items)
	return items
}

func siteKeyDigest(key string) string {
	normalized := strings.TrimSpace(strings.ToLower(key))
	if normalized == "" {
		return ""
	}
	sum := sha1.Sum([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func (d *dashboard) isRecentCluster(key string) bool {
	if d.recentClusters == nil {
		return false
	}
	return d.recentClusters[strings.TrimSpace(key)]
}

func (d *dashboard) fingerprintSnapshot() map[string]store.ClusterFingerprint {
	d.fingerprintMu.RLock()
	defer d.fingerprintMu.RUnlock()
	return cloneFingerprints(d.fingerprints)
}

func (d *dashboard) groupedFingerprints() map[string]store.ClusterFingerprint {
	current := d.fingerprintSnapshot()
	items := make([]store.ClusterFingerprint, 0, len(current))
	for _, fp := range current {
		items = append(items, fp)
	}
	sort.Slice(items, func(i, j int) bool {
		leftLabeled := strings.TrimSpace(items[i].Label) != ""
		rightLabeled := strings.TrimSpace(items[j].Label) != ""
		if leftLabeled != rightLabeled {
			return leftLabeled
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})

	grouped := make(map[string]store.ClusterFingerprint, len(items))
	groupOrder := make([]string, 0, len(items))
	for _, fp := range items {
		labelKey := strings.TrimSpace(fp.Label)
		groupKey := ""
		if labelKey != "" {
			groupKey = "label:" + labelKey
		} else {
			groupKey = fingerprintGroupKey(fp)
			if strings.TrimSpace(groupKey) == "" {
				groupKey = strings.TrimSpace(fp.Signature)
			}
		}
		if strings.TrimSpace(groupKey) == strings.TrimSpace(fp.Signature) {
			for _, existingKey := range groupOrder {
				current := grouped[existingKey]
				if !shouldCollapseFingerprintGroup(current, fp) {
					continue
				}
				groupKey = existingKey
				break
			}
		}

		current, exists := grouped[groupKey]
		if !exists {
			grouped[groupKey] = fp
			groupOrder = append(groupOrder, groupKey)
			continue
		}

		currentLabeled := strings.TrimSpace(current.Label) != ""
		nextLabeled := strings.TrimSpace(fp.Label) != ""
		switch {
		case nextLabeled && !currentLabeled:
			grouped[groupKey] = fp
		case nextLabeled == currentLabeled && fp.UpdatedAt.After(current.UpdatedAt):
			grouped[groupKey] = fp
		}
	}
	return grouped
}

func shouldCollapseFingerprintGroup(current, candidate store.ClusterFingerprint) bool {
	currentLabel := strings.TrimSpace(current.Label)
	candidateLabel := strings.TrimSpace(candidate.Label)

	if currentLabel != candidateLabel {
		if !(currentLabel == "" && candidateLabel == "") {
			return false
		}
	}

	currentCache := strings.TrimSpace(current.SnapshotCacheKey)
	candidateCache := strings.TrimSpace(candidate.SnapshotCacheKey)
	if currentCache != "" && candidateCache != "" && currentCache == candidateCache {
		return true
	}

	if detector.FingerprintCloseMatch(current.Snapshot, candidate.Snapshot) {
		return true
	}

	if currentLabel != "" && candidateLabel != "" {
		currentScore := detector.ResponseSimilarity(current.Snapshot, candidate.Snapshot)
		if currentScore >= 0.82 {
			return true
		}
	}

	return false
}

func (d *dashboard) labeledFingerprintCount() int {
	count := 0
	for _, fp := range d.groupedFingerprints() {
		if strings.TrimSpace(fp.Label) != "" {
			count++
		}
	}
	return count
}

func (d *dashboard) unlabeledFingerprintCount() int {
	count := 0
	for _, fp := range d.groupedFingerprints() {
		if strings.TrimSpace(fp.Label) == "" {
			count++
		}
	}
	return count
}

func (d *dashboard) mergeSites(incoming []model.Site) int {
	if len(incoming) == 0 {
		return 0
	}

	if d.seenSiteKeys == nil {
		d.seenSiteKeys = map[string]bool{}
	}
	indexByKey := make(map[string]int, len(d.sites))
	for index, site := range d.sites {
		key := d.siteKey(site)
		if key == "" {
			continue
		}
		indexByKey[key] = index
	}

	added := 0
	for _, site := range incoming {
		key := d.siteKey(site)
		if key == "" {
			d.sites = append(d.sites, site)
			added++
			d.siteTotalCount++
			continue
		}
		digest := siteKeyDigest(key)
		if index, ok := indexByKey[key]; ok {
			d.sites[index] = site
			continue
		}
		if d.seenSiteKeys[digest] {
			continue
		}
		d.seenSiteKeys[digest] = true
		indexByKey[key] = len(d.sites)
		d.sites = append(d.sites, site)
		added++
		d.siteTotalCount++
	}
	return added
}

func (d *dashboard) resetConsole(title string, status string) {
	d.runOnUI(func() {
		d.consoleMu.Lock()
		defer d.consoleMu.Unlock()

		if d.consoleTitle != nil {
			d.consoleTitle.SetText("任务 // " + title)
		}
		d.consoleLines = []string{
			"[boot] WAF Killer 终端控制台已连接",
			"[task] " + status,
		}
		d.consoleRefreshPending = false
		d.renderConsoleLinesLocked()
		if d.consoleStatus != nil {
			d.consoleStatus.SetText(status)
		}
		if d.consoleProgress != nil {
			d.consoleProgress.SetValue(0)
		}
		if d.consoleProgressText != nil {
			d.consoleProgressText.SetText("0%")
		}
		if d.consoleDetailBox != nil {
			d.consoleDetailBox.Hide()
		}
		if d.consoleToggleBtn != nil {
			d.consoleToggleBtn.SetText("详情")
		}
		d.consoleDetailsVisible = false
		if d.consoleScroll != nil {
			d.consoleScroll.Offset = fyne.Position{}
			d.consoleScroll.Refresh()
		}
	})
}

func (d *dashboard) appendConsoleLog(line string) {
	d.consoleMu.Lock()
	d.consoleLines = append(d.consoleLines, line)
	if len(d.consoleLines) > 120 {
		d.consoleLines = append(d.consoleLines[:2], d.consoleLines[len(d.consoleLines)-118:]...)
	}
	shouldRefresh := d.consoleDetailsVisible && d.consoleBody != nil && !d.consoleRefreshPending
	if shouldRefresh {
		d.consoleRefreshPending = true
	}
	d.consoleMu.Unlock()
	if !shouldRefresh {
		return
	}
	time.AfterFunc(180*time.Millisecond, func() {
		d.runOnUI(func() {
			d.consoleMu.Lock()
			defer d.consoleMu.Unlock()
			d.consoleRefreshPending = false
			if !d.consoleDetailsVisible || d.consoleBody == nil {
				return
			}
			d.renderConsoleLinesLocked()
			if d.consoleScroll != nil {
				d.consoleScroll.Offset.Y = 1e9
				d.consoleScroll.Refresh()
			}
		})
	})
}

func (d *dashboard) diagnosticLogPath() string {
	base := strings.TrimSpace(d.cfg.App.DatabasePath)
	if base != "" {
		return filepath.Join(filepath.Dir(base), "rule_validation_diagnostics.log")
	}
	return filepath.Join("data", "rule_validation_diagnostics.log")
}

func (d *dashboard) appendDiagnosticLog(lines ...string) {
	path := d.diagnosticLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		d.appendConsoleLog("[diag-file] 创建日志目录失败: " + err.Error())
		return
	}

	block := strings.Join(lines, "\n")
	if strings.TrimSpace(block) == "" {
		return
	}
	block = fmt.Sprintf("[%s]\n%s\n\n", time.Now().Format("2006-01-02 15:04:05"), block)

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		d.appendConsoleLog("[diag-file] 打开日志文件失败: " + err.Error())
		return
	}
	defer file.Close()

	if _, err := file.WriteString(block); err != nil {
		d.appendConsoleLog("[diag-file] 写入日志文件失败: " + err.Error())
		return
	}
}

func (d *dashboard) setConsoleStatus(text string) {
	d.queueConsoleUpdate(text, 0, 0, false)
}

func (d *dashboard) setConsoleProgress(current, total int) {
	d.queueConsoleUpdate("", current, total, true)
}

func (d *dashboard) queueConsoleUpdate(status string, current, total int, hasProgress bool) {
	d.consoleUpdateMu.Lock()
	if status != "" {
		d.consoleStatusLatest = status
		d.consoleHasStatus = true
	}
	if hasProgress {
		d.consoleProgressCur = current
		d.consoleProgressTotal = total
		d.consoleHasProgress = true
	}
	if d.consoleUpdatePending {
		d.consoleUpdateMu.Unlock()
		return
	}
	d.consoleUpdatePending = true
	d.consoleUpdateMu.Unlock()

	d.runOnUI(func() {
		d.consoleUpdateMu.Lock()
		statusText := d.consoleStatusLatest
		hasStatus := d.consoleHasStatus
		progressCurrent := d.consoleProgressCur
		progressTotal := d.consoleProgressTotal
		hasProgress := d.consoleHasProgress
		d.consoleHasStatus = false
		d.consoleHasProgress = false
		d.consoleUpdatePending = false
		d.consoleUpdateMu.Unlock()

		d.consoleMu.Lock()
		defer d.consoleMu.Unlock()

		if hasStatus && d.consoleStatus != nil {
			d.consoleStatus.SetText(statusText)
		}
		if hasProgress {
			value := 0.0
			percentText := "0%"
			switch {
			case progressTotal > 0 && progressCurrent > 0:
				value = float64(progressCurrent) / float64(progressTotal)
				if value > 1 {
					value = 1
				}
				percentText = fmt.Sprintf("%d%%", int(value*100))
			case progressTotal > 0:
				percentText = "0%"
			}

			if d.consoleProgress != nil {
				d.consoleProgress.SetValue(value)
			}
			if d.consoleProgressText != nil {
				d.consoleProgressText.SetText(percentText)
			}
		}
	})
}

func (d *dashboard) finishSearchConsole(success bool) {
	d.consoleMu.Lock()
	defer d.consoleMu.Unlock()
	if d.consoleStatus != nil {
		if success {
			d.consoleStatus.SetText("搜索完成")
		} else {
			d.consoleStatus.SetText("搜索失败")
		}
	}
	if d.consoleProgress != nil && success {
		d.consoleProgress.SetValue(1)
	}
	if d.consoleProgressText != nil && success {
		d.consoleProgressText.SetText("100%")
	}
}

func (d *dashboard) renderConsoleLinesLocked() {
	if d.consoleBody == nil {
		return
	}
	objects := make([]fyne.CanvasObject, 0, len(d.consoleLines))
	for _, line := range d.consoleLines {
		text := canvas.NewText(line, accentGreen)
		text.TextSize = 12
		objects = append(objects, text)
	}
	d.consoleBody.Objects = objects
	d.consoleBody.Refresh()
}

func (d *dashboard) toggleConsoleDetails() {
	d.consoleMu.Lock()
	defer d.consoleMu.Unlock()

	if d.consoleDetailBox == nil || d.consoleToggleBtn == nil {
		return
	}
	if d.consoleDetailsVisible {
		d.consoleDetailBox.Hide()
		d.consoleToggleBtn.SetText("详情")
		d.consoleDetailsVisible = false
		return
	}
	d.consoleDetailBox.Show()
	d.consoleToggleBtn.SetText("收起")
	d.consoleDetailsVisible = true
	d.renderConsoleLinesLocked()
	if d.consoleScroll != nil {
		d.consoleScroll.Offset.Y = 1e9
		d.consoleScroll.Refresh()
	}
}

func (d *dashboard) showURLViewer() {
	d.showSiteViewer("URL 总览", d.sites, "没有 URL", "当前还没有采集到 URL，请先执行搜索。", false)
}

func (d *dashboard) showSuspectedViewer() {
	suspected, _ := d.suspectedTargets()
	d.showSiteViewer("疑似 WAF 总览", suspected, "没有疑似WAF", "当前还没有识别出疑似 WAF 目标，请先执行识别。", true)
}

func (d *dashboard) showClusterViewer() {
	clusters := d.clusterViews()
	if len(clusters) == 0 {
		if d.totalClusterGroupCount() > 0 {
			dialog.ShowInformation("没有可见聚类", "当前聚类都已被忽略，所以这里不再展示。", d.window)
			return
		}
		dialog.ShowInformation("没有聚类结果", "当前还没有可查看的聚类结果，请先执行自动聚类。", d.window)
		return
	}

	displayNames := make([]string, len(clusters))
	refreshDisplayNameAt := func(index int) {
		if index < 0 || index >= len(clusters) {
			return
		}
		cluster := clusters[index]
		prefix := ""
		if cluster.IsNew {
			prefix = "[新增] "
		}
		if label := strings.TrimSpace(cluster.Label); label != "" {
			if sourceText := clusterLabelSourceText(cluster.LabelSource); sourceText != "" {
				displayNames[index] = prefix + "[" + sourceText + "] " + label
			} else {
				displayNames[index] = prefix + label
			}
			return
		}
		if title := clusterDefaultTitle(cluster); title != "待标注聚类" {
			displayNames[index] = prefix + title
			return
		}
		unnamedIndex := 0
		for i, current := range clusters {
			if strings.TrimSpace(current.Label) != "" {
				continue
			}
			if title := clusterDefaultTitle(current); title != "待标注聚类" {
				continue
			}
			unnamedIndex++
			if i == index {
				displayNames[index] = prefix + fmt.Sprintf("未标记%d", unnamedIndex)
				return
			}
		}
		displayNames[index] = prefix + "未标记"
	}
	refreshDisplayNames := func() {
		displayNames = make([]string, len(clusters))
		for i := range clusters {
			refreshDisplayNameAt(i)
		}
	}
	refreshDisplayNames()

	source := newSourcePreviewLabel()
	sourceScroll := container.NewScroll(source)
	previewHolder := container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "cluster-viewer-empty", false))
	labelEntry := widget.NewEntry()
	labelEntry.SetPlaceHolder("输入 WAF 产品名称后写入标签")
	feedbackText := canvas.NewText("", accentGreen)
	feedbackText.TextSize = 11
	feedbackText.TextStyle = fyne.TextStyle{Bold: true}
	selectedClusterKey := ""
	currentSelectedIndex := -1
	checkedClusterKeys := map[string]bool{}
	feedbackToken := int64(0)
	showViewerNotice := func(message string, accent color.NRGBA) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		feedbackToken = time.Now().UnixNano()
		token := feedbackToken
		feedbackText.Color = accent
		feedbackText.Text = message
		feedbackText.Refresh()
		time.AfterFunc(2200*time.Millisecond, func() {
			if feedbackToken != token {
				return
			}
			feedbackText.Text = ""
			feedbackText.Refresh()
		})
	}

	list := widget.NewList(
		func() int { return len(clusters) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 11, G: 17, B: 29, A: 232})
			tint := canvas.NewLinearGradient(
				color.NRGBA{R: 255, G: 255, B: 255, A: 0},
				color.NRGBA{R: accentBlue.R, G: accentBlue.G, B: accentBlue.B, A: 16},
				0,
			)
			bar := canvas.NewRectangle(accentBlue)
			bar.SetMinSize(fyne.NewSize(5, 0))
			check := widget.NewCheck("", nil)
			title := widget.NewLabel("聚类")
			title.TextStyle = fyne.TextStyle{Bold: true}
			title.Wrapping = fyne.TextWrapOff
			count := canvas.NewText("0 个", accentGreen)
			count.TextSize = 13
			count.TextStyle = fyne.TextStyle{Bold: true}
			content := container.NewHBox(title, layout.NewSpacer(), count)
			separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
			separator.SetMinSize(fyne.NewSize(0, 1))
			glow := canvas.NewRectangle(color.NRGBA{R: accentBlue.R, G: accentBlue.G, B: accentBlue.B, A: 10})
			return container.NewStack(
				bg,
				tint,
				glow,
				container.NewHBox(bar, check, container.NewPadded(content)),
				container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			cluster := clusters[id]
			row := item.(*fyne.Container)
			isSelected := id == currentSelectedIndex
			bg := row.Objects[0].(*canvas.Rectangle)
			hasSnapshot := d.clusterHasSnapshot(cluster.Key)
			if isSelected {
				bg.FillColor = color.NRGBA{R: 26, G: 34, B: 52, A: 244}
			} else if hasSnapshot {
				if id%2 == 0 {
					bg.FillColor = color.NRGBA{R: 10, G: 18, B: 30, A: 236}
				} else {
					bg.FillColor = color.NRGBA{R: 16, G: 24, B: 38, A: 236}
				}
			} else {
				if id%2 == 0 {
					bg.FillColor = color.NRGBA{R: 9, G: 15, B: 26, A: 236}
				} else {
					bg.FillColor = color.NRGBA{R: 18, G: 25, B: 40, A: 236}
				}
			}
			bg.Refresh()

			tint := row.Objects[1].(*canvas.LinearGradient)
			if isSelected {
				tint.StartColor = color.NRGBA{R: 255, G: 184, B: 216, A: 16}
				tint.EndColor = color.NRGBA{R: 78, G: 169, B: 255, A: 58}
			} else if hasSnapshot {
				tint.StartColor = color.NRGBA{R: 84, G: 255, B: 205, A: 10}
				tint.EndColor = color.NRGBA{R: 44, G: 195, B: 255, A: 36}
			} else {
				tint.StartColor = color.NRGBA{R: 255, G: 255, B: 255, A: 0}
				tint.EndColor = color.NRGBA{R: accentBlue.R, G: accentBlue.G, B: accentBlue.B, A: 16}
			}
			tint.Refresh()

			glow := row.Objects[2].(*canvas.Rectangle)
			if isSelected {
				glow.FillColor = color.NRGBA{R: 120, G: 189, B: 255, A: 24}
			} else if hasSnapshot {
				glow.FillColor = color.NRGBA{R: 84, G: 255, B: 205, A: 12}
			} else {
				glow.FillColor = color.NRGBA{R: accentBlue.R, G: accentBlue.G, B: accentBlue.B, A: 10}
			}
			glow.Refresh()

			main := row.Objects[3].(*fyne.Container)
			check := main.Objects[1].(*widget.Check)
			check.OnChanged = nil
			check.SetChecked(checkedClusterKeys[cluster.Key])
			check.OnChanged = func(checked bool) {
				if checked {
					checkedClusterKeys[cluster.Key] = true
				} else {
					delete(checkedClusterKeys, cluster.Key)
				}
			}
			bar := main.Objects[0].(*canvas.Rectangle)
			if cluster.IsNew {
				bar.FillColor = accentGreen
			} else if strings.TrimSpace(cluster.Label) != "" {
				bar.FillColor = color.NRGBA{R: 255, G: 164, B: 182, A: 255}
			} else {
				bar.FillColor = accentBlue
			}
			bar.Refresh()

			padded := main.Objects[2].(*fyne.Container)
			content := padded.Objects[0].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(displayNames[id])
			countText := content.Objects[2].(*canvas.Text)
			countText.Text = fmt.Sprintf("%d 个", cluster.Count)
			if cluster.IsNew {
				countText.Color = accentGreen
			} else {
				countText.Color = color.NRGBA{R: 124, G: 255, B: 190, A: 255}
			}
			countText.Refresh()
			row.Refresh()
		},
	)
	for i := range clusters {
		list.SetItemHeight(i, 62)
	}
	refreshClusterSelection := func(previous, current int) {
		if previous >= 0 && previous < len(clusters) {
			list.RefreshItem(previous)
		}
		if current >= 0 && current < len(clusters) && current != previous {
			list.RefreshItem(current)
		}
	}
	renderSelectedCluster := func(id int) {
		if id < 0 || id >= len(clusters) {
			selectedClusterKey = ""
			source.SetText("")
			labelEntry.SetText("")
			previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "cluster-viewer-empty", false)}
			previewHolder.Refresh()
			return
		}
		cluster := clusters[id]
		selectedClusterKey = cluster.Key
		snapshot := d.clusterBlockedSnapshot(cluster.Key)
		lines := []string{
			"聚类标签: " + clusterDefaultTitle(cluster),
			"标签来源: " + emptyFallback(map[string]string{"manual": "手工标记", "yaml": "规则识别"}[cluster.LabelSource], "-"),
			"规则命中: " + emptyFallback(d.clusterRuleDetails[cluster.Key], "-"),
			"聚类键: " + emptyFallback(cluster.Key, "-"),
			"聚类签名: " + emptyFallback(cluster.Signature, "-"),
			fmt.Sprintf("组内站点: %d", cluster.Count),
			"代表站点:",
			strings.Join(cluster.SampleSites, "\n"),
			"",
			"拦截响应原始报文:",
			d.clusterRawResponse(cluster.Key),
		}
		source.SetText(sourcePreviewText(strings.Join(lines, "\n")))
		labelEntry.SetText(cluster.Label)
		previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(snapshot, cluster.Key, false)}
		previewHolder.Refresh()
	}
	selectCluster := func(index int) {
		previousIndex := currentSelectedIndex
		if index < 0 || index >= len(clusters) {
			currentSelectedIndex = -1
			renderSelectedCluster(-1)
			refreshClusterSelection(previousIndex, -1)
			return
		}
		currentSelectedIndex = index
		renderSelectedCluster(index)
		list.Select(index)
		refreshClusterSelection(previousIndex, index)
	}
	list.OnSelected = func(id widget.ListItemID) {
		previousIndex := currentSelectedIndex
		currentSelectedIndex = id
		renderSelectedCluster(id)
		refreshClusterSelection(previousIndex, id)
	}

	detailTabs := container.NewAppTabs(
		container.NewTabItem("HTML源码", sourceScroll),
		container.NewTabItem("浏览器快照", previewHolder),
	)
	detailTabs.SelectIndex(1)

	saveBtn := widget.NewButton("写入标签", func() {
		if selectedClusterKey == "" {
			dialog.ShowInformation("选择聚类", "请先在左侧选择一个聚类。", d.window)
			return
		}
		label := strings.TrimSpace(labelEntry.Text)
		if label == "" {
			dialog.ShowInformation("输入标签", "请输入要写入的 WAF 产品名称。", d.window)
			return
		}
		d.assignClusterLabelByKey(selectedClusterKey, label)
		for index := range clusters {
			if clusters[index].Key != selectedClusterKey {
				continue
			}
			clusters[index].Label = label
			clusters[index].LabelSource = "manual"
			refreshDisplayNameAt(index)
			renderSelectedCluster(index)
			list.RefreshItem(index)
			showViewerNotice(fmt.Sprintf("已写入标签：%s", label), accentGreen)
			return
		}
	})
	reloadBtn := widget.NewButton("重载快照", func() {
		if selectedClusterKey == "" {
			dialog.ShowInformation("选择聚类", "请先在左侧选择一个聚类。", d.window)
			return
		}
		snapshot := d.clusterBlockedSnapshot(selectedClusterKey)
		if strings.TrimSpace(snapshot.Body) == "" && strings.TrimSpace(snapshot.Raw) == "" {
			dialog.ShowInformation("没有快照源", "当前聚类没有可用于重新截图的响应体。", d.window)
			return
		}
		previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(snapshot, selectedClusterKey, true)}
		previewHolder.Refresh()
	})
	mergeBtn := widget.NewButton("合并选中", func() {
		selectedKeys := make([]string, 0, len(checkedClusterKeys))
		for _, cluster := range clusters {
			if checkedClusterKeys[cluster.Key] {
				selectedKeys = append(selectedKeys, cluster.Key)
			}
		}
		if len(selectedKeys) < 2 {
			dialog.ShowInformation("选择聚类", "请至少勾选两个分类后再执行合并。", d.window)
			return
		}

		canonicalKey := selectedClusterKey
		if canonicalKey == "" || !checkedClusterKeys[canonicalKey] {
			canonicalKey = selectedKeys[0]
		}
		d.mergeClusterKeys(selectedKeys, canonicalKey)
		clusters = d.clusterViews()
		checkedClusterKeys = map[string]bool{}
		if len(clusters) == 0 {
			selectCluster(-1)
			return
		}

		refreshDisplayNames()
		for i := range clusters {
			list.SetItemHeight(i, 62)
		}
		list.Refresh()

		nextIndex := 0
		for i, cluster := range clusters {
			if cluster.Key == canonicalKey {
				nextIndex = i
				break
			}
		}
		selectCluster(nextIndex)
		showViewerNotice(fmt.Sprintf("已合并 %d 个分类，并记忆后续归并关系。", len(selectedKeys)), accentGreen)
	})
	ignoreBtn := widget.NewButton("忽略分类", func() {
		if selectedClusterKey == "" {
			dialog.ShowInformation("选择聚类", "请先在左侧选择一个聚类。", d.window)
			return
		}

		currentIndex := currentSelectedIndex
		d.ignoreClusterByKey(selectedClusterKey)
		clusters = d.clusterViews()
		if len(clusters) == 0 {
			viewer := dialog.NewInformation("没有可见聚类", "当前聚类都已被忽略。", d.window)
			viewer.Show()
			selectedClusterKey = ""
			source.SetText("")
			labelEntry.SetText("")
			previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "cluster-viewer-empty", false)}
			previewHolder.Refresh()
			list.Refresh()
			return
		}

		refreshDisplayNames()
		for i := range clusters {
			list.SetItemHeight(i, 62)
		}
		list.Refresh()
		nextIndex := currentIndex
		if nextIndex >= len(clusters) {
			nextIndex = 0
		}
		selectCluster(nextIndex)
		showViewerNotice("当前分类已忽略，并自动切换到下一个分类。", accentAmber)
	})

	detailHeader := container.NewVBox(
		container.NewGridWithColumns(
			6,
			widget.NewLabel("产品名称"),
			labelEntry,
			saveBtn,
			reloadBtn,
			ignoreBtn,
			mergeBtn,
		),
		feedbackText,
	)

	body := container.NewHSplit(
		neonPanel(accentBlue, list),
		neonPanel(accentPink, container.NewBorder(detailHeader, nil, nil, nil, detailTabs)),
	)
	body.Offset = 0.4

	viewer := d.app.NewWindow("聚类总览")
	viewer.Resize(fyne.NewSize(1020, 580))
	viewer.SetContent(body)
	viewer.Show()
	recentCount := 0
	for _, cluster := range clusters {
		if cluster.IsNew {
			recentCount++
		}
	}
	if recentCount > 0 {
		showViewerNotice(fmt.Sprintf("本轮新增 %d 个聚类分组，已置顶并添加 [新增] 标记。", recentCount), accentGreen)
	}
	selectCluster(0)
}

func (d *dashboard) openRuleCompareDialog() {
	options := filterVisibleValidationPlugins(d.plugins)
	if len(options) < 2 {
		dialog.ShowInformation("规则对比", "至少需要两条正式规则才能进行对比。", d.window)
		return
	}
	if len(d.results) == 0 {
		dialog.ShowInformation("规则对比", "当前还没有规则验证结果，请先执行规则验证。", d.window)
		return
	}
	testedRules := map[string]bool{}
	for _, row := range d.buildRuleStatsRows() {
		if row.Tested {
			testedRules[strings.TrimSpace(row.Name)] = true
		}
	}
	testedCount := 0
	for _, option := range options {
		if testedRules[strings.TrimSpace(option.Name)] {
			testedCount++
		}
	}
	if testedCount < 2 {
		dialog.ShowInformation("规则对比", "至少需要两条已检测过的正式规则才能进行对比。", d.window)
		return
	}
	sort.Slice(options, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(options[i].Name)) < strings.ToLower(strings.TrimSpace(options[j].Name))
	})

	selected := []string{}
	selectedSet := map[string]bool{}
	updateSelection := func(name string, checked bool) {
		if checked {
			if selectedSet[name] {
				return
			}
			selectedSet[name] = true
			selected = append(selected, name)
			if len(selected) > 2 {
				removed := selected[0]
				selected = selected[1:]
				delete(selectedSet, removed)
			}
			return
		}
		if !selectedSet[name] {
			return
		}
		delete(selectedSet, name)
		filtered := selected[:0]
		for _, item := range selected {
			if item == name {
				continue
			}
			filtered = append(filtered, item)
		}
		selected = filtered
	}

	selectedCountLabel := canvas.NewText("已选择 0 条", color.NRGBA{R: 171, G: 210, B: 255, A: 230})
	selectedCountLabel.TextSize = 11
	selectedCountLabel.TextStyle = fyne.TextStyle{Bold: true}
	selectedOrderLabel := widget.NewLabel("请选择两条规则，先选的是第一条，后选的是第二条。")
	selectedOrderLabel.Wrapping = fyne.TextWrapWord
	updateLabels := func() {
		selectedCountLabel.Text = fmt.Sprintf("已选择 %d 条", len(selected))
		selectedCountLabel.Refresh()
		switch len(selected) {
		case 0:
			selectedOrderLabel.SetText("请选择两条规则，先选的是第一条，后选的是第二条。")
		case 1:
			selectedOrderLabel.SetText("第一条规则: " + selected[0])
		default:
			selectedOrderLabel.SetText("第一条规则: " + selected[0] + "\n第二条规则: " + selected[1])
		}
	}

	var list *widget.List
	list = widget.NewList(
		func() int { return len(options) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 228})
			bar := canvas.NewRectangle(accentAmber)
			bar.SetMinSize(fyne.NewSize(4, 0))
			check := widget.NewCheck("", nil)
			label := widget.NewLabel("规则")
			label.TextStyle = fyne.TextStyle{Bold: true}
			label.Wrapping = fyne.TextWrapOff
			return container.NewStack(
				bg,
				container.NewHBox(bar, check, container.NewPadded(label)),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(options) {
				return
			}
			name := options[id].Name
			tested := testedRules[strings.TrimSpace(name)]
			accent := pluginAccent(options[id])
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if !tested {
				bg.FillColor = color.NRGBA{R: 18, G: 20, B: 26, A: 210}
			} else if selectedSet[name] {
				bg.FillColor = color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 42}
			} else if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			if tested {
				bar.FillColor = accent
			} else {
				bar.FillColor = color.NRGBA{R: 92, G: 100, B: 118, A: 255}
			}
			bar.Refresh()
			check := main.Objects[1].(*widget.Check)
			check.OnChanged = nil
			check.SetChecked(tested && selectedSet[name])
			check.Disable()
			if tested {
				check.Enable()
				check.OnChanged = func(checked bool) {
					updateSelection(name, checked)
					updateLabels()
					list.Refresh()
				}
			}
			label := main.Objects[2].(*fyne.Container).Objects[0].(*widget.Label)
			if tested {
				label.SetText(name)
				label.Importance = widget.MediumImportance
			} else {
				label.SetText(name + " | 未检测")
				label.Importance = widget.LowImportance
			}
		},
	)
	for i := range options {
		list.SetItemHeight(i, 38)
	}
	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(options) {
			return
		}
		name := options[id].Name
		if !testedRules[strings.TrimSpace(name)] {
			list.UnselectAll()
			return
		}
		updateSelection(name, !selectedSet[name])
		updateLabels()
		list.Refresh()
		list.UnselectAll()
	}

	startBtn := widget.NewButtonWithIcon("开始对比", playResource(), nil)
	cancelBtn := widget.NewButton("取消", nil)
	startBtn.Importance = widget.LowImportance
	cancelBtn.Importance = widget.LowImportance

	viewer := d.app.NewWindow("规则对比")
	startBtn.OnTapped = func() {
		if len(selected) != 2 {
			dialog.ShowInformation("规则对比", "请准确选择两条规则。", viewer)
			return
		}
		viewer.Close()
		d.showRuleCompareViewer(selected[0], selected[1])
	}
	cancelBtn.OnTapped = func() {
		viewer.Close()
	}

	actionBar := container.NewHBox(
		layout.NewSpacer(),
		neonPanel(accentMuted, container.NewPadded(cancelBtn)),
		neonPanel(accentBlue, container.NewPadded(startBtn)),
	)
	content := container.NewBorder(
		neonPanel(accentAmber, container.NewVBox(selectedCountLabel, selectedOrderLabel)),
		neonPanel(accentBlue, actionBar),
		nil,
		nil,
		neonPanel(accentAmber, list),
	)
	viewer.Resize(fyne.NewSize(560, 460))
	viewer.SetContent(content)
	viewer.Show()
	updateLabels()
}

func (d *dashboard) showRuleCompareViewer(firstRule string, secondRule string) {
	aBlockedBBypass := d.buildRuleCompareDiffGroups(firstRule, secondRule, true)
	aBypassBBlocked := d.buildRuleCompareDiffGroups(firstRule, secondRule, false)
	if len(aBlockedBBypass) == 0 && len(aBypassBBlocked) == 0 {
		dialog.ShowInformation("规则对比", "当前没有找到两条规则之间互相验证有效性的差异样本。", d.window)
		return
	}

	tabs := container.NewAppTabs(
		container.NewTabItem(
			fmt.Sprintf("A拦截B绕过 (%d)", totalRuleCompareDiffRows(aBlockedBBypass)),
			d.buildRuleCompareDirectionPane(firstRule, secondRule, "A拦截B绕过 URL列表", aBlockedBBypass),
		),
		container.NewTabItem(
			fmt.Sprintf("A绕过B拦截 (%d)", totalRuleCompareDiffRows(aBypassBBlocked)),
			d.buildRuleCompareDirectionPane(firstRule, secondRule, "A绕过B拦截 URL列表", aBypassBBlocked),
		),
	)
	note := widget.NewLabel(fmt.Sprintf("A：%s    B：%s", firstRule, secondRule))
	note.Wrapping = fyne.TextWrapWord

	viewer := d.app.NewWindow("规则对比")
	viewer.Resize(fyne.NewSize(1220, 760))
	viewer.SetContent(container.NewBorder(
		neonPanel(accentAmber, note),
		nil,
		nil,
		nil,
		tabs,
	))
	viewer.Show()
}

func (d *dashboard) buildRuleCompareDirectionPane(ruleA string, ruleB string, directionTitle string, groups []ruleCompareDiffGroup) fyne.CanvasObject {
	if len(groups) == 0 {
		empty := widget.NewLabel("当前方向下没有命中的 URL。")
		empty.Wrapping = fyne.TextWrapWord
		return neonPanel(accentBlue, container.NewCenter(empty))
	}

	summary := widget.NewMultiLineEntry()
	summary.Disable()
	summary.SetMinRowsVisible(6)
	aRequest := widget.NewMultiLineEntry()
	aRequest.Disable()
	aRequest.SetMinRowsVisible(14)
	aResponse := widget.NewMultiLineEntry()
	aResponse.Disable()
	aResponse.SetMinRowsVisible(14)
	aPreviewHolder := container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "rule-compare-a-empty", false))
	bRequest := widget.NewMultiLineEntry()
	bRequest.Disable()
	bRequest.SetMinRowsVisible(14)
	bResponse := widget.NewMultiLineEntry()
	bResponse.Disable()
	bResponse.SetMinRowsVisible(14)
	bPreviewHolder := container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "rule-compare-b-empty", false))

	siteRows := []ruleCompareDiffRow{}
	currentGroup := -1
	currentSite := -1

	groupList := widget.NewList(
		func() int { return len(groups) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
			bar := canvas.NewRectangle(accentAmber)
			bar.SetMinSize(fyne.NewSize(4, 0))
			label := widget.NewLabel("分组")
			label.TextStyle = fyne.TextStyle{Bold: true}
			label.Wrapping = fyne.TextWrapOff
			return container.NewStack(bg, container.NewHBox(bar, container.NewPadded(label)))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(groups) {
				return
			}
			group := groups[id]
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id == currentGroup {
				bg.FillColor = color.NRGBA{R: 42, G: 34, B: 18, A: 242}
			} else if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = wafAccent(group.WAF)
			bar.Refresh()
			label := main.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
			label.SetText(fmt.Sprintf("%s | %s | %d 个URL", group.Title, group.WAF, len(group.Rows)))
		},
	)
	for i := range groups {
		groupList.SetItemHeight(i, 38)
	}

	siteList := widget.NewList(
		func() int { return len(siteRows) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
			bar := canvas.NewRectangle(accentGreen)
			bar.SetMinSize(fyne.NewSize(4, 0))
			label := widget.NewLabel("站点")
			label.TextStyle = fyne.TextStyle{Bold: true}
			label.Wrapping = fyne.TextWrapOff
			return container.NewStack(bg, container.NewHBox(bar, container.NewPadded(label)))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(siteRows) {
				return
			}
			rowData := siteRows[id]
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id == currentSite {
				bg.FillColor = color.NRGBA{R: 28, G: 34, B: 52, A: 244}
			} else if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = accentGreen
			bar.Refresh()
			label := main.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
			label.SetText(fmt.Sprintf("%s | A:%s | B:%s",
				rowData.Title,
				emptyFallback(rowData.AResult.Verdict, "-"),
				emptyFallback(rowData.BResult.Verdict, "-"),
			))
		},
	)

	setSiteHeights := func() {
		for i := range siteRows {
			siteList.SetItemHeight(i, 38)
		}
	}

	setRuleDetail := func(ruleName string, result model.TestResult, requestEntry *widget.Entry, responseEntry *widget.Entry, previewHolder *fyne.Container, cacheKey string) {
		requestEntry.SetText(strings.Join([]string{
			"规则: " + emptyFallback(ruleName, "-"),
			"",
			emptyFallback(visiblePacketText(result.SentRequest), "暂无请求包"),
		}, "\n"))

		responseEntry.SetText(strings.Join([]string{
			"判定: " + emptyFallback(result.Verdict, "-"),
			"命中规则: " + emptyFallback(result.MatchedRule, "-"),
			fmt.Sprintf("状态码: %d", result.StatusCode),
			fmt.Sprintf("相似度: 基线 %.2f | 拦截 %.2f | 差异 %.0f%%", result.BaselineSim, result.BlockedSim, result.DiffRatio*100),
			"",
			emptyFallback(sourcePreviewText(testResultRawResponse(result)), "暂无响应包"),
		}, "\n"))

		previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(d.testResultSnapshot(result), cacheKey, false)}
		previewHolder.Refresh()
	}
	selectSite := func(index int) {
		if index < 0 || index >= len(siteRows) {
			currentSite = -1
			aRequest.SetText("")
			aResponse.SetText("")
			aPreviewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "rule-compare-a-empty", false)}
			aPreviewHolder.Refresh()
			bRequest.SetText("")
			bResponse.SetText("")
			bPreviewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "rule-compare-b-empty", false)}
			bPreviewHolder.Refresh()
			siteList.Refresh()
			return
		}
		currentSite = index
		row := siteRows[index]
		aCacheKey := "rule-compare-" + siteKeyDigest("a::"+row.SiteKey+"::"+row.ClusterKey+"::"+ruleA)
		bCacheKey := "rule-compare-" + siteKeyDigest("b::"+row.SiteKey+"::"+row.ClusterKey+"::"+ruleB)
		setRuleDetail(ruleA, row.AResult, aRequest, aResponse, aPreviewHolder, aCacheKey)
		setRuleDetail(ruleB, row.BResult, bRequest, bResponse, bPreviewHolder, bCacheKey)
		siteList.Select(index)
		siteList.Refresh()
	}

	selectGroup := func(index int) {
		if index < 0 || index >= len(groups) {
			currentGroup = -1
			siteRows = nil
			groupList.Refresh()
			siteList.Refresh()
			selectSite(-1)
			return
		}
		currentGroup = index
		siteRows = append([]ruleCompareDiffRow(nil), groups[index].Rows...)
		summary.SetText(strings.Join([]string{
			directionTitle,
			fmt.Sprintf("规则A: %s", ruleA),
			fmt.Sprintf("规则B: %s", ruleB),
			fmt.Sprintf("当前分组: %s | %s", groups[index].Title, groups[index].WAF),
			fmt.Sprintf("命中 URL: %d", len(groups[index].Rows)),
		}, "\n"))
		groupList.Refresh()
		siteList.Refresh()
		setSiteHeights()
		selectSite(0)
	}

	groupList.OnSelected = func(id widget.ListItemID) {
		selectGroup(id)
	}
	siteList.OnSelected = func(id widget.ListItemID) {
		selectSite(id)
	}

	buildRuleTabs := func(alias string, ruleName string, accent color.NRGBA, requestEntry *widget.Entry, responseEntry *widget.Entry, previewHolder *fyne.Container) fyne.CanvasObject {
		innerTabs := container.NewAppTabs(
			container.NewTabItem("请求", neonPanel(accent, requestEntry)),
			container.NewTabItem("响应", neonPanel(accentBlue, responseEntry)),
			container.NewTabItem("浏览器快照", neonPanel(accentPink, previewHolder)),
		)
		innerTabs.SelectIndex(0)
		return container.NewBorder(
			neonPanel(accent, widget.NewLabelWithStyle(fmt.Sprintf("%s：%s", alias, ruleName), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})),
			nil,
			nil,
			nil,
			innerTabs,
		)
	}

	detailTabs := container.NewAppTabs(
		container.NewTabItem("A", buildRuleTabs("A", ruleA, accentAmber, aRequest, aResponse, aPreviewHolder)),
		container.NewTabItem("B", buildRuleTabs("B", ruleB, accentBlue, bRequest, bResponse, bPreviewHolder)),
	)
	detailTabs.SelectIndex(0)

	rightLower := container.NewHSplit(
		neonPanel(accentCyan, siteList),
		detailTabs,
	)
	rightLower.Offset = 0.40
	body := container.NewHSplit(
		neonPanel(accentAmber, groupList),
		container.NewBorder(
			neonPanel(accentBlue, summary),
			nil,
			nil,
			nil,
			rightLower,
		),
	)
	body.Offset = 0.30
	selectGroup(0)
	return body
}

func (d *dashboard) showFingerprintViewer() {
	if d.labeledFingerprintCount() == 0 {
		dialog.ShowInformation("没有指纹", "当前还没有已保存的 WAF 识别指纹。", d.window)
		return
	}

	type fingerprintView struct {
		Signature        string
		Label            string
		Source           string
		Hint             string
		MatchDetail      string
		Snapshot         model.ResponseSnapshot
		SnapshotCacheKey string
		UpdatedAt        time.Time
	}

	grouped := d.groupedFingerprints()
	items := make([]fingerprintView, 0, len(grouped))
	for _, fp := range grouped {
		if strings.TrimSpace(fp.Label) == "" {
			continue
		}
		items = append(items, fingerprintView{
			Signature:        fp.Signature,
			Label:            fp.Label,
			Source:           fp.Source,
			Hint:             fp.Hint,
			MatchDetail:      fp.MatchDetail,
			Snapshot:         fp.Snapshot,
			SnapshotCacheKey: fp.SnapshotCacheKey,
			UpdatedAt:        fp.UpdatedAt,
		})
	}
	if len(items) == 0 {
		dialog.ShowInformation("没有指纹", "当前还没有已保存的 WAF 识别指纹。", d.window)
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Label == items[j].Label {
			if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
				return items[i].Signature < items[j].Signature
			}
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].Label < items[j].Label
	})

	source := newSourcePreviewLabel()
	sourceScroll := container.NewScroll(source)
	previewHolder := container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "fingerprint-viewer-empty", false))
	currentSelectedIndex := -1

	list := widget.NewList(
		func() int { return len(items) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 11, G: 17, B: 29, A: 232})
			tint := canvas.NewLinearGradient(
				color.NRGBA{R: 255, G: 255, B: 255, A: 0},
				color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 18},
				0,
			)
			bar := canvas.NewRectangle(color.NRGBA{R: 255, G: 164, B: 182, A: 255})
			bar.SetMinSize(fyne.NewSize(5, 0))
			title := widget.NewLabel("指纹")
			title.TextStyle = fyne.TextStyle{Bold: true}
			title.Wrapping = fyne.TextWrapOff
			content := container.NewVBox(title)
			separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
			separator.SetMinSize(fyne.NewSize(0, 1))
			glow := canvas.NewRectangle(color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 10})
			return container.NewStack(
				bg,
				tint,
				glow,
				container.NewHBox(bar, container.NewPadded(content)),
				container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			row := item.(*fyne.Container)
			isSelected := id == currentSelectedIndex

			bg := row.Objects[0].(*canvas.Rectangle)
			if isSelected {
				bg.FillColor = color.NRGBA{R: 34, G: 28, B: 46, A: 244}
			} else if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 12, G: 18, B: 30, A: 236}
			} else {
				bg.FillColor = color.NRGBA{R: 18, G: 24, B: 38, A: 236}
			}
			bg.Refresh()

			tint := row.Objects[1].(*canvas.LinearGradient)
			if isSelected {
				tint.StartColor = color.NRGBA{R: 255, G: 184, B: 216, A: 18}
				tint.EndColor = color.NRGBA{R: 255, G: 113, B: 171, A: 44}
			} else {
				tint.StartColor = color.NRGBA{R: 255, G: 255, B: 255, A: 0}
				tint.EndColor = color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 18}
			}
			tint.Refresh()

			glow := row.Objects[2].(*canvas.Rectangle)
			if isSelected {
				glow.FillColor = color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 24}
			} else {
				glow.FillColor = color.NRGBA{R: accentPink.R, G: accentPink.G, B: accentPink.B, A: 10}
			}
			glow.Refresh()

			main := row.Objects[3].(*fyne.Container)
			padded := main.Objects[1].(*fyne.Container)
			content := padded.Objects[0].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(items[id].Label)
			row.Refresh()
		},
	)
	for i := range items {
		list.SetItemHeight(i, 44)
	}

	selectFingerprint := func(index int) {
		if index < 0 || index >= len(items) {
			currentSelectedIndex = -1
			source.SetText("")
			previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "fingerprint-viewer-empty", false)}
			previewHolder.Refresh()
			list.Refresh()
			return
		}
		currentSelectedIndex = index
		item := items[index]
		lines := []string{
			"标签名称: " + emptyFallback(item.Label, "-"),
			"标签来源: " + emptyFallback(clusterLabelSourceText(item.Source), "-"),
			"指纹签名: " + emptyFallback(item.Signature, "-"),
			"更新时间: " + item.UpdatedAt.Format("2006-01-02 15:04:05"),
			"识别提示: " + emptyFallback(item.Hint, "-"),
			"规则命中: " + emptyFallback(item.MatchDetail, "-"),
			"代表响应原始报文:",
			emptyFallback(item.Snapshot.Raw, "暂无原始报文"),
		}
		source.SetText(sourcePreviewText(strings.Join(lines, "\n")))
		cacheKey := item.SnapshotCacheKey
		if strings.TrimSpace(cacheKey) == "" {
			cacheKey = "fingerprint-" + item.Signature
		}
		previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(item.Snapshot, cacheKey, false)}
		previewHolder.Refresh()
		list.Select(index)
		list.Refresh()
	}

	list.OnSelected = func(id widget.ListItemID) {
		selectFingerprint(id)
	}

	detailTabs := container.NewAppTabs(
		container.NewTabItem("HTML源码", sourceScroll),
		container.NewTabItem("浏览器快照", previewHolder),
	)
	detailTabs.SelectIndex(1)

	body := container.NewHSplit(
		neonPanel(accentPink, list),
		neonPanel(accentBlue, detailTabs),
	)
	body.Offset = 0.38

	viewer := d.app.NewWindow("WAF识别指纹")
	viewer.Resize(fyne.NewSize(1040, 580))
	viewer.SetContent(body)
	viewer.Show()
	selectFingerprint(0)
}

func (d *dashboard) showRuleViewer() {
	if len(d.plugins) == 0 {
		dialog.ShowInformation("没有规则", "当前还没有可查看的绕过规则。", d.window)
		return
	}

	detail := widget.NewMultiLineEntry()
	detail.Disable()
	detail.SetMinRowsVisible(18)

	list := widget.NewList(
		func() int { return len(d.plugins) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
			bar := canvas.NewRectangle(accentPink)
			bar.SetMinSize(fyne.NewSize(4, 0))
			titleLabel := widget.NewLabel("规则")
			titleLabel.TextStyle = fyne.TextStyle{Bold: true}
			titleLabel.Wrapping = fyne.TextWrapOff
			separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
			separator.SetMinSize(fyne.NewSize(0, 1))
			return container.NewStack(
				bg,
				container.NewHBox(bar, container.NewPadded(titleLabel)),
				container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(d.plugins) {
				return
			}
			p := d.plugins[id]
			accent := pluginAccent(p)
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()

			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = accent
			bar.Refresh()
			titleLabel := main.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
			titleLabel.SetText(p.Name)
		},
	)
	for i := range d.plugins {
		list.SetItemHeight(i, 40)
	}

	formatPluginDetail := func(p model.Plugin) string {
		headers := make([]string, 0, len(p.Headers))
		for key, value := range p.Headers {
			headers = append(headers, key+": "+value)
		}
		sort.Strings(headers)

		raw := strings.TrimSpace(p.Raw)
		if raw == "" {
			lines := []string{p.Method + " " + emptyFallback(p.RequestURI, "/") + " HTTP/1.1"}
			if strings.TrimSpace(p.Host) != "" {
				lines = append(lines, "Host: "+p.Host)
			}
			if len(headers) > 0 {
				lines = append(lines, headers...)
			}
			lines = append(lines, "", emptyFallback(p.Body, "-"))
			raw = strings.Join(lines, "\n")
		}

		templateState := "否"
		if isTemplatePlugin(p) {
			templateState = "是（内置模板，保留但不参与绕过检测/绕过率）"
		}
		preflightMode := "builtin"
		if strings.TrimSpace(p.PreflightMode) != "" {
			preflightMode = strings.TrimSpace(p.PreflightMode)
		}
		preflightPrune := "默认"
		if p.PreflightPrune != nil {
			if *p.PreflightPrune {
				preflightPrune = "true"
			} else {
				preflightPrune = "false"
			}
		}

		return strings.Join([]string{
			"规则名称: " + p.Name,
			"路径: " + p.Path,
			"内置模板: " + templateState,
			"标签: " + emptyFallback(strings.Join(p.Tags, ", "), "-"),
			"展示颜色: " + emptyFallback(p.Color, "自动"),
			"预探测模式: " + preflightMode,
			"预探测删除无效URL: " + preflightPrune,
			"规则意图:\n" + pluginIntentSummary(p),
			"验证模式: " + emptyFallback(p.ValidationMode, "-"),
			fmt.Sprintf("相似度阈值: %.2f", p.SimilarityThreshold),
			"",
			"原始请求:",
			visiblePacketText(raw),
		}, "\n")
	}

	selectRule := func(index int) {
		if index < 0 || index >= len(d.plugins) {
			return
		}
		detail.SetText(formatPluginDetail(d.plugins[index]))
		list.Select(index)
	}

	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(d.plugins) {
			return
		}
		detail.SetText(formatPluginDetail(d.plugins[id]))
	}

	content := container.NewHSplit(
		neonPanel(accentPink, list),
		neonPanel(accentBlue, detail),
	)
	content.Offset = 0.34

	viewer := d.app.NewWindow("绕过规则")
	viewer.Resize(fyne.NewSize(1040, 580))
	viewer.SetContent(content)
	viewer.Show()
	selectRule(0)
}

func (d *dashboard) showBypassViewer() {
	if len(d.sessionBypassResults) == 0 {
		dialog.ShowInformation("没有绕过结果", "当前会话还没有可查看的绕过成功 URL。", d.window)
		return
	}

	items := make([]model.TestResult, 0, len(d.sessionBypassResults))
	for _, result := range d.sessionBypassResults {
		items = append(items, result)
	}
	sort.Slice(items, func(i, j int) bool {
		left := emptyFallback(items[i].Site.URL, items[i].Site.Host)
		right := emptyFallback(items[j].Site.URL, items[j].Site.Host)
		return left < right
	})

	detail := widget.NewMultiLineEntry()
	detail.Disable()
	detail.SetMinRowsVisible(20)

	list := widget.NewList(
		func() int { return len(items) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
			bar := canvas.NewRectangle(accentGreen)
			bar.SetMinSize(fyne.NewSize(4, 0))
			titleLabel := widget.NewLabel("URL")
			titleLabel.TextStyle = fyne.TextStyle{Bold: true}
			titleLabel.Wrapping = fyne.TextWrapOff
			separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
			separator.SetMinSize(fyne.NewSize(0, 1))
			return container.NewStack(
				bg,
				container.NewHBox(bar, container.NewPadded(titleLabel)),
				container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			if id < 0 || id >= len(items) {
				return
			}
			result := items[id]
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()
			titleLabel := row.Objects[1].(*fyne.Container).Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
			titleLabel.SetText(emptyFallback(result.Site.URL, emptyFallback(result.Site.OriginalURL, result.Site.Host)))
		},
	)
	for i := range items {
		list.SetItemHeight(i, 40)
	}

	selectBypass := func(index int) {
		if index < 0 || index >= len(items) {
			return
		}
		result := items[index]
		lines := []string{
			"URL: " + emptyFallback(result.Site.URL, emptyFallback(result.Site.OriginalURL, result.Site.Host)),
			"规则: " + emptyFallback(result.Plugin.Name, "-"),
			"判定: " + emptyFallback(result.Verdict, "-"),
			"命中: " + emptyFallback(result.MatchedRule, "-"),
			"",
			"绕过数据包:",
			emptyFallback(visiblePacketText(result.SentRequest), "暂无请求包"),
		}
		detail.SetText(strings.Join(lines, "\n"))
		list.Select(index)
	}

	list.OnSelected = func(id widget.ListItemID) {
		selectBypass(id)
	}

	body := container.NewHSplit(
		neonPanel(accentGreen, list),
		neonPanel(accentBlue, detail),
	)
	body.Offset = 0.36

	viewer := d.app.NewWindow("绕过成功")
	viewer.Resize(fyne.NewSize(1100, 600))
	viewer.SetContent(body)
	viewer.Show()
	selectBypass(0)
}

func (d *dashboard) clusterViewByKey(clusterKey string) (clusterView, bool) {
	for _, cluster := range d.clusterViews() {
		if cluster.Key == clusterKey {
			return cluster, true
		}
	}
	return clusterView{}, false
}

func (d *dashboard) showBypassClusterDetailViewer(clusterKey string) {
	clusterKey = strings.TrimSpace(clusterKey)
	if clusterKey == "" {
		return
	}

	viewer := d.app.NewWindow("聚类绕过详情")
	viewer.Resize(fyne.NewSize(1120, 680))
	viewer.SetContent(buildBrowserSnapshotLoading("正在加载聚类详情..."))
	viewer.Show()

	go func() {
		cluster, ok := d.clusterViewByKey(clusterKey)
		if !ok {
			d.runOnUI(func() {
				viewer.Close()
				dialog.ShowInformation("没有聚类详情", "当前没有找到对应的聚类分组。", d.window)
			})
			return
		}

		rows := d.buildClusterResultRows(clusterKey)
		if len(rows) == 0 {
			d.runOnUI(func() {
				viewer.Close()
				dialog.ShowInformation("没有验证明细", "当前聚类在本轮规则验证中还没有可展示的站点明细。", d.window)
			})
			return
		}

		passedSites := 0
		failedSites := 0
		totalAttempts := 0
		for _, row := range rows {
			totalAttempts += row.Attempts
			if row.Passed {
				passedSites++
			} else {
				failedSites++
			}
		}

		summaryText := strings.Join([]string{
			"聚类标签: " + emptyFallback(cluster.Label, "待标注"),
			"标签来源: " + emptyFallback(clusterLabelSourceText(cluster.LabelSource), "-"),
			"规则命中: " + emptyFallback(d.clusterRuleDetails[cluster.Key], "-"),
			"聚类键: " + emptyFallback(cluster.Key, "-"),
			"聚类签名: " + emptyFallback(cluster.Signature, "-"),
			fmt.Sprintf("组内站点: %d", cluster.Count),
			fmt.Sprintf("本轮验证: 站点 %d | 满足相似度 %d | 未满足 %d | 规则尝试 %d", len(rows), passedSites, failedSites, totalAttempts),
			"代表站点:\n" + strings.Join(cluster.SampleSites, "\n"),
		}, "\n")

		d.runOnUI(func() {
			summary := widget.NewMultiLineEntry()
			summary.Disable()
			summary.SetMinRowsVisible(8)
			summary.SetText(summaryText)

			source := newSourcePreviewLabel()
			sourceScroll := container.NewScroll(source)
			previewHolder := container.NewMax(d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "bypass-cluster-viewer-empty", false))

			currentSelected := -1
			list := widget.NewList(
				func() int { return len(rows) },
				func() fyne.CanvasObject {
					bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
					bar := canvas.NewRectangle(accentBlue)
					bar.SetMinSize(fyne.NewSize(4, 0))
					lineLabel := widget.NewLabel("站点")
					lineLabel.TextStyle = fyne.TextStyle{Bold: true}
					lineLabel.Wrapping = fyne.TextWrapOff
					separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
					separator.SetMinSize(fyne.NewSize(0, 1))
					return container.NewStack(
						bg,
						container.NewHBox(bar, container.NewPadded(lineLabel)),
						container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
					)
				},
				func(id widget.ListItemID, item fyne.CanvasObject) {
					if id < 0 || id >= len(rows) {
						return
					}
					rowData := rows[id]
					row := item.(*fyne.Container)
					bg := row.Objects[0].(*canvas.Rectangle)
					if id == currentSelected {
						bg.FillColor = color.NRGBA{R: 28, G: 34, B: 52, A: 244}
					} else if id%2 == 0 {
						bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
					} else {
						bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
					}
					bg.Refresh()

					main := row.Objects[1].(*fyne.Container)
					bar := main.Objects[0].(*canvas.Rectangle)
					accent := verdictAccent(rowData.Verdict)
					if !rowData.Passed {
						accent = accentAmber
					}
					bar.FillColor = accent
					bar.Refresh()
					lineLabel := main.Objects[1].(*fyne.Container).Objects[0].(*widget.Label)
					lineLabel.SetText(fmt.Sprintf("%s | 基线 %.2f | 拦截 %.2f | 差异 %.0f%% | %s | %d/%d",
						rowData.Title,
						rowData.BaselineSim,
						rowData.BlockedSim,
						rowData.DiffRatio*100,
						emptyFallback(rowData.Verdict, "-"),
						rowData.Successes,
						rowData.Attempts,
					))
					row.Refresh()
				},
			)
			for i := range rows {
				list.SetItemHeight(i, 36)
			}

			selectSite := func(index int) {
				if index < 0 || index >= len(rows) {
					currentSelected = -1
					source.SetText("")
					previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "bypass-cluster-viewer-empty", false)}
					previewHolder.Refresh()
					list.Refresh()
					return
				}
				currentSelected = index
				row := rows[index]
				lines := []string{
					"站点: " + emptyFallback(row.URL, row.Title),
					"判定: " + emptyFallback(row.Verdict, "-"),
					"规则: " + emptyFallback(row.RuleName, "-"),
					"命中规则: " + emptyFallback(row.MatchedRule, "-"),
					fmt.Sprintf("相似度: 基线 %.2f | 拦截 %.2f | 差异 %.0f%%", row.BaselineSim, row.BlockedSim, row.DiffRatio*100),
					fmt.Sprintf("统计: %d/%d 命中相似度", row.Successes, row.Attempts),
					fmt.Sprintf("状态码: %d", row.StatusCode),
					"",
					"HTTP 响应原文:",
					emptyFallback(row.RawResponse, "暂无原始报文"),
				}
				source.SetText(sourcePreviewText(strings.Join(lines, "\n")))
				cacheKey := "bypass-viewer-" + siteKeyDigest(row.ClusterKey+"::"+row.SiteKey+"::"+row.RuleName)
				previewHolder.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(row.Snapshot, cacheKey, false)}
				previewHolder.Refresh()
				list.Select(index)
				list.Refresh()
			}

			list.OnSelected = func(id widget.ListItemID) {
				selectSite(id)
			}

			detailTabs := container.NewAppTabs(
				container.NewTabItem("HTML源码", sourceScroll),
				container.NewTabItem("浏览器快照", previewHolder),
			)
			detailTabs.SelectIndex(1)

			lower := container.NewHSplit(
				neonPanel(accentCyan, list),
				neonPanel(accentBlue, detailTabs),
			)
			lower.Offset = 0.42
			body := container.NewBorder(
				neonPanel(accentBlue, summary),
				nil,
				nil,
				nil,
				lower,
			)

			viewer.SetContent(body)
			selectSite(d.preferredClusterResultIndex(rows, ""))
		})
	}()
}

func (d *dashboard) showSiteViewer(title string, sites []model.Site, emptyTitle string, emptyMessage string, compact bool) {
	if len(sites) == 0 {
		dialog.ShowInformation(emptyTitle, emptyMessage, d.window)
		return
	}

	detail := widget.NewMultiLineEntry()
	detail.Disable()
	detail.SetMinRowsVisible(12)

	list := widget.NewList(
		func() int { return len(sites) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.NRGBA{R: 12, G: 18, B: 30, A: 220})
			bar := canvas.NewRectangle(accentCyan)
			bar.SetMinSize(fyne.NewSize(4, 0))
			titleLabel := widget.NewLabel("URL")
			titleLabel.TextStyle = fyne.TextStyle{Bold: true}
			titleLabel.Wrapping = fyne.TextWrapOff
			subtitleLabel := widget.NewLabel("")
			subtitleLabel.Wrapping = fyne.TextWrapOff
			content := container.NewVBox(titleLabel, subtitleLabel)
			separator := canvas.NewRectangle(color.NRGBA{R: 46, G: 58, B: 82, A: 255})
			separator.SetMinSize(fyne.NewSize(0, 1))
			return container.NewStack(
				bg,
				container.NewHBox(bar, container.NewPadded(content)),
				container.NewBorder(nil, separator, nil, nil, layout.NewSpacer()),
			)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			site := sites[id]
			row := item.(*fyne.Container)
			bg := row.Objects[0].(*canvas.Rectangle)
			if id%2 == 0 {
				bg.FillColor = color.NRGBA{R: 10, G: 16, B: 27, A: 228}
			} else {
				bg.FillColor = color.NRGBA{R: 16, G: 22, B: 36, A: 228}
			}
			bg.Refresh()

			main := row.Objects[1].(*fyne.Container)
			bar := main.Objects[0].(*canvas.Rectangle)
			bar.FillColor = wafAccent(d.effectiveSiteWAF(site))
			bar.Refresh()

			padded := main.Objects[1].(*fyne.Container)
			content := padded.Objects[0].(*fyne.Container)
			titleLabel := content.Objects[0].(*widget.Label)
			subtitleLabel := content.Objects[1].(*widget.Label)
			if compact {
				titleLabel.SetText(emptyFallback(site.Domain, emptyFallback(site.Host, emptyFallback(site.OriginalURL, site.URL))))
				subtitleLabel.SetText("")
				subtitleLabel.Hide()
			} else {
				titleLabel.SetText(emptyFallback(site.OriginalURL, emptyFallback(site.URL, site.Host)))
				subtitleLabel.SetText(fmt.Sprintf("%s | %s | %s", d.effectiveSiteWAF(site), emptyFallback(site.Title, site.Domain), emptyFallback(site.Server, site.Product)))
				subtitleLabel.Show()
			}
			row.Refresh()
		},
	)
	for i := range sites {
		if compact {
			list.SetItemHeight(i, 40)
		} else {
			list.SetItemHeight(i, 72)
		}
	}
	list.OnSelected = func(id widget.ListItemID) {
		site := sites[id]
		lines := []string{
			"原始URL: " + emptyFallback(site.OriginalURL, "-"),
			"URL: " + emptyFallback(site.URL, "-"),
			"主机: " + emptyFallback(site.Host, "-"),
			"标题: " + emptyFallback(site.Title, "-"),
			"WAF: " + emptyFallback(d.effectiveSiteWAF(site), "-"),
			"产品: " + emptyFallback(site.Product, "-"),
			"服务端: " + emptyFallback(site.Server, "-"),
		}
		if detection, ok := d.detectionForSite(site); ok {
			lines = append(lines,
				"",
				"识别地址: "+emptyFallback(detection.DetectedURL, "-"),
				fmt.Sprintf("相似度 A: %.2f", detection.SimilarityA),
				fmt.Sprintf("相似度 B: %.2f", detection.SimilarityB),
				"存在 WAF: "+boolText(detection.HasWAF),
			)
		}
		detail.SetText(strings.Join(lines, "\n"))
	}

	body := container.NewHSplit(
		neonPanel(accentCyan, list),
		neonPanel(accentBlue, detail),
	)
	if compact {
		body.Offset = 0.5
	} else {
		body.Offset = 0.58
	}

	viewer := d.app.NewWindow(title)
	viewer.Resize(fyne.NewSize(980, 560))
	viewer.SetContent(body)
	viewer.Show()
	list.Select(0)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func csvToInts(raw string) []int {
	values := splitCSV(raw)
	out := make([]int, 0, len(values))
	for _, value := range values {
		n, err := strconv.Atoi(value)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

func intsToCSV(values []int) string {
	chunks := make([]string, 0, len(values))
	for _, value := range values {
		chunks = append(chunks, strconv.Itoa(value))
	}
	return strings.Join(chunks, ",")
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

const (
	sourcePreviewRuneLimit = 80000
	sourcePreviewLineWidth = 180
)

func newSourcePreviewLabel() *widget.Label {
	label := widget.NewLabel("")
	label.Wrapping = fyne.TextWrapOff
	label.TextStyle = fyne.TextStyle{Monospace: true}
	return label
}

func sourcePreviewText(value string) string {
	if value == "" {
		return ""
	}
	preview, truncated := truncateRunes(value, sourcePreviewRuneLimit)
	text := wrapLongSourceLines(visiblePacketText(preview), sourcePreviewLineWidth)
	if truncated {
		text += fmt.Sprintf("\n\n... 已截断，仅显示前 %d 个字符，避免大源码拖选导致界面卡顿。", sourcePreviewRuneLimit)
	}
	return text
}

func truncateRunes(value string, limit int) (string, bool) {
	if limit <= 0 {
		return "", value != ""
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index], true
		}
		count++
	}
	return value, false
}

func wrapLongSourceLines(value string, width int) string {
	if width <= 0 || value == "" {
		return value
	}
	var out strings.Builder
	column := 0
	for _, r := range value {
		if r == '\n' {
			out.WriteRune(r)
			column = 0
			continue
		}
		if column >= width {
			out.WriteByte('\n')
			column = 0
		}
		out.WriteRune(r)
		column++
	}
	return out.String()
}

func visiblePacketText(value string) string {
	if value == "" {
		return ""
	}
	var out strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			out.WriteString(fmt.Sprintf("[0x%02X]", value[0]))
			value = value[1:]
			continue
		}
		if r == '\n' {
			out.WriteByte('\n')
			value = value[size:]
			continue
		}
		if r < 0x20 || r == 0x7f {
			out.WriteString(fmt.Sprintf("[0x%02X]", r))
			value = value[size:]
			continue
		}
		out.WriteRune(r)
		value = value[size:]
	}
	return out.String()
}
