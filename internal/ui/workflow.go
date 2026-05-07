package ui

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"image/color"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"wafbps/internal/detector"
	"wafbps/internal/exporter"
	"wafbps/internal/model"
	"wafbps/internal/store"
)

type workflowStep struct {
	Title    string
	Subtitle string
	Accent   color.NRGBA
	Icon     fyne.Resource
}

type staticStepButton struct {
	widget.BaseWidget
	title    string
	icon     fyne.Resource
	bgColor  color.NRGBA
	onTapped func()
}

func newStaticStepButton(title string, icon fyne.Resource, bgColor color.NRGBA, onTapped func()) *staticStepButton {
	btn := &staticStepButton{
		title:    title,
		icon:     icon,
		bgColor:  bgColor,
		onTapped: onTapped,
	}
	btn.ExtendBaseWidget(btn)
	return btn
}

func (b *staticStepButton) Tapped(*fyne.PointEvent) {
	if b.onTapped != nil {
		b.onTapped()
	}
}

func (b *staticStepButton) CreateRenderer() fyne.WidgetRenderer {
	bg := canvas.NewRectangle(b.bgColor)
	icon := themedIcon(b.icon, 18)
	label := widget.NewLabel(b.title)
	label.Wrapping = fyne.TextWrapOff
	content := container.NewPadded(container.NewCenter(container.NewHBox(icon, label)))
	return &staticStepButtonRenderer{
		button:  b,
		bg:      bg,
		content: content,
		objects: []fyne.CanvasObject{bg, content},
	}
}

type staticStepButtonRenderer struct {
	button  *staticStepButton
	bg      *canvas.Rectangle
	content *fyne.Container
	objects []fyne.CanvasObject
}

func (r *staticStepButtonRenderer) Layout(size fyne.Size) {
	r.bg.Resize(size)
	r.content.Resize(size)
}

func (r *staticStepButtonRenderer) MinSize() fyne.Size {
	return r.content.MinSize()
}

func (r *staticStepButtonRenderer) Refresh() {
	r.bg.FillColor = r.button.bgColor
	r.bg.Refresh()
	r.content.Refresh()
}

func (r *staticStepButtonRenderer) Destroy() {}

func (r *staticStepButtonRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

func (r *staticStepButtonRenderer) BackgroundColor() color.Color {
	return color.Transparent
}

type clusterView struct {
	Key         string
	Label       string
	LabelSource string
	Signature   string
	SampleHost  string
	SampleSites []string
	Count       int
	IsNew       bool
}

type clusterBucket struct {
	key            string
	label          string
	representative model.DetectionResult
	members        []string
}

type previousClusterInfo struct {
	key       string
	label     string
	signature string
	snapshot  model.ResponseSnapshot
}

var (
	sampleWordPoolOnce sync.Once
	sampleEnglishWords []string
	sampleChineseWords []string
)

const (
	sampleNumberMin = 1000
	sampleNumberMax = 999999
)

func workflowSteps() []workflowStep {
	return []workflowStep{
		{Title: "目标采集", Subtitle: "", Accent: accentCyan, Icon: radarResource()},
		{Title: "WAF识别", Subtitle: "", Accent: accentAmber, Icon: shieldResource()},
		{Title: "响应聚类", Subtitle: "", Accent: accentPink, Icon: shieldResource()},
		{Title: "配置规则", Subtitle: "", Accent: accentPink, Icon: pluginResource()},
		{Title: "绕过验证", Subtitle: "", Accent: accentGreen, Icon: boltResource()},
		{Title: "配置代理", Subtitle: "", Accent: accentBlue, Icon: proxyResource()},
	}
}

func workflowProxyStepAccent() color.NRGBA {
	return color.NRGBA{R: 118, G: 214, B: 255, A: 255}
}

func (d *dashboard) buildWorkflowHeader() fyne.CanvasObject {
	d.queryEntry.SetPlaceHolder("输入 FOFA 查询语句，例如 body=\"login\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"")
	if strings.TrimSpace(d.sizeEntry.Text) == "" || strings.TrimSpace(d.sizeEntry.Text) == "0" {
		d.sizeEntry.SetText("2000")
	} else {
		d.sizeEntry.SetText(sanitizeFOFASizeInput(d.sizeEntry.Text))
	}
	if strings.TrimSpace(d.concurrencyEntry.Text) == "" || strings.TrimSpace(d.concurrencyEntry.Text) == "0" {
		d.concurrencyEntry.SetText("100")
	}
	if strings.TrimSpace(d.snapshotConcurrencyEntry.Text) == "" || strings.TrimSpace(d.snapshotConcurrencyEntry.Text) == "0" {
		d.snapshotConcurrencyEntry.SetText("20")
	}
	if d.pipelineCountEntry == nil {
		d.pipelineCountEntry = widget.NewEntry()
		d.pipelineCountEntry.SetText("1")
		d.pipelineCountEntry.OnChanged = func(value string) {
			sanitized := sanitizePipelineCountInput(value)
			if sanitized != value {
				d.pipelineCountEntry.SetText(sanitized)
			}
		}
	}
	if strings.TrimSpace(d.pipelineCountEntry.Text) == "" || strings.TrimSpace(d.pipelineCountEntry.Text) == "0" {
		d.pipelineCountEntry.SetText("1")
	} else {
		d.pipelineCountEntry.SetText(sanitizePipelineCountInput(d.pipelineCountEntry.Text))
	}

	searchBtn := widget.NewButtonWithIcon("搜索", searchResource(), func() {
		d.fetchSites("search")
	})
	pipelineBtn := widget.NewButtonWithIcon("一键执行", playResource(), func() {
		d.runPipeline()
	})
	sampleBtn := widget.NewButtonWithIcon("随机采样", boltResource(), func() {
		if !d.searchRunning {
			keyword := d.randomSampleKeyword()
			d.queryEntry.SetText(keyword)
			d.setStatus(fmt.Sprintf("采集区 // 已生成随机采样关键词 %s，正在自动搜索", keyword))
		}
		d.fetchSites("sample")
	})
	clusterBtn := widget.NewButtonWithIcon("自动聚类", resultResource(), func() {
		d.autoClusterResponses()
	})
	fingerprintBtn := widget.NewButtonWithIcon("自动提取WAF指纹", pluginResource(), func() {
		d.extractClusterFingerprints()
	})
	ruleValidationBtn := widget.NewButtonWithIcon("规则验证", shieldResource(), func() {
		if d.ruleValidationRunning {
			d.stopRuleValidation("用户手动停止")
			return
		}
		d.openRuleValidationDialog()
	})
	ruleCompareBtn := widget.NewButtonWithIcon("规则对比", compareResource(), func() {
		d.openRuleCompareDialog()
	})
	identifyBtn := d.newDetectToggleButton(true)
	d.searchBtn = searchBtn
	d.sampleBtn = sampleBtn
	d.pipelineBtn = pipelineBtn
	d.toolbarDetectBtn = identifyBtn
	d.ruleValidationBtn = ruleValidationBtn
	d.updateSearchButtons()
	d.updateDetectButtons()
	d.updatePipelineButton()
	d.updateRuleValidationButton()
	openAIConfigBtn := widget.NewButtonWithIcon("大模型配置", pluginResource(), func() {
		d.openOpenAISettingsDialog()
	})
	configBtn := widget.NewButtonWithIcon("FOFA配置", shieldResource(), func() {
		d.openSettingsDialog()
	})
	initBtn := widget.NewButtonWithIcon("初始化", shieldResource(), func() {
		dialog.ShowConfirm("初始化数据库", "确认后将清空本地数据库中的扫描记录和结果；手工标记固化的规则会保留。是否继续？", func(ok bool) {
			if !ok {
				return
			}
			backupPath, err := d.resetDatabaseStateWithBackup()
			if err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			d.setStatus(fmt.Sprintf("数据库 // 已初始化并清空本地数据，备份已保存到 %s", backupPath))
		}, d.window)
	})
	exportBtn := widget.NewButtonWithIcon("导出", exportResource(), func() {
		d.exportWorkspaceBundle()
	})
	importBtn := widget.NewButtonWithIcon("导入", importResource(), func() {
		d.openImportWorkspaceDialog()
	})
	agentBtn := newStaticStepButton(
		"智能助手",
		agentResource(),
		color.NRGBA{R: 150, G: 244, B: 185, A: 72},
		func() {
			d.openAgentAssistant()
		},
	)
	pipelineMultiplyIcon := themedIcon(multiplyResource(), 16)

	controlRow := container.NewGridWithColumns(
		12,
		widget.NewLabel("搜索关键词"),
		d.queryEntry,
		widget.NewLabel("目标量"),
		d.sizeEntry,
		d.chinaOnlyCheck,
		widget.NewLabel("线程数量"),
		d.concurrencyEntry,
		widget.NewLabel("快照线程"),
		d.snapshotConcurrencyEntry,
		openAIConfigBtn,
		configBtn,
		initBtn,
	)
	actionRow := container.NewHBox(
		pipelineBtn,
		pipelineMultiplyIcon,
		func() fyne.CanvasObject {
			holder := container.NewGridWrap(fyne.NewSize(48, d.pipelineCountEntry.MinSize().Height))
			holder.Add(d.pipelineCountEntry)
			return holder
		}(),
		sampleBtn,
		searchBtn,
		identifyBtn,
		clusterBtn,
		fingerprintBtn,
		ruleValidationBtn,
		ruleCompareBtn,
		exportBtn,
		importBtn,
		agentBtn,
		layout.NewSpacer(),
	)

	stats := container.NewGridWithColumns(
		5,
		func() fyne.CanvasObject {
			viewBtn := widget.NewButton("查看", func() {
				d.showSuspectedViewer()
			})
			viewBtn.Importance = widget.LowImportance
			return neonPanel(accentCyan, container.NewVBox(
				container.NewHBox(
					captionText("站点 / 疑似WAF"),
					layout.NewSpacer(),
					d.suspectedDeltaValue,
				),
				container.NewHBox(
					d.siteCountValue,
					canvas.NewText(" / ", color.NRGBA{R: 148, G: 176, B: 224, A: 210}),
					d.suspectedValue,
				),
				container.NewHBox(
					d.siteDeltaValue,
					layout.NewSpacer(),
					viewBtn,
				),
			))
		}(),
		metricActionDeltaObjectDetailCard("已聚类数", container.NewHBox(
			d.clusterCountValue,
			canvas.NewText("  ", color.Transparent),
			d.clusterPendingValue,
		), d.clusterDeltaValue, d.clusterMetricBar, accentBlue, "查看", func() {
			d.showClusterViewer()
		}),
		metricActionDeltaDetailCard("WAF识别指纹", d.labeledValue, d.labeledDeltaValue, d.fingerprintMetricBar, accentPink, "查看", func() {
			d.showFingerprintViewer()
		}),
		metricActionCard("绕过规则", d.pluginCountValue, color.NRGBA{R: 186, G: 150, B: 255, A: 255}, "查看", func() {
			d.showRuleViewer()
		}),
		func() fyne.CanvasObject {
			viewBtn := widget.NewButton("查看", func() {
				d.showBypassViewer()
			})
			viewBtn.Importance = widget.LowImportance
			return neonPanel(accentGreen, container.NewVBox(
				container.NewHBox(
					captionText("绕过成功"),
					layout.NewSpacer(),
				),
				container.NewHBox(
					d.possibleValue,
					canvas.NewText(" ", color.Transparent),
					d.possibleSlashValue,
					canvas.NewText(" ", color.Transparent),
					d.possibleTotalValue,
				),
				container.NewHBox(layout.NewSpacer(), viewBtn),
			))
		}(),
	)

	return neonPanel(accentCyan, container.NewVBox(
		controlRow,
		actionRow,
		stats,
	))
}

func (d *dashboard) randomSampleKeyword() string {
	return d.randomDictionaryWord()
}

func (d *dashboard) randomDictionaryWord() string {
	sampleWordPoolOnce.Do(func() {
		sampleEnglishWords = loadEmbeddedWordList("wordlist_en.txt")
		sampleChineseWords = loadEmbeddedWordList("wordlist_zh.txt")
	})

	d.sampleWordMu.Lock()
	if d.usedSampleWords == nil {
		d.usedSampleWords = map[string]bool{}
	}

	options := make([]string, 0, len(sampleEnglishWords)+len(sampleChineseWords)+64)
	for _, word := range sampleEnglishWords {
		if !d.usedSampleWords[word] {
			options = append(options, word)
		}
	}
	for _, word := range sampleChineseWords {
		if !d.usedSampleWords[word] {
			options = append(options, word)
		}
	}

	var keyword string
	switch {
	case len(options) > 0:
		keyword = options[cryptoIntn(len(options))]
	default:
		for attempts := 0; attempts < 1024; attempts++ {
			candidate := randomNumberToken()
			if d.usedSampleWords[candidate] {
				continue
			}
			keyword = candidate
			break
		}
	}
	if strings.TrimSpace(keyword) == "" {
		keyword = fmt.Sprintf("%d", sampleNumberMin+cryptoIntn(sampleNumberMax-sampleNumberMin+1))
	}

	d.usedSampleWords[keyword] = true
	d.sampleWordMu.Unlock()
	if d.dbState.UsedSamples == nil {
		d.dbState.UsedSamples = map[string]bool{}
	}
	d.dbState.UsedSamples[keyword] = true
	d.persistCurrentDBStateAsync()
	return keyword
}

func loadEmbeddedWordList(name string) []string {
	data, err := embeddedAssets.ReadFile("assets/" + name)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	words := make([]string, 0, len(lines))
	for _, line := range lines {
		word := strings.TrimSpace(line)
		if word == "" || strings.HasPrefix(word, "#") || seen[word] || !isSafeSampleWord(word) {
			continue
		}
		seen[word] = true
		words = append(words, word)
	}
	return words
}

func isSafeSampleWord(word string) bool {
	lower := strings.ToLower(strings.TrimSpace(word))
	if lower == "" {
		return false
	}

	englishBlockedExact := map[string]bool{
		"adult": true, "anal": true, "ass": true, "assault": true, "bomb": true, "bullet": true,
		"casino": true, "cocaine": true, "communist": true, "court": true, "crime": true,
		"dead": true, "death": true, "drugs": true, "erotic": true, "escort": true,
		"fight": true, "firearm": true, "government": true, "gun": true, "guns": true,
		"kill": true, "killed": true, "killing": true, "knife": true, "murder": true,
		"military": true, "nazi": true, "nude": true, "nudity": true, "orgasm": true,
		"party": true, "penis": true, "police": true, "politic": true, "politics": true,
		"porn": true, "porno": true, "president": true, "prostitute": true, "pussy": true,
		"rape": true, "regime": true, "revolt": true, "rifle": true, "sex": true,
		"sexual": true, "shoot": true, "slut": true, "terror": true, "terrorist": true,
		"vagina": true, "violence": true, "violent": true, "war": true, "weapon": true,
		"weapons": true, "xxx": true,
	}
	englishBlockedContains := []string{
		"porn", "sex", "nude", "naked", "erot", "xxx", "weapon", "terror", "murder",
		"kill", "shoot", "bomb", "violent", "politic", "govern", "president", "military",
	}
	chineseBlockedContains := []string{
		"政治", "政府", "国家", "中国", "主席", "总书记", "共产党", "选举", "外交", "维权", "军", "军事", "部队",
		"警察", "法院", "税务", "色情", "成人", "裸", "乳", "阴", "肛", "性", "约炮", "开房",
		"暴力", "杀", "枪", "刀", "炸", "恐怖", "血腥", "博彩", "赌博", "毒品",
	}

	if isASCIIWord(lower) {
		if englishBlockedExact[lower] {
			return false
		}
		for _, blocked := range englishBlockedContains {
			if strings.Contains(lower, blocked) {
				return false
			}
		}
		return true
	}
	for _, blocked := range chineseBlockedContains {
		if strings.Contains(word, blocked) {
			return false
		}
	}
	return true
}

func isASCIIWord(word string) bool {
	for _, r := range word {
		if r > 127 {
			return false
		}
	}
	return true
}

func randomNumberToken() string {
	span := sampleNumberMax - sampleNumberMin + 1
	return fmt.Sprintf("%d", sampleNumberMin+cryptoIntn(span))
}

func cryptoIntn(max int) int {
	if max <= 1 {
		return 0
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func (d *dashboard) buildWorkflowNav() fyne.CanvasObject {
	steps := workflowSteps()
	d.workflowList = widget.NewList(
		func() int { return len(steps) },
		func() fyne.CanvasObject {
			badge := listBadge(accentCyan, radarResource())
			title := widget.NewLabel("步骤")
			title.TextStyle = fyne.TextStyle{Bold: true}
			subtitle := widget.NewLabel("说明")
			subtitle.Wrapping = fyne.TextWrapWord
			meta := widget.NewLabel("状态")
			meta.Wrapping = fyne.TextWrapWord
			return container.NewHBox(badge, container.NewVBox(title, subtitle, meta))
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			step := steps[id]
			row := item.(*fyne.Container)
			row.Objects[0] = listBadge(step.Accent, step.Icon)
			content := row.Objects[1].(*fyne.Container)
			content.Objects[0].(*widget.Label).SetText(fmt.Sprintf("%d. %s", id+1, step.Title))
			content.Objects[1].(*widget.Label).SetText(step.Subtitle)
			content.Objects[2].(*widget.Label).SetText(d.workflowSummaryText(id))
			row.Refresh()
		},
	)
	d.workflowList.OnSelected = func(id widget.ListItemID) {
		d.gotoStep(id)
	}
	d.workflowList.Select(d.currentStep)

	return neonPanel(accentAmber, container.NewBorder(
		sectionHeading(accentAmber, siteResource(), "工作流", ""),
		nil,
		nil,
		nil,
		d.workflowList,
	))
}

func (d *dashboard) buildWorkflowTopBar() fyne.CanvasObject {
	steps := workflowSteps()
	d.workflowButtons = nil
	items := make([]fyne.CanvasObject, 0, len(steps))
	for idx, step := range steps {
		index := idx
		title := fmt.Sprintf("%d. %s", index+1, step.Title)
		bgColor := color.NRGBA{R: 0, G: 0, B: 0, A: 0}
		if index == 5 {
			bgColor = color.NRGBA{R: 118, G: 214, B: 255, A: 34}
		}
		button := newStaticStepButton(title, step.Icon, bgColor, func() {
			d.gotoStep(index)
		})
		items = append(items, button)
	}

	return neonPanel(accentAmber, container.NewGridWithColumns(len(items), items...))
}

func (d *dashboard) buildDetailDrawer() fyne.CanvasObject {
	d.detailTabs = nil
	empty := widget.NewLabel("当前没有规则绕过率数据。完成规则验证后，这里会显示每条规则的整体绕过率。")
	empty.Wrapping = fyne.TextWrapWord
	content := fyne.CanvasObject(empty)
	if d.ruleStatsList != nil {
		content = d.ruleStatsList
	}
	title := widget.NewLabelWithStyle("规则绕过率", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	title.Wrapping = fyne.TextWrapOff
	iconTitle := container.NewHBox(
		themedIcon(resultResource(), 20),
		title,
	)
	header := container.NewBorder(
		nil,
		nil,
		container.NewGridWrap(fyne.NewSize(118, 24), iconTitle),
		nil,
		layout.NewSpacer(),
		d.ruleStatsSummary,
	)
	return neonPanel(accentBlue, container.NewBorder(
		header,
		nil,
		nil,
		nil,
		content,
	))
}

func (d *dashboard) buildCurrentStep() fyne.CanvasObject {
	switch d.currentStep {
	case 0:
		return d.buildCollectionStep()
	case 1:
		return d.buildIdentifyStep()
	case 2:
		return d.buildClusterStep()
	case 3:
		return d.buildCollectionStep()
	case 4:
		return d.buildCollectionStep()
	case 5:
		return d.buildProxyStep()
	default:
		return d.buildCollectionStep()
	}
}

func (d *dashboard) buildCollectionStep() fyne.CanvasObject {
	return d.buildBypassStatsCard()
}

func (d *dashboard) buildIdentifyStep() fyne.CanvasObject {
	d.identifyDetectBtn = nil
	return d.buildCollectionStep()
}

func (d *dashboard) buildClusterStep() fyne.CanvasObject {
	return d.buildCollectionStep()
}

func (d *dashboard) buildBypassStep() fyne.CanvasObject {
	actions := container.NewHBox(
		widget.NewButtonWithIcon("运行当前规则", boltResource(), func() {
			d.runSelectedPlugin()
		}),
		widget.NewButtonWithIcon("批量验证", radarResource(), func() {
			d.runAllPlugins()
		}),
		widget.NewButtonWithIcon("导出报告", resultResource(), func() {
			d.exportResults("html")
		}),
	)

	ruleTree := neonPanel(accentPink, container.NewBorder(
		sectionHeading(accentPink, pluginResource(), "规则库树", ""),
		nil,
		nil,
		nil,
		d.buildPluginTree(),
	))

	resultPanel := neonPanel(accentGreen, container.NewBorder(
		container.NewHBox(sectionHeading(accentGreen, resultResource(), "批量验证结果", ""), layout.NewSpacer(), actions),
		nil,
		nil,
		nil,
		d.resultList,
	))

	return container.NewHSplit(ruleTree, resultPanel)
}

func (d *dashboard) buildProxyStep() fyne.CanvasObject {
	summary := widget.NewMultiLineEntry()
	summary.Disable()
	summary.SetMinRowsVisible(14)
	summary.SetText(strings.Join([]string{
		"代理配置 //",
		"",
		fmt.Sprintf("上行代理: %s", d.proxyUpstreamSummary()),
		fmt.Sprintf("下行代理: %s", d.proxyDownstreamSummary()),
		fmt.Sprintf("HTTPS证书: %s", d.proxyDownstreamCertSummary()),
		"",
		"上行代理会统一作用于 FOFA、WAF 识别、规则验证和智能体请求。",
		"下行代理用于维护监听地址、协议与 HTTPS 证书材料，支持 socks5。",
	}, "\n"))

	cards := container.NewGridWithColumns(
		3,
		iconChip(accentBlue, shieldResource(), "上行代理", d.proxyUpstreamSummary()),
		iconChip(accentAmber, radarResource(), "下行代理", d.proxyDownstreamSummary()),
		iconChip(accentPink, resultResource(), "证书状态", d.proxyDownstreamCertSummary()),
	)

	return container.NewVBox(
		cards,
		neonPanel(accentBlue, container.NewBorder(
			container.NewHBox(
				sectionHeading(accentBlue, shieldResource(), "配置代理", ""),
				layout.NewSpacer(),
				widget.NewButtonWithIcon("打开代理中心", shieldResource(), func() {
					d.openProxySettingsDialog()
				}),
			),
			nil,
			nil,
			nil,
			summary,
		)),
	)
}

func (d *dashboard) buildLibraryStep() fyne.CanvasObject {
	d.syncLibraryFilterOptions()

	filters := container.NewGridWithColumns(
		2,
		widget.NewLabel("技术点/关键字"),
		d.libraryTagEntry,
	)

	actions := container.NewHBox(
		widget.NewButtonWithIcon("重载规则", pluginResource(), func() {
			d.reloadPlugins()
		}),
		widget.NewButtonWithIcon("查看当前规则", shieldResource(), func() {
			d.updatePluginDetails()
			d.setStatus("规则库 // 已刷新当前规则详情")
		}),
		widget.NewButtonWithIcon("导出当前规则", resultResource(), func() {
			d.exportCurrentPlugin()
		}),
	)

	return container.NewVBox(
		neonPanel(accentPink, container.NewVBox(
			sectionHeading(accentPink, pluginResource(), "规则库", ""),
			filters,
			actions,
		)),
		neonPanel(accentPink, container.NewBorder(
			sectionHeading(accentPink, pluginResource(), "规则列表", ""),
			nil,
			nil,
			nil,
			d.buildPluginTree(),
		)),
	)
}

func (d *dashboard) buildPluginTree() fyne.CanvasObject {
	treeData := map[string][]string{"": {}}
	indexByLeaf := map[string]int{}
	indices := d.visiblePluginIndices(d.currentStep == 3)

	byTag := map[string][]int{}
	for _, i := range indices {
		p := d.plugins[i]
		tag := "未分类技术点"
		if len(p.Tags) > 0 && strings.TrimSpace(p.Tags[0]) != "" {
			tag = p.Tags[0]
		}
		byTag[tag] = append(byTag[tag], i)
	}

	tags := make([]string, 0, len(byTag))
	for tag := range byTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	treeData[""] = tags

	for _, tag := range tags {
		indices := byTag[tag]
		children := make([]string, 0, len(indices))
		for _, idx := range indices {
			leaf := fmt.Sprintf("%s/%s", tag, d.plugins[idx].Name)
			indexByLeaf[leaf] = idx
			children = append(children, leaf)
		}
		sort.Strings(children)
		treeData[tag] = children
	}

	tree := widget.NewTree(
		func(uid string) []string {
			return treeData[uid]
		},
		func(uid string) bool {
			_, ok := treeData[uid]
			return ok
		},
		func(branch bool) fyne.CanvasObject {
			icon := themedIcon(pluginResource(), 16)
			label := widget.NewLabel("节点")
			return container.NewHBox(icon, label)
		},
		func(uid string, branch bool, obj fyne.CanvasObject) {
			row := obj.(*fyne.Container)
			label := row.Objects[1].(*widget.Label)
			if uid == "" {
				label.SetText("规则库")
				return
			}
			parts := strings.Split(uid, "/")
			label.SetText(parts[len(parts)-1])
		},
	)

	tree.OnSelected = func(uid string) {
		if idx, ok := indexByLeaf[uid]; ok {
			d.selectedPlugin = idx
			d.updatePluginDetails()
			d.refreshCockpit()
		}
	}

	return tree
}

func (d *dashboard) visiblePluginIndices(applyLibraryFilter bool) []int {
	out := make([]int, 0, len(d.plugins))
	tagKeyword := ""
	if applyLibraryFilter {
		tagKeyword = strings.ToLower(strings.TrimSpace(d.libraryTagEntry.Text))
	}
	for i, plugin := range d.plugins {
		if applyLibraryFilter && tagKeyword != "" {
			joined := strings.ToLower(strings.Join(append([]string{plugin.Name}, plugin.Tags...), " "))
			if !strings.Contains(joined, tagKeyword) {
				continue
			}
		}
		out = append(out, i)
	}
	return out
}

func (d *dashboard) workflowSummaryText(step int) string {
	switch step {
	case 0:
		return fmt.Sprintf("已采集 %d 条 URL", len(d.sites))
	case 1:
		return fmt.Sprintf("疑似 WAF %d 个", d.suspectedSiteCount())
	case 2:
		return fmt.Sprintf("聚类 %d 组 / 已标注 %d 组 / 已忽略 %d 组", d.totalClusterGroupCount(), d.labeledClusterCount(), d.ignoredClusterCount())
	case 3:
		return fmt.Sprintf("产品 %d 个 / 规则 %d 条", d.libraryProductCount(), len(d.plugins))
	case 4:
		return fmt.Sprintf("规则 %d 条 / 结果 %d 条", len(d.plugins), len(d.results))
	case 5:
		return "网络参数与代理入口"
	default:
		return "待命"
	}
}

func (d *dashboard) rebuildClusterMembers() {
	members := make(map[string][]string)
	for key, detection := range d.detections {
		clusterKey := strings.TrimSpace(detection.ClusterKey)
		if !detection.HasWAF || clusterKey == "" {
			continue
		}
		members[clusterKey] = append(members[clusterKey], key)
	}
	d.clusterMembers = members
	d.invalidateClusterViewCache()
}

func (d *dashboard) invalidateClusterViewCache() {
	d.clusterViewsDirty = true
	d.clusterViewCache = nil
}

func cloneClusterViews(src []clusterView) []clusterView {
	if len(src) == 0 {
		return []clusterView{}
	}
	dst := make([]clusterView, len(src))
	for i, view := range src {
		dst[i] = view
		if len(view.SampleSites) > 0 {
			dst[i].SampleSites = append([]string(nil), view.SampleSites...)
		}
	}
	return dst
}

func (d *dashboard) allClusterViews() []clusterView {
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}
	if !d.clusterViewsDirty && d.clusterViewCache != nil {
		return cloneClusterViews(d.clusterViewCache)
	}

	source := make([]clusterView, 0, len(d.clusterMembers))
	for clusterKey, memberKeys := range d.clusterMembers {
		if len(memberKeys) == 0 {
			continue
		}
		view := clusterView{
			Key:         clusterKey,
			SampleSites: []string{},
			Count:       len(memberKeys),
			IsNew:       d.isRecentCluster(clusterKey),
		}
		seenURLs := map[string]bool{}
		for _, memberKey := range memberKeys {
			detection, ok := d.detections[memberKey]
			if !ok {
				continue
			}
			if view.Signature == "" {
				view.Signature = detection.ClusterHint
			}
			if view.Label == "" {
				view.Label = d.clusterLabelForDetection(detection)
				view.LabelSource = d.clusterLabelSource(clusterKey, detection)
			}
			url := d.clusterSiteURL(detection.Site)
			if url == "" {
				continue
			}
			if view.SampleHost == "" {
				view.SampleHost = url
			}
			if !seenURLs[url] && len(view.SampleSites) < 10 {
				seenURLs[url] = true
				view.SampleSites = append(view.SampleSites, url)
			}
		}
		source = append(source, view)
	}

	sort.Slice(source, func(i, j int) bool {
		leftLabeled := strings.TrimSpace(source[i].Label) != ""
		rightLabeled := strings.TrimSpace(source[j].Label) != ""
		clusterRank := func(view clusterView, labeled bool) int {
			if view.IsNew {
				return 0
			}
			if !labeled {
				return 1
			}
			return 2
		}
		leftRank := clusterRank(source[i], leftLabeled)
		rightRank := clusterRank(source[j], rightLabeled)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if source[i].Count == source[j].Count {
			return source[i].Key < source[j].Key
		}
		return source[i].Count > source[j].Count
	})
	d.clusterViewCache = cloneClusterViews(source)
	d.clusterViewsDirty = false
	return cloneClusterViews(source)
}

func (d *dashboard) buildClusterBaseline() []store.ClusterBaselineItem {
	clusters := d.allClusterViews()
	items := make([]store.ClusterBaselineItem, 0, len(clusters))
	for _, cluster := range clusters {
		signature := strings.TrimSpace(cluster.Signature)
		if signature == "" {
			signature = strings.TrimSpace(detector.FingerprintSignature(d.clusterBlockedSnapshot(cluster.Key)))
		}
		items = append(items, store.ClusterBaselineItem{
			Key:       strings.TrimSpace(cluster.Key),
			Label:     strings.TrimSpace(cluster.Label),
			Signature: signature,
		})
	}
	return items
}

func (d *dashboard) clusterSiteURL(site model.Site) string {
	value := strings.TrimSpace(emptyFallback(site.OriginalURL, emptyFallback(site.URL, site.Host)))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	scheme := strings.ToLower(strings.TrimSpace(site.Protocol))
	switch scheme {
	case "http", "https":
	default:
		if strings.TrimSpace(site.Port) == "443" {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + value
}

func (d *dashboard) clusterViews() []clusterView {
	all := d.allClusterViews()
	visible := make([]clusterView, 0, len(all))
	for _, cluster := range all {
		if d.ignoredClusters[cluster.Key] {
			continue
		}
		visible = append(visible, cluster)
	}
	return visible
}

func clusterDefaultTitle(cluster clusterView) string {
	if strings.TrimSpace(cluster.Label) != "" {
		return strings.TrimSpace(cluster.Label)
	}
	if strings.TrimSpace(cluster.Key) == detector.ConnectionBlockedClusterKey {
		return "连接断开型拦截"
	}
	if strings.Contains(strings.TrimSpace(cluster.Signature), "连接断开型拦截") {
		return "连接断开型拦截"
	}
	return "待标注聚类"
}

func (d *dashboard) isTrulyNewClusterBucket(bucket *clusterBucket, previousKeys map[string]bool, previous []previousClusterInfo) bool {
	if bucket == nil {
		return false
	}
	if previousKeys[strings.TrimSpace(bucket.key)] {
		return false
	}

	currentLabel := strings.TrimSpace(bucket.label)
	currentSnapshot := bucket.representative.BlockedResponse
	currentSignature := strings.TrimSpace(detector.FingerprintSignature(currentSnapshot))

	for _, prev := range previous {
		if currentSignature != "" && prev.signature != "" && currentSignature == prev.signature {
			return false
		}
		if currentLabel != "" && prev.label != "" && currentLabel == prev.label {
			if detector.FingerprintCloseMatch(prev.snapshot, currentSnapshot) {
				return false
			}
			if detector.ResponseSimilarity(prev.snapshot, currentSnapshot) >= 0.78 {
				return false
			}
		}
	}

	return true
}

func (d *dashboard) updateClusterDetails() {
	if d.clusterDetails == nil {
		return
	}
	clusters := d.clusterViews()
	if d.selectedCluster < 0 || d.selectedCluster >= len(clusters) {
		if d.clusterTagEntry != nil {
			d.clusterTagEntry.SetText("")
		}
		d.clusterResultRows = nil
		d.selectedClusterSite = -1
		if d.clusterResultList != nil {
			d.clusterResultList.Refresh()
		}
		d.clusterDetails.SetText("")
		if d.clusterPreview != nil {
			d.clusterPreview.SetText("")
		}
		if d.clusterSnapshot != nil {
			d.clusterSnapshot.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(model.ResponseSnapshot{}, "cluster-empty", false)}
			d.clusterSnapshot.Refresh()
		}
		return
	}

	cluster := clusters[d.selectedCluster]
	snapshot := d.clusterBlockedSnapshot(cluster.Key)
	rawResponse := d.clusterRawResponse(cluster.Key)
	d.clusterTagEntry.SetText(cluster.Label)
	previousSiteKey := ""
	if d.selectedClusterSite >= 0 && d.selectedClusterSite < len(d.clusterResultRows) {
		previousSiteKey = d.clusterResultRows[d.selectedClusterSite].SiteKey
	}
	d.clusterResultRows = d.buildClusterResultRows(cluster.Key)
	if d.clusterResultList != nil {
		d.clusterResultList.Refresh()
		for i := range d.clusterResultRows {
			d.clusterResultList.SetItemHeight(i, 58)
		}
	}
	d.selectedClusterSite = d.preferredClusterResultIndex(d.clusterResultRows, previousSiteKey)
	if d.clusterResultList != nil && d.selectedClusterSite >= 0 {
		d.clusterResultList.Select(d.selectedClusterSite)
	}

	validatedSites := len(d.clusterResultRows)
	passedSites := 0
	failedSites := 0
	totalAttempts := 0
	for _, row := range d.clusterResultRows {
		totalAttempts += row.Attempts
		if row.Passed {
			passedSites++
		} else {
			failedSites++
		}
	}

	text := strings.Join([]string{
		"聚类签名 // " + cluster.Signature,
		"",
		"当前标签: " + emptyFallback(cluster.Label, "待标注"),
		"标签来源: " + emptyFallback(clusterLabelSourceText(cluster.LabelSource), "-"),
		"规则命中: " + emptyFallback(d.clusterRuleDetails[cluster.Key], "-"),
		"样本数量: " + fmt.Sprintf("%d", cluster.Count),
		"本轮验证: " + fmt.Sprintf("站点 %d | 满足相似度 %d | 未满足 %d | 规则尝试 %d", validatedSites, passedSites, failedSites, totalAttempts),
		"代表站点:",
		strings.Join(cluster.SampleSites, "\n"),
	}, "\n")
	d.clusterDetails.SetText(text)
	if d.clusterPreview != nil {
		if len(d.clusterResultRows) == 0 {
			d.clusterPreview.SetText(sourcePreviewText(strings.Join([]string{
				text,
				"",
				"HTTP 响应原始报文:",
				rawResponse,
			}, "\n")))
		}
	}
	if d.clusterSnapshot != nil {
		if len(d.clusterResultRows) == 0 {
			d.clusterSnapshot.Objects = []fyne.CanvasObject{d.buildBrowserSnapshotPreview(snapshot, cluster.Key, false)}
			d.clusterSnapshot.Refresh()
		}
	}
	if len(d.clusterResultRows) > 0 {
		d.updateClusterResultDetails()
	}
}

func (d *dashboard) autoClusterResponses() bool {
	d.detectMu.Lock()
	if d.pipelineRunning && d.pipelineStage != "" && d.pipelineStage != "cluster" {
		d.detectMu.Unlock()
		return false
	}
	if d.clusterRunning {
		d.detectMu.Unlock()
		dialog.ShowInformation("聚类进行中", "当前已有聚类任务在运行，请先等待完成或停止后再试。", d.window)
		return false
	}
	d.detectMu.Unlock()

	previousBaseline := append([]store.ClusterBaselineItem(nil), d.clusterBaseline...)
	if len(previousBaseline) == 0 {
		previousBaseline = d.buildClusterBaseline()
	}
	previousClusterKeys := make(map[string]bool, len(previousBaseline))
	previousInfos := make([]previousClusterInfo, 0, len(previousBaseline))
	for _, cluster := range previousBaseline {
		previousClusterKeys[cluster.Key] = true
		snapshot := d.clusterBlockedSnapshot(cluster.Key)
		previousInfos = append(previousInfos, previousClusterInfo{
			key:       cluster.Key,
			label:     strings.TrimSpace(cluster.Label),
			signature: strings.TrimSpace(emptyFallback(cluster.Signature, detector.FingerprintSignature(snapshot))),
			snapshot:  snapshot,
		})
	}

	items := make([]struct {
		key       string
		detection model.DetectionResult
	}, 0, len(d.detections))
	for key, detection := range d.detections {
		if !detection.HasWAF {
			continue
		}
		if previousClusterKeys[strings.TrimSpace(detection.ClusterKey)] {
			continue
		}
		items = append(items, struct {
			key       string
			detection model.DetectionResult
		}{key: key, detection: detection})
	}
	if len(items) == 0 {
		if !d.pipelineRunning {
			dialog.ShowInformation("没有新增聚类", "当前没有新增的疑似 WAF 站点需要参与聚类。", d.window)
		}
		d.setMetricDelta(d.clusterDeltaValue, 0)
		d.recentClusters = map[string]bool{}
		d.invalidateClusterViewCache()
		d.refreshDashboard()
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.detectMu.Lock()
	d.clusterCancel = cancel
	d.clusterRunning = true
	d.clusterStopReason = ""
	d.clusterOutcome = "running"
	d.detectMu.Unlock()

	d.setStatus(fmt.Sprintf("聚类中 // 正在聚合 %d 条疑似WAF响应", len(items)))
	d.resetConsole("自动聚类", fmt.Sprintf("准备分拣 %d 条新增疑似WAF响应", len(items)))
	d.appendConsoleLog(fmt.Sprintf("[init] 新增疑似响应=%d | 历史聚类=%d | 模式=增量分拣", len(items), len(previousBaseline)))

	go func() {
		defer func() {
			d.detectMu.Lock()
			d.clusterCancel = nil
			d.clusterRunning = false
			d.clusterStopReason = ""
			d.detectMu.Unlock()
			cancel()
		}()

		nextClusterID := 1
		buckets := make([]*clusterBucket, 0)
		newLabels := map[string]string{}
		assignedExisting := 0
		stopped := false
		const similarityThreshold = 0.86
		findPreviousMatch := func(current model.DetectionResult, currentLabel string) (previousClusterInfo, bool) {
			currentSignature := strings.TrimSpace(detector.FingerprintSignature(current.BlockedResponse))
			bestIndex := -1
			bestScore := 0.0
			for index, prev := range previousInfos {
				if currentSignature != "" && prev.signature != "" && currentSignature == prev.signature {
					return prev, true
				}
				if currentLabel != "" && prev.label != "" && currentLabel == prev.label {
					if detector.FingerprintCloseMatch(prev.snapshot, current.BlockedResponse) {
						return prev, true
					}
				}
				score := detector.ResponseSimilarity(prev.snapshot, current.BlockedResponse)
				if score > bestScore {
					bestScore = score
					bestIndex = index
				}
			}
			if bestIndex >= 0 && bestScore >= similarityThreshold {
				return previousInfos[bestIndex], true
			}
			return previousClusterInfo{}, false
		}

		for index, item := range items {
			if ctx.Err() != nil {
				stopped = true
				break
			}

			current := item.detection
			currentLabel := d.clusterLabelForDetection(current)
			if fp, ok := d.matchFingerprint(current.BlockedResponse); ok {
				if currentLabel == "" && strings.TrimSpace(fp.Label) != "" {
					currentLabel = strings.TrimSpace(fp.Label)
				}
				if mergedKey := clusterKeyForFingerprint(fp); mergedKey != "" {
					current.ClusterKey = mergedKey
				}
				if current.ClusterHint == "" && strings.TrimSpace(fp.Hint) != "" {
					current.ClusterHint = strings.TrimSpace(fp.Hint)
				}
			}

			if matched, ok := findPreviousMatch(current, currentLabel); ok {
				current.ClusterKey = matched.key
				if currentLabel == "" {
					currentLabel = matched.label
				}
				if current.ClusterHint == "" {
					current.ClusterHint = detector.FingerprintHint(matched.snapshot)
				}
				current.ClusterLabel = currentLabel
				d.detections[item.key] = current
				assignedExisting++
				goto clusterProgress
			}

			if current.ClusterKey == detector.ConnectionBlockedClusterKey {
				var bucket *clusterBucket
				for _, candidate := range buckets {
					if candidate.key == detector.ConnectionBlockedClusterKey {
						bucket = candidate
						break
					}
				}
				if bucket == nil {
					bucket = &clusterBucket{
						key:            detector.ConnectionBlockedClusterKey,
						label:          currentLabel,
						representative: current,
					}
					buckets = append(buckets, bucket)
				}
				if bucket.label == "" {
					bucket.label = currentLabel
				}
				bucket.members = append(bucket.members, item.key)
			} else {
				if strings.TrimSpace(current.ClusterKey) != "" {
					for _, bucket := range buckets {
						if bucket.key == current.ClusterKey {
							if bucket.label == "" {
								bucket.label = currentLabel
							}
							bucket.members = append(bucket.members, item.key)
							goto clusterProgress
						}
					}
				}

				bestIndex := -1
				bestScore := 0.0
				for bucketIndex, bucket := range buckets {
					if bucket.key == detector.ConnectionBlockedClusterKey {
						continue
					}
					score := detector.ResponseSimilarity(bucket.representative.BlockedResponse, current.BlockedResponse)
					if score > bestScore {
						bestScore = score
						bestIndex = bucketIndex
					}
				}

				if bestIndex >= 0 && bestScore >= similarityThreshold {
					bucket := buckets[bestIndex]
					if bucket.label == "" {
						bucket.label = currentLabel
					}
					bucket.members = append(bucket.members, item.key)
				} else {
					key := strings.TrimSpace(current.ClusterKey)
					if key == "" {
						key = fmt.Sprintf("cluster-auto-%03d", nextClusterID)
						nextClusterID++
					}
					buckets = append(buckets, &clusterBucket{
						key:            key,
						label:          currentLabel,
						representative: current,
						members:        []string{item.key},
					})
				}
			}

		clusterProgress:
			completed := index + 1
			d.setConsoleStatus(fmt.Sprintf("聚类进行中... %d/%d", completed, len(items)))
			d.setConsoleProgress(completed, len(items))
		}

		if stopped || ctx.Err() != nil {
			stopReason := "内部取消"
			d.detectMu.Lock()
			if strings.TrimSpace(d.clusterStopReason) != "" {
				stopReason = d.clusterStopReason
			}
			d.clusterOutcome = "stopped"
			d.detectMu.Unlock()
			d.recentClusters = map[string]bool{}
			d.invalidateClusterViewCache()
			d.setMetricDelta(d.clusterDeltaValue, 0)
			d.appendConsoleLog(fmt.Sprintf("[stop] 聚类已停止 | 原因=%s", stopReason))
			d.setConsoleStatus(fmt.Sprintf("聚类已停止，原因：%s", stopReason))
			d.setStatus(fmt.Sprintf("聚类区 // 已停止当前聚类任务，原因：%s", stopReason))
			return
		}

		for _, bucket := range buckets {
			hint := bucket.representative.ClusterHint
			if hint == "" {
				hint = fmt.Sprintf("自动聚类 | 响应相似度聚合 | 代表站点 %s", emptyFallback(bucket.representative.Site.Host, bucket.representative.Site.URL))
			}
			if strings.TrimSpace(bucket.label) == "" {
				if fp, ok := d.matchFingerprint(bucket.representative.BlockedResponse); ok {
					bucket.label = strings.TrimSpace(fp.Label)
					if strings.TrimSpace(fp.Hint) != "" {
						hint = fp.Hint
					}
				}
			}
			for _, key := range bucket.members {
				detection := d.detections[key]
				detection.ClusterKey = bucket.key
				detection.ClusterHint = hint
				if bucket.label != "" {
					detection.ClusterLabel = bucket.label
					newLabels[bucket.key] = bucket.label
				}
				d.detections[key] = detection
			}
		}

		newClusterKeys := map[string]bool{}
		for _, bucket := range buckets {
			if d.isTrulyNewClusterBucket(bucket, previousClusterKeys, previousInfos) {
				newClusterKeys[bucket.key] = true
			}
		}

		snapshotFailures := 0
		type snapshotJob struct {
			key    string
			label  string
			target model.ResponseSnapshot
		}
		snapshotJobs := make([]snapshotJob, 0, len(buckets))
		for _, bucket := range buckets {
			if !newClusterKeys[bucket.key] {
				continue
			}
			snapshot := bucket.representative.BlockedResponse
			if strings.TrimSpace(snapshot.Body) == "" && strings.TrimSpace(snapshot.Raw) == "" {
				snapshotFailures++
				continue
			}
			if d.clusterHasSnapshot(bucket.key) {
				continue
			}
			snapshotJobs = append(snapshotJobs, snapshotJob{
				key:    bucket.key,
				label:  emptyFallback(bucket.label, bucket.key),
				target: snapshot,
			})
		}
		if len(snapshotJobs) > 0 {
			workers := d.currentSnapshotConcurrency()
			if workers < 1 {
				workers = 20
			}
			if workers > len(snapshotJobs) {
				workers = len(snapshotJobs)
			}

			d.appendConsoleLog(fmt.Sprintf("[snapshot] 开始为 %d 个聚类生成浏览器快照，并发 %d", len(snapshotJobs), workers))
			jobs := make(chan snapshotJob)
			type snapshotResult struct {
				label string
				err   error
			}
			results := make(chan snapshotResult, len(snapshotJobs))
			var wg sync.WaitGroup

			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for job := range jobs {
						if ctx.Err() != nil {
							return
						}
						_, err := d.ensureClusterSnapshot(job.target, job.key, false)
						select {
						case results <- snapshotResult{label: job.label, err: err}:
						case <-ctx.Done():
							return
						}
					}
				}()
			}

			go func() {
				for _, job := range snapshotJobs {
					select {
					case jobs <- job:
					case <-ctx.Done():
						close(jobs)
						wg.Wait()
						close(results)
						return
					}
				}
				close(jobs)
				wg.Wait()
				close(results)
			}()

			completedSnapshots := 0
			for result := range results {
				if ctx.Err() != nil {
					stopped = true
					break
				}
				completedSnapshots++
				if result.err != nil {
					snapshotFailures++
				}

				d.setConsoleStatus(fmt.Sprintf("生成浏览器快照... %d/%d", completedSnapshots, len(snapshotJobs)))
				d.setConsoleProgress(completedSnapshots, len(snapshotJobs))
			}
		}

		if stopped || ctx.Err() != nil {
			stopReason := "内部取消"
			d.detectMu.Lock()
			if strings.TrimSpace(d.clusterStopReason) != "" {
				stopReason = d.clusterStopReason
			}
			d.clusterOutcome = "stopped"
			d.detectMu.Unlock()
			d.recentClusters = map[string]bool{}
			d.setMetricDelta(d.clusterDeltaValue, 0)
			d.appendConsoleLog(fmt.Sprintf("[stop] 聚类已停止 | 原因=%s", stopReason))
			d.setConsoleStatus(fmt.Sprintf("聚类已停止，原因：%s", stopReason))
			d.setStatus(fmt.Sprintf("聚类区 // 已停止当前聚类任务，原因：%s", stopReason))
			return
		}

		d.clusterLabels = newLabels
		d.rebuildClusterMembers()
		d.clusterBaseline = d.buildClusterBaseline()
		yamlApplied := d.applyWAFYAMLMatches()
		d.recentClusters = newClusterKeys
		d.invalidateClusterViewCache()
		d.setMetricDelta(d.clusterDeltaValue, len(newClusterKeys))
		if d.currentStep == 2 {
			if len(d.clusterViews()) > 0 {
				d.selectedCluster = 0
			} else {
				d.selectedCluster = -1
			}
			if d.clusterList != nil {
				d.clusterList.Refresh()
			}
			d.updateClusterDetails()
		}
		d.refreshDashboard()

		d.updateActiveScanRecord(func(record *store.ScanRecord) {
			record.ClusterCount = d.totalClusterGroupCount()
			record.SuspectedCount = d.suspectedSiteCount()
		})
		d.persistDatabase()
		d.detectMu.Lock()
		d.clusterOutcome = "completed"
		d.detectMu.Unlock()
		doneMessage := fmt.Sprintf("[done] 聚类完成 | 新增分组 %d 组 | 归入历史 %d 组 | 本轮快照 %d 组", len(newClusterKeys), assignedExisting, len(snapshotJobs)-snapshotFailures)
		if yamlApplied > 0 {
			doneMessage += fmt.Sprintf(" | waf.yaml 自动识别 %d 组", yamlApplied)
		}
		d.appendConsoleLog(doneMessage)
		d.setConsoleStatus(fmt.Sprintf("聚类完成，新增 %d 组，归入历史 %d 组", len(newClusterKeys), assignedExisting))
		d.setConsoleProgress(len(items), len(items))
		status := fmt.Sprintf("聚类区 // 已完成增量分拣，本轮新增 %d 组，归入历史 %d 组", len(newClusterKeys), assignedExisting)
		if yamlApplied > 0 {
			status += fmt.Sprintf("，waf.yaml 自动识别 %d 组", yamlApplied)
		}
		d.setStatus(status)
	}()

	return true
}

func (d *dashboard) assignClusterLabel() {
	clusters := d.clusterViews()
	if d.selectedCluster < 0 || d.selectedCluster >= len(clusters) {
		dialog.ShowInformation("选择聚类", "请先在聚类列表中选择一个类别。", d.window)
		return
	}
	label := strings.TrimSpace(d.clusterTagEntry.Text)
	if label == "" {
		dialog.ShowInformation("输入标签", "请输入当前聚类对应的 WAF 产品名称。", d.window)
		return
	}
	cluster := clusters[d.selectedCluster]
	d.assignClusterLabelByKey(cluster.Key, label)
	d.setStatus(fmt.Sprintf("聚类区 // 已将当前类别标注为 %s", label))
}

func (d *dashboard) assignClusterLabelByKey(clusterKey string, label string) {
	label = strings.TrimSpace(label)
	if clusterKey == "" || label == "" {
		return
	}
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}
	memberKeys := append([]string(nil), d.clusterMembers[clusterKey]...)
	d.clusterLabels[clusterKey] = label
	if d.clusterLabelSources == nil {
		d.clusterLabelSources = map[string]string{}
	}
	d.clusterLabelSources[clusterKey] = "manual"
	d.invalidateClusterViewCache()
	for _, key := range memberKeys {
		detection, ok := d.detections[key]
		if !ok {
			continue
		}
		detection.ClusterLabel = label
		d.detections[key] = detection
	}
	updatedBaseline := false
	for index := range d.clusterBaseline {
		if d.clusterBaseline[index].Key != clusterKey {
			continue
		}
		d.clusterBaseline[index].Label = label
		updatedBaseline = true
	}
	if !updatedBaseline {
		d.clusterBaseline = append(d.clusterBaseline, store.ClusterBaselineItem{
			Key:       clusterKey,
			Label:     label,
			Signature: strings.TrimSpace(detector.FingerprintSignature(d.clusterBlockedSnapshot(clusterKey))),
		})
	}
	signature, remembered := d.rememberClusterFingerprint(clusterKey, label, "")
	if d.dbState.Current.ClusterLabels == nil {
		d.dbState.Current.ClusterLabels = map[string]string{}
	}
	if d.dbState.Current.ClusterLabelSources == nil {
		d.dbState.Current.ClusterLabelSources = map[string]string{}
	}
	d.dbState.Current.ClusterLabels[clusterKey] = label
	d.dbState.Current.ClusterLabelSources[clusterKey] = "manual"
	for _, key := range memberKeys {
		detection, ok := d.dbState.Current.Detections[key]
		if !ok {
			continue
		}
		detection.ClusterLabel = label
		d.dbState.Current.Detections[key] = detection
	}
	d.dbState.Current.ClusterBaseline = append([]store.ClusterBaselineItem(nil), d.clusterBaseline...)
	d.dbState.Current.ClusterCount = d.totalClusterGroupCount()
	if remembered {
		if d.dbState.Fingerprints == nil {
			d.dbState.Fingerprints = map[string]store.ClusterFingerprint{}
		}
		d.fingerprintMu.RLock()
		d.dbState.Fingerprints[signature] = d.fingerprints[signature]
		d.fingerprintMu.RUnlock()
	}
	if d.clusterList != nil {
		clusters := d.clusterViews()
		for index, cluster := range clusters {
			if cluster.Key == clusterKey {
				d.clusterList.RefreshItem(index)
				break
			}
		}
	}
	d.updateClusterDetails()
	d.refreshClusterMetrics()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ClusterCount = d.totalClusterGroupCount()
	})
	d.persistCurrentDBStateAsync()
}

func (d *dashboard) ignoreSelectedCluster() {
	clusters := d.clusterViews()
	if d.selectedCluster < 0 || d.selectedCluster >= len(clusters) {
		dialog.ShowInformation("选择聚类", "请先在聚类列表中选择一个类别。", d.window)
		return
	}
	cluster := clusters[d.selectedCluster]
	d.ignoreClusterByKey(cluster.Key)
	d.showActionSuccess("忽略成功", "当前分类已忽略，不会再出现在聚类列表中。")
}

func (d *dashboard) ignoreClusterByKey(clusterKey string) {
	if strings.TrimSpace(clusterKey) == "" {
		return
	}
	if d.ignoredClusters == nil {
		d.ignoredClusters = map[string]bool{}
	}
	d.ignoredClusters[clusterKey] = true
	d.invalidateClusterViewCache()
	d.selectedCluster = -1
	if d.clusterList != nil {
		d.clusterList.Refresh()
	}
	d.updateClusterDetails()
	d.refreshDashboard()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ClusterCount = d.totalClusterGroupCount()
	})
	d.persistDatabase()
	d.setStatus("聚类区 // 当前类别已忽略，不再展示")
}

func (d *dashboard) suspectedSiteCount() int {
	count := 0
	for _, detection := range d.detections {
		if detection.HasWAF {
			count++
		}
	}
	return count
}

func (d *dashboard) labeledClusterCount() int {
	count := 0
	for _, cluster := range d.allClusterViews() {
		if strings.TrimSpace(cluster.Label) != "" {
			count++
		}
	}
	return count
}

func (d *dashboard) totalClusterGroupCount() int {
	return len(d.allClusterViews())
}

func (d *dashboard) pendingClusterCount() int {
	pending := d.totalClusterGroupCount() - d.labeledClusterCount() - d.ignoredClusterCount()
	if pending < 0 {
		return 0
	}
	return pending
}

func (d *dashboard) ignoredClusterCount() int {
	count := 0
	for _, cluster := range d.allClusterViews() {
		if d.ignoredClusters[cluster.Key] {
			count++
		}
	}
	return count
}

func (d *dashboard) matchFingerprint(snapshot model.ResponseSnapshot) (store.ClusterFingerprint, bool) {
	current := d.fingerprintSnapshot()
	if len(current) == 0 {
		return store.ClusterFingerprint{}, false
	}
	signature := detector.FingerprintSignature(snapshot)
	if signature != "" {
		if fp, ok := current[signature]; ok && detector.FingerprintVerifiedMatch(fp.Snapshot, snapshot) {
			return fp, true
		}
	}

	best := store.ClusterFingerprint{}
	bestScore := 0.0
	for _, fp := range current {
		if !detector.FingerprintCloseMatch(fp.Snapshot, snapshot) {
			continue
		}
		score := detector.ResponseSimilarity(fp.Snapshot, snapshot)
		if score > bestScore {
			bestScore = score
			best = fp
		}
	}
	if bestScore >= 0.95 {
		return best, true
	}
	return store.ClusterFingerprint{}, false
}

func fingerprintGroupKey(fp store.ClusterFingerprint) string {
	if strings.TrimSpace(fp.MergeGroup) != "" {
		return strings.TrimSpace(fp.MergeGroup)
	}
	return strings.TrimSpace(fp.Signature)
}

func clusterKeyForFingerprint(fp store.ClusterFingerprint) string {
	groupKey := fingerprintGroupKey(fp)
	if groupKey == "" {
		return ""
	}
	return "cluster-merged-" + groupKey
}

func (d *dashboard) rememberClusterFingerprint(clusterKey string, label string, matchDetail string) (string, bool) {
	label = strings.TrimSpace(label)
	if clusterKey == "" {
		return "", false
	}
	snapshot := d.clusterBlockedSnapshot(clusterKey)
	if strings.TrimSpace(snapshot.Body) == "" && strings.TrimSpace(snapshot.Raw) == "" {
		return "", false
	}
	signature := detector.FingerprintSignature(snapshot)
	if signature == "" {
		return "", false
	}
	hint := detector.FingerprintHint(snapshot)
	matchDetail = strings.TrimSpace(matchDetail)
	if matchDetail == "" && d.clusterRuleDetails != nil {
		matchDetail = strings.TrimSpace(d.clusterRuleDetails[clusterKey])
	}
	source := strings.TrimSpace(d.clusterLabelSources[clusterKey])
	if source == "" && label != "" {
		source = "manual"
	}
	d.fingerprintMu.Lock()
	defer d.fingerprintMu.Unlock()
	if d.fingerprints == nil {
		d.fingerprints = map[string]store.ClusterFingerprint{}
	}
	groupKey := signature
	if existing, ok := d.fingerprints[signature]; ok {
		if current := fingerprintGroupKey(existing); current != "" {
			groupKey = current
		}
		if label == "" {
			label = strings.TrimSpace(existing.Label)
		}
		if matchDetail == "" {
			matchDetail = strings.TrimSpace(existing.MatchDetail)
		}
		if source == "" {
			source = strings.TrimSpace(existing.Source)
		}
	}
	d.fingerprints[signature] = store.ClusterFingerprint{
		Signature:        signature,
		Label:            label,
		Source:           source,
		Hint:             hint,
		MatchDetail:      matchDetail,
		Snapshot:         snapshot,
		SnapshotCacheKey: clusterKey,
		MergeGroup:       groupKey,
		UpdatedAt:        time.Now(),
	}
	return signature, true
}

func (d *dashboard) mergeClusterKeys(clusterKeys []string, preferredKey string) {
	if len(clusterKeys) < 2 {
		return
	}
	selected := map[string]bool{}
	for _, key := range clusterKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		selected[key] = true
	}
	if len(selected) < 2 {
		return
	}

	canonicalKey := strings.TrimSpace(preferredKey)
	if canonicalKey == "" || !selected[canonicalKey] {
		for _, key := range clusterKeys {
			if selected[key] {
				canonicalKey = key
				break
			}
		}
	}
	if canonicalKey == "" {
		return
	}
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}

	canonicalSignature := detector.FingerprintSignature(d.clusterBlockedSnapshot(canonicalKey))
	groupKey := canonicalSignature
	d.fingerprintMu.RLock()
	if existing, ok := d.fingerprints[canonicalSignature]; ok {
		if current := fingerprintGroupKey(existing); current != "" {
			groupKey = current
		}
	}
	d.fingerprintMu.RUnlock()
	if groupKey == "" {
		for key := range selected {
			signature := detector.FingerprintSignature(d.clusterBlockedSnapshot(key))
			d.fingerprintMu.RLock()
			existing, ok := d.fingerprints[signature]
			d.fingerprintMu.RUnlock()
			if ok {
				if current := fingerprintGroupKey(existing); current != "" {
					groupKey = current
					break
				}
			}
		}
	}
	if groupKey == "" {
		groupKey = canonicalSignature
	}

	canonicalLabel := strings.TrimSpace(d.clusterLabels[canonicalKey])
	if canonicalLabel == "" {
		for _, memberKey := range d.clusterMembers[canonicalKey] {
			detection, ok := d.detections[memberKey]
			if !ok {
				continue
			}
			if strings.TrimSpace(detection.ClusterLabel) != "" {
				canonicalLabel = strings.TrimSpace(detection.ClusterLabel)
				break
			}
		}
	}
	if canonicalLabel == "" {
		for key := range selected {
			if label := strings.TrimSpace(d.clusterLabels[key]); label != "" {
				canonicalLabel = label
				break
			}
		}
	}
	canonicalSource := strings.TrimSpace(d.clusterLabelSources[canonicalKey])
	if canonicalSource == "" {
		for key := range selected {
			source := strings.TrimSpace(d.clusterLabelSources[key])
			if source == "manual" {
				canonicalSource = "manual"
				break
			}
			if canonicalSource == "" && source != "" {
				canonicalSource = source
			}
		}
	}
	if d.dbState.Current.ClusterLabels == nil {
		d.dbState.Current.ClusterLabels = map[string]string{}
	}
	if d.dbState.Current.ClusterLabelSources == nil {
		d.dbState.Current.ClusterLabelSources = map[string]string{}
	}
	if d.dbState.Current.IgnoredClusters == nil {
		d.dbState.Current.IgnoredClusters = map[string]bool{}
	}
	if d.dbState.Fingerprints == nil {
		d.dbState.Fingerprints = map[string]store.ClusterFingerprint{}
	}

	type fingerprintSeed struct {
		clusterKey string
		signature  string
		snapshot   model.ResponseSnapshot
	}
	seeds := make([]fingerprintSeed, 0, len(selected))
	mergedMemberKeys := make([]string, 0)
	for key := range selected {
		snapshot := d.clusterBlockedSnapshot(key)
		signature := detector.FingerprintSignature(snapshot)
		seeds = append(seeds, fingerprintSeed{
			clusterKey: key,
			signature:  signature,
			snapshot:   snapshot,
		})
		mergedMemberKeys = append(mergedMemberKeys, d.clusterMembers[key]...)
	}

	for _, detectionKey := range mergedMemberKeys {
		detection, ok := d.detections[detectionKey]
		if !ok {
			continue
		}
		detection.ClusterKey = canonicalKey
		if canonicalLabel != "" {
			detection.ClusterLabel = canonicalLabel
		}
		d.detections[detectionKey] = detection
		if current, ok := d.dbState.Current.Detections[detectionKey]; ok {
			current.ClusterKey = canonicalKey
			if canonicalLabel != "" {
				current.ClusterLabel = canonicalLabel
			}
			d.dbState.Current.Detections[detectionKey] = current
		}
	}
	if canonicalLabel != "" {
		d.clusterLabels[canonicalKey] = canonicalLabel
		if canonicalSource == "" {
			canonicalSource = "manual"
		}
		d.clusterLabelSources[canonicalKey] = canonicalSource
	}

	for _, seed := range seeds {
		if strings.TrimSpace(seed.signature) == "" {
			continue
		}
		var snapshotFingerprint store.ClusterFingerprint
		d.fingerprintMu.Lock()
		if strings.TrimSpace(seed.snapshot.Body) != "" || strings.TrimSpace(seed.snapshot.Raw) != "" {
			if d.fingerprints == nil {
				d.fingerprints = map[string]store.ClusterFingerprint{}
			}
			hint := detector.FingerprintHint(seed.snapshot)
			fp := d.fingerprints[seed.signature]
			if fp.Signature == "" {
				fp.Signature = seed.signature
			}
			fp.Snapshot = seed.snapshot
			fp.Hint = hint
			if strings.TrimSpace(fp.SnapshotCacheKey) == "" {
				fp.SnapshotCacheKey = seed.clusterKey
			}
			d.fingerprints[seed.signature] = fp
		}

		fp := d.fingerprints[seed.signature]
		fp.MergeGroup = groupKey
		if canonicalLabel != "" {
			fp.Label = canonicalLabel
		}
		if strings.TrimSpace(fp.SnapshotCacheKey) == "" {
			fp.SnapshotCacheKey = canonicalKey
		}
		fp.UpdatedAt = time.Now()
		d.fingerprints[seed.signature] = fp
		snapshotFingerprint = d.fingerprints[seed.signature]
		d.fingerprintMu.Unlock()

		if seed.clusterKey != canonicalKey {
			delete(d.clusterLabels, seed.clusterKey)
			delete(d.clusterLabelSources, seed.clusterKey)
			delete(d.ignoredClusters, seed.clusterKey)
			delete(d.dbState.Current.ClusterLabels, seed.clusterKey)
			delete(d.dbState.Current.ClusterLabelSources, seed.clusterKey)
			delete(d.dbState.Current.IgnoredClusters, seed.clusterKey)
		}
		if d.dbState.Fingerprints == nil {
			d.dbState.Fingerprints = map[string]store.ClusterFingerprint{}
		}
		d.dbState.Fingerprints[seed.signature] = snapshotFingerprint
	}

	if canonicalLabel != "" {
		d.clusterLabels[canonicalKey] = canonicalLabel
		if canonicalSource == "" {
			canonicalSource = "manual"
		}
		d.clusterLabelSources[canonicalKey] = canonicalSource
	}
	if d.dbState.Current.ClusterLabels == nil {
		d.dbState.Current.ClusterLabels = map[string]string{}
	}
	if d.dbState.Current.ClusterLabelSources == nil {
		d.dbState.Current.ClusterLabelSources = map[string]string{}
	}
	if d.dbState.Current.IgnoredClusters == nil {
		d.dbState.Current.IgnoredClusters = map[string]bool{}
	}
	if canonicalLabel != "" {
		d.dbState.Current.ClusterLabels[canonicalKey] = canonicalLabel
		d.dbState.Current.ClusterLabelSources[canonicalKey] = canonicalSource
	}
	combinedMembers := append([]string(nil), d.clusterMembers[canonicalKey]...)
	seenMembers := make(map[string]bool, len(combinedMembers))
	for _, memberKey := range combinedMembers {
		seenMembers[memberKey] = true
	}
	for _, memberKey := range mergedMemberKeys {
		if seenMembers[memberKey] {
			continue
		}
		seenMembers[memberKey] = true
		combinedMembers = append(combinedMembers, memberKey)
	}
	d.clusterMembers[canonicalKey] = combinedMembers
	for key := range selected {
		if key == canonicalKey {
			continue
		}
		delete(d.clusterMembers, key)
	}
	d.invalidateClusterViewCache()
	d.clusterBaseline = d.buildClusterBaseline()
	d.dbState.Current.ClusterBaseline = append([]store.ClusterBaselineItem(nil), d.clusterBaseline...)
	d.dbState.Current.ClusterCount = d.totalClusterGroupCount()
	d.refreshClusterMetrics()
	d.updateClusterDetails()
	d.updateActiveScanRecord(func(record *store.ScanRecord) {
		record.ClusterCount = d.totalClusterGroupCount()
	})
	d.persistCurrentDBStateAsync()
}

func (d *dashboard) extractClusterFingerprints() {
	clusters := d.allClusterViews()
	if len(clusters) == 0 {
		dialog.ShowInformation("没有聚类", "当前还没有聚类结果可用于提取指纹。", d.window)
		return
	}
	beforeVisible := d.labeledFingerprintCount()

	d.detectMu.Lock()
	if d.fingerprintRunning {
		d.detectMu.Unlock()
		d.setStatus("指纹库 // 指纹提取任务正在运行")
		return
	}
	if d.searchRunning || d.detectRunning || d.clusterRunning || d.pipelineRunning {
		d.detectMu.Unlock()
		d.setStatus("指纹库 // 当前有任务进行中，请等待完成后再提取指纹")
		dialog.ShowInformation("任务进行中", "请等待当前搜索、识别、聚类或一键执行任务完成后，再提取 WAF 指纹。", d.window)
		return
	}
	d.fingerprintRunning = true
	d.detectMu.Unlock()

	d.resetConsole("自动提取指纹", fmt.Sprintf("准备从 %d 个聚类中提取 WAF 指纹", len(clusters)))
	d.setStatus("指纹库 // 正在提取 WAF 识别指纹")
	d.appendConsoleLog(fmt.Sprintf("[fingerprint] 开始提取指纹 | 聚类总数=%d", len(clusters)))

	go func(clusterItems []clusterView) {
		defer func() {
			d.detectMu.Lock()
			d.fingerprintRunning = false
			d.detectMu.Unlock()
		}()

		labeled := 0
		added := 0
		updated := 0
		processed := 0
		for _, cluster := range clusterItems {
			processed++
			label := strings.TrimSpace(cluster.Label)
			if label != "" {
				labeled++
				signature := detector.FingerprintSignature(d.clusterBlockedSnapshot(cluster.Key))
				d.fingerprintMu.RLock()
				before := len(d.fingerprints)
				d.fingerprintMu.RUnlock()
				rememberedSignature, remembered := d.rememberClusterFingerprint(cluster.Key, label, "")
				if remembered {
					if d.dbState.Fingerprints == nil {
						d.dbState.Fingerprints = map[string]store.ClusterFingerprint{}
					}
					d.fingerprintMu.RLock()
					d.dbState.Fingerprints[rememberedSignature] = d.fingerprints[rememberedSignature]
					d.fingerprintMu.RUnlock()
				}
				d.fingerprintMu.RLock()
				currentLen := len(d.fingerprints)
				currentFP, currentOK := d.fingerprints[signature]
				d.fingerprintMu.RUnlock()
				if currentLen > before {
					added++
				} else if signature != "" {
					if currentOK && strings.TrimSpace(currentFP.Label) == label {
						updated++
					}
				} else {
					updated++
				}
			}
			d.setConsoleStatus(fmt.Sprintf("指纹提取进行中... %d/%d", processed, len(clusterItems)))
			d.setConsoleProgress(processed, len(clusterItems))
		}
		if labeled == 0 {
			d.setConsoleStatus("没有可提取的已标记聚类")
			d.setConsoleProgress(0, 1)
			d.setStatus("指纹库 // 当前没有已标记聚类可提取")
			d.flashClusterNotice("当前没有已标记聚类可提取 WAF 指纹", accentAmber)
			return
		}

		afterVisible := d.labeledFingerprintCount()
		visibleAdded := afterVisible - beforeVisible
		if visibleAdded < 0 {
			visibleAdded = 0
		}
		d.refreshDashboard()
		d.persistCurrentDBStateAsync()
		d.appendConsoleLog(fmt.Sprintf("[fingerprint] 提取完成 | 已处理聚类=%d | 原始新增=%d | 原始更新=%d | 新增指纹组=%d", labeled, added, updated, visibleAdded))
		d.setConsoleStatus(fmt.Sprintf("指纹提取完成，已处理 %d 个聚类，新增 %d 个指纹组", labeled, visibleAdded))
		d.setConsoleProgress(len(clusterItems), len(clusterItems))
		d.flashClusterNotice(fmt.Sprintf("WAF 指纹提取完成：已处理 %d 个聚类，新增 %d 个指纹组", labeled, visibleAdded), accentGreen)
		d.setStatus(fmt.Sprintf("指纹库 // 已处理 %d 个已标记聚类，新增 %d 个指纹组", labeled, visibleAdded))
	}(append([]clusterView(nil), clusters...))
}

func (d *dashboard) libraryProductCount() int {
	seen := map[string]bool{}
	for _, cluster := range d.allClusterViews() {
		if strings.TrimSpace(cluster.Label) != "" {
			seen[cluster.Label] = true
		}
	}
	return len(seen)
}

func (d *dashboard) clusterRawResponse(clusterKey string) string {
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}
	for _, memberKey := range d.clusterMembers[clusterKey] {
		detection, ok := d.detections[memberKey]
		if ok && detection.BlockedResponse.Raw != "" {
			return detection.BlockedResponse.Raw
		}
	}
	return "暂无原始报文"
}

func (d *dashboard) clusterBlockedSnapshot(clusterKey string) model.ResponseSnapshot {
	if d.clusterMembers == nil {
		d.rebuildClusterMembers()
	}
	for _, memberKey := range d.clusterMembers[clusterKey] {
		detection, ok := d.detections[memberKey]
		if ok && (strings.TrimSpace(detection.BlockedResponse.Body) != "" || strings.TrimSpace(detection.BlockedResponse.Raw) != "") {
			return detection.BlockedResponse
		}
	}
	return model.ResponseSnapshot{}
}

func (d *dashboard) syncLibraryFilterOptions() {
	if d.libraryWAFSelect == nil {
		return
	}
	options := []string{"全部产品"}
	seen := map[string]bool{"全部产品": true}
	for _, cluster := range d.allClusterViews() {
		value := strings.TrimSpace(cluster.Label)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		options = append(options, value)
	}
	sort.Strings(options[1:])
	current := d.libraryWAFSelect.Selected
	d.libraryWAFSelect.Options = options
	d.libraryWAFSelect.Refresh()
	if current == "" || !seen[current] {
		d.libraryWAFSelect.SetSelected("全部产品")
		return
	}
	d.libraryWAFSelect.SetSelected(current)
}

func (d *dashboard) alertItems() []string {
	summary := exporter.BuildSummary(d.results)
	alerts := make([]string, 0, 4)
	if summary.Blocked >= 5 {
		alerts = append(alerts, fmt.Sprintf("大规模拦截告警：当前已检测到 %d 条拦截结果，建议优先复核规则有效性。", summary.Blocked))
	}
	if summary.RequestErrors+summary.NoResponse >= 3 {
		alerts = append(alerts, fmt.Sprintf("链路稳定性告警：异常或无响应共 %d 条，建议检查目标站点可达性。", summary.RequestErrors+summary.NoResponse))
	}
	if len(d.plugins) > 0 && summary.PossibleBypass == 0 {
		alerts = append(alerts, "有效性告警：当前还没有成功绕过记录，建议检查规则库或目标标签是否正确。")
	}
	if len(alerts) == 0 {
		alerts = append(alerts, "当前未发现大规模异常，可继续按计划执行巡检与规则回归。")
	}
	return alerts
}
