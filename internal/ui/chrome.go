package ui

import (
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

var (
	accentCyan   = color.NRGBA{R: 0, G: 242, B: 255, A: 255}
	accentPink   = color.NRGBA{R: 255, G: 71, B: 136, A: 255}
	accentAmber  = color.NRGBA{R: 255, G: 168, B: 56, A: 255}
	accentGreen  = color.NRGBA{R: 73, G: 255, B: 150, A: 255}
	accentBlue   = color.NRGBA{R: 74, G: 143, B: 255, A: 255}
	accentMuted  = color.NRGBA{R: 140, G: 155, B: 186, A: 255}
	panelBase    = color.NRGBA{R: 12, G: 17, B: 28, A: 240}
	panelOverlay = color.NRGBA{R: 24, G: 31, B: 47, A: 160}
)

func neonPanel(accent color.NRGBA, content fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewLinearGradient(
		color.NRGBA{R: panelBase.R, G: panelBase.G, B: panelBase.B, A: 250},
		color.NRGBA{R: 10, G: 13, B: 22, A: 252},
		28,
	)
	overlay := canvas.NewLinearGradient(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 18},
		color.NRGBA{R: panelOverlay.R, G: panelOverlay.G, B: panelOverlay.B, A: 130},
		135,
	)
	sheen := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 28},
		color.NRGBA{R: 255, G: 255, B: 255, A: 0},
		300,
	)
	cornerGlowA := canvas.NewRadialGradient(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 36},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 0},
	)
	cornerGlowB := canvas.NewRadialGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 22},
		color.NRGBA{R: 255, G: 255, B: 255, A: 0},
	)
	topRail := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 80},
		accent,
		270,
	)
	topRail.SetMinSize(fyne.NewSize(0, 4))
	bottomRail := canvas.NewLinearGradient(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 0},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 70},
		90,
	)
	bottomRail.SetMinSize(fyne.NewSize(0, 2))
	leftRail := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 56},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 120},
		180,
	)
	leftRail.SetMinSize(fyne.NewSize(6, 0))
	rightRail := canvas.NewLinearGradient(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 36},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 0},
		0,
	)
	rightRail.SetMinSize(fyne.NewSize(3, 0))
	innerGlow := canvas.NewRectangle(color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 8})

	body := container.NewBorder(
		topRail,
		bottomRail,
		leftRail,
		rightRail,
		container.NewPadded(content),
	)
	return container.NewStack(bg, overlay, sheen, cornerGlowA, cornerGlowB, innerGlow, body)
}

func metricValue(text string, accent color.NRGBA) *canvas.Text {
	value := canvas.NewText(text, accent)
	value.TextSize = 28
	value.TextStyle = fyne.TextStyle{Bold: true}
	return value
}

func metricDeltaText(accent color.NRGBA) *canvas.Text {
	delta := canvas.NewText("", color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 210})
	delta.TextSize = 11
	delta.TextStyle = fyne.TextStyle{Bold: true}
	return delta
}

func captionText(text string) *canvas.Text {
	label := canvas.NewText(strings.ToUpper(text), color.NRGBA{R: 196, G: 214, B: 255, A: 210})
	label.TextSize = 11
	return label
}

func metricCard(title string, value *canvas.Text, accent color.NRGBA) fyne.CanvasObject {
	return neonPanel(accent, container.NewVBox(
		captionText(title),
		value,
	))
}

func metricActionCard(title string, value *canvas.Text, accent color.NRGBA, actionLabel string, onTap func()) fyne.CanvasObject {
	actionBtn := widget.NewButton(actionLabel, onTap)
	actionBtn.Importance = widget.LowImportance
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		canvas.NewText("", color.Transparent),
	)
	footer := container.NewHBox(layout.NewSpacer(), actionBtn)
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func metricActionDetailCard(title string, value *canvas.Text, detail fyne.CanvasObject, accent color.NRGBA, actionLabel string, onTap func()) fyne.CanvasObject {
	actionBtn := widget.NewButton(actionLabel, onTap)
	actionBtn.Importance = widget.LowImportance
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		canvas.NewText("", color.Transparent),
	)
	footer := container.NewHBox(detail, layout.NewSpacer(), actionBtn)
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func metricActionDeltaDetailCard(title string, value, delta *canvas.Text, detail fyne.CanvasObject, accent color.NRGBA, actionLabel string, onTap func()) fyne.CanvasObject {
	actionBtn := widget.NewButton(actionLabel, onTap)
	actionBtn.Importance = widget.LowImportance
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		delta,
	)
	footer := container.NewHBox(detail, layout.NewSpacer(), actionBtn)
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func metricActionDeltaObjectDetailCard(title string, value fyne.CanvasObject, delta *canvas.Text, detail fyne.CanvasObject, accent color.NRGBA, actionLabel string, onTap func()) fyne.CanvasObject {
	actionBtn := widget.NewButton(actionLabel, onTap)
	actionBtn.Importance = widget.LowImportance
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		delta,
	)
	footer := container.NewHBox(detail, layout.NewSpacer(), actionBtn)
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func metricActionDeltaCard(title string, value, delta *canvas.Text, accent color.NRGBA, actionLabel string, onTap func()) fyne.CanvasObject {
	actionBtn := widget.NewButton(actionLabel, onTap)
	actionBtn.Importance = widget.LowImportance
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		delta,
	)
	footer := container.NewHBox(layout.NewSpacer(), actionBtn)
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func metricDeltaCard(title string, value, delta *canvas.Text, accent color.NRGBA) fyne.CanvasObject {
	header := container.NewHBox(
		captionText(title),
		layout.NewSpacer(),
		delta,
	)
	footer := container.NewHBox(layout.NewSpacer())
	return neonPanel(accent, container.NewVBox(
		header,
		value,
		footer,
	))
}

func iconChip(accent color.NRGBA, resource fyne.Resource, title, subtitle string) fyne.CanvasObject {
	titleLabel := widget.NewLabel(title)
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}
	subtitleLabel := widget.NewLabel(subtitle)
	subtitleLabel.Wrapping = fyne.TextWrapWord

	return neonPanel(accent, container.NewHBox(
		themedIcon(resource, 22),
		container.NewVBox(titleLabel, subtitleLabel),
	))
}

func sectionHeading(accent color.NRGBA, resource fyne.Resource, title, subtitle string, trailing ...fyne.CanvasObject) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subtitleLabel := widget.NewLabel(subtitle)
	subtitleLabel.Wrapping = fyne.TextWrapWord

	objects := []fyne.CanvasObject{
		themedIcon(resource, 20),
		container.NewVBox(titleLabel, subtitleLabel),
		layout.NewSpacer(),
	}
	objects = append(objects, trailing...)
	return container.NewHBox(objects...)
}

func listBadge(accent color.NRGBA, resource fyne.Resource) fyne.CanvasObject {
	glow := canvas.NewRadialGradient(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 34},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 0},
	)
	base := canvas.NewRectangle(color.NRGBA{R: 14, G: 20, B: 34, A: 220})
	base.SetMinSize(fyne.NewSize(46, 46))
	return container.NewStack(
		glow,
		base,
		container.NewCenter(themedIcon(resource, 20)),
	)
}

func verdictChip(verdict string) fyne.CanvasObject {
	accent := verdictAccent(verdict)
	glow := canvas.NewRectangle(color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 34})
	glow.SetMinSize(fyne.NewSize(84, 24))
	base := canvas.NewRectangle(color.NRGBA{R: 10, G: 15, B: 26, A: 235})
	base.SetMinSize(fyne.NewSize(84, 24))
	label := canvas.NewText(verdict, color.NRGBA{R: 245, G: 250, B: 255, A: 235})
	label.TextSize = 11
	label.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewStack(
		glow,
		base,
		container.NewPadded(container.NewCenter(label)),
	)
}

func animatedSignalLamp(size float32, accent color.NRGBA) fyne.CanvasObject {
	halo := canvas.NewCircle(color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 20})
	halo.Resize(fyne.NewSize(size, size))
	core := canvas.NewCircle(color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 120})
	core.Resize(fyne.NewSize(size*0.42, size*0.42))
	core.Move(fyne.NewPos(size*0.29, size*0.29))

	anim := canvas.NewColorRGBAAnimation(
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 72},
		color.NRGBA{R: accent.R, G: accent.G, B: accent.B, A: 255},
		1100*time.Millisecond,
		func(c color.Color) {
			core.FillColor = c
			core.Refresh()
		},
	)
	anim.AutoReverse = true
	anim.Curve = fyne.AnimationEaseInOut
	anim.RepeatCount = fyne.AnimationRepeatForever
	anim.Start()

	return container.NewStack(
		halo,
		core,
	)
}

func statusColor(message string) color.NRGBA {
	switch {
	case strings.Contains(message, "错误"):
		return accentPink
	case strings.Contains(message, "运行"):
		return accentAmber
	case strings.Contains(message, "同步") || strings.Contains(message, "待命") || strings.Contains(message, "就绪"):
		return accentCyan
	case strings.Contains(message, "结果") || strings.Contains(message, "完成") || strings.Contains(message, "已保存"):
		return accentGreen
	default:
		return accentMuted
	}
}

func verdictAccent(verdict string) color.NRGBA {
	switch {
	case strings.Contains(verdict, "可能绕过"):
		return accentGreen
	case strings.Contains(verdict, "已拦截"):
		return accentPink
	case strings.Contains(verdict, "复核"):
		return accentAmber
	case strings.Contains(verdict, "异常") || strings.Contains(verdict, "失败"):
		return accentPink
	case strings.Contains(verdict, "无响应"):
		return accentBlue
	default:
		return accentCyan
	}
}

func wafAccent(name string) color.NRGBA {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "cloudflare"):
		return accentCyan
	case strings.Contains(lower, "akamai"):
		return accentAmber
	case strings.Contains(lower, "aws"):
		return accentBlue
	case strings.Contains(lower, "aliyun"):
		return accentPink
	case strings.Contains(lower, "f5"):
		return accentGreen
	case strings.Contains(lower, "modsecurity"):
		return accentAmber
	case strings.Contains(lower, "safeline"), strings.Contains(lower, "chaitin"):
		return accentGreen
	default:
		return accentMuted
	}
}
