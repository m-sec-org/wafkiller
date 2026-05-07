package ui

import (
	"image/color"
	"math"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

type neonProgressBar struct {
	widget.BaseWidget
	value      float64
	sheenPhase float32
	anim       *fyne.Animation
}

func newNeonProgressBar() *neonProgressBar {
	bar := &neonProgressBar{}
	bar.ExtendBaseWidget(bar)
	return bar
}

func (b *neonProgressBar) SetValue(value float64) {
	if value < 0 {
		value = 0
	}
	if value > 1 {
		value = 1
	}
	if math.Abs(b.value-value) < 0.0001 {
		return
	}
	b.value = value
	b.Refresh()
}

func (b *neonProgressBar) CreateRenderer() fyne.WidgetRenderer {
	bgGlow := canvas.NewRectangle(color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 18})
	bgGlow.CornerRadius = 7

	bg := canvas.NewRectangle(color.NRGBA{R: 8, G: 12, B: 22, A: 245})
	bg.CornerRadius = 6

	track := canvas.NewLinearGradient(
		color.NRGBA{R: 18, G: 28, B: 46, A: 255},
		color.NRGBA{R: 9, G: 13, B: 24, A: 255},
		270,
	)

	fillGlow := canvas.NewRectangle(color.NRGBA{R: accentCyan.R, G: accentCyan.G, B: accentCyan.B, A: 42})
	fillGlow.CornerRadius = 6

	fill := canvas.NewLinearGradient(
		color.NRGBA{R: 0, G: 219, B: 255, A: 255},
		color.NRGBA{R: 255, G: 94, B: 154, A: 255},
		270,
	)

	sheen := canvas.NewLinearGradient(
		color.NRGBA{R: 255, G: 255, B: 255, A: 110},
		color.NRGBA{R: 255, G: 255, B: 255, A: 0},
		270,
	)

	r := &neonProgressBarRenderer{
		bar:      b,
		bgGlow:   bgGlow,
		bg:       bg,
		track:    track,
		fillGlow: fillGlow,
		fill:     fill,
		sheen:    sheen,
		objects:  []fyne.CanvasObject{bgGlow, bg, track, fillGlow, fill, sheen},
	}
	b.startAnimation()
	r.Refresh()
	return r
}

func (b *neonProgressBar) startAnimation() {
	if b.anim != nil {
		return
	}
	anim := fyne.NewAnimation(850*time.Millisecond, func(done float32) {
		b.sheenPhase = done
		b.Refresh()
	})
	anim.Curve = fyne.AnimationLinear
	anim.RepeatCount = fyne.AnimationRepeatForever
	b.anim = anim
	anim.Start()
}

type neonProgressBarRenderer struct {
	bar      *neonProgressBar
	bgGlow   *canvas.Rectangle
	bg       *canvas.Rectangle
	track    *canvas.LinearGradient
	fillGlow *canvas.Rectangle
	fill     *canvas.LinearGradient
	sheen    *canvas.LinearGradient
	objects  []fyne.CanvasObject
}

func (r *neonProgressBarRenderer) Layout(size fyne.Size) {
	r.bgGlow.Resize(size)
	r.bg.Resize(size)
	r.track.Resize(size)

	fillWidth := float32(r.bar.value) * size.Width
	if r.bar.value > 0 && fillWidth < 6 {
		fillWidth = 6
	}
	if fillWidth > size.Width {
		fillWidth = size.Width
	}

	fillSize := fyne.NewSize(fillWidth, size.Height)
	r.fillGlow.Resize(fillSize)
	r.fill.Resize(fillSize)

	sheenWidth := fillWidth * 0.28
	if sheenWidth > 34 {
		sheenWidth = 34
	}
	if sheenWidth < 0 {
		sheenWidth = 0
	}
	r.sheen.Resize(fyne.NewSize(sheenWidth, size.Height))
	sheenX := (fillWidth + sheenWidth) * r.bar.sheenPhase
	sheenX -= sheenWidth
	sheenX = maxFloat32(0, sheenX)
	sheenX = minFloat32(sheenX, maxFloat32(0, fillWidth-sheenWidth))
	r.sheen.Move(fyne.NewPos(sheenX, 0))

	visible := fillWidth > 0
	toggleCanvas(r.fillGlow, visible)
	toggleCanvas(r.fill, visible)
	toggleCanvas(r.sheen, visible)
}

func (r *neonProgressBarRenderer) MinSize() fyne.Size {
	return fyne.NewSize(420, 8)
}

func (r *neonProgressBarRenderer) Refresh() {
	r.Layout(r.bar.Size())
	for _, obj := range r.objects {
		canvas.Refresh(obj)
	}
}

func (r *neonProgressBarRenderer) Destroy() {
	if r.bar.anim != nil {
		r.bar.anim.Stop()
		r.bar.anim = nil
	}
}

func (r *neonProgressBarRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

func (r *neonProgressBarRenderer) BackgroundColor() color.Color {
	return color.Transparent
}

func maxFloat32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}

func minFloat32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func toggleCanvas(obj fyne.CanvasObject, visible bool) {
	if visible {
		obj.Show()
		return
	}
	obj.Hide()
}
