package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type neonTheme struct{}

func (neonTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 12, G: 14, B: 20, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 22, G: 25, B: 35, A: 255}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 45, G: 48, B: 58, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 222, G: 232, B: 255, A: 255}
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 14, G: 18, B: 27, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 10, G: 14, B: 22, A: 255}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 0, G: 242, B: 255, A: 170}
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 10, G: 13, B: 21, A: 250}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 118, G: 128, B: 160, A: 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0, G: 242, B: 255, A: 255}
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0, G: 242, B: 255, A: 90}
	case theme.ColorNameHover:
		return color.NRGBA{R: 27, G: 39, B: 57, A: 255}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 255, G: 71, B: 136, A: 255}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0, G: 242, B: 255, A: 80}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0, G: 242, B: 255, A: 120}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 255, G: 71, B: 136, A: 32}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (neonTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (neonTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (neonTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInlineIcon:
		return 16
	case theme.SizeNameText:
		return 12
	default:
		return theme.DefaultTheme().Size(name)
	}
}
