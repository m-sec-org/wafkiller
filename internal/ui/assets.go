package ui

import (
	"embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
)

//go:embed assets/*.svg assets/*.txt
var embeddedAssets embed.FS

func mustAsset(name string) fyne.Resource {
	data, err := embeddedAssets.ReadFile("assets/" + name)
	if err != nil {
		panic(err)
	}
	return fyne.NewStaticResource(name, data)
}

func heroResource() fyne.Resource {
	return mustAsset("hero.svg")
}

func emblemResource() fyne.Resource {
	return mustAsset("emblem.svg")
}

func radarResource() fyne.Resource {
	return mustAsset("radar.svg")
}

func shieldResource() fyne.Resource {
	return mustAsset("shield.svg")
}

func boltResource() fyne.Resource {
	return mustAsset("bolt.svg")
}

func siteResource() fyne.Resource {
	return mustAsset("site.svg")
}

func pluginResource() fyne.Resource {
	return mustAsset("plugin.svg")
}

func resultResource() fyne.Resource {
	return mustAsset("result.svg")
}

func exportResource() fyne.Resource {
	return mustAsset("export.svg")
}

func importResource() fyne.Resource {
	return mustAsset("import.svg")
}

func searchResource() fyne.Resource {
	return mustAsset("search.svg")
}

func playResource() fyne.Resource {
	return mustAsset("play.svg")
}

func detectResource() fyne.Resource {
	return mustAsset("detect.svg")
}

func stopResource() fyne.Resource {
	return mustAsset("stop.svg")
}

func multiplyResource() fyne.Resource {
	return mustAsset("multiply.svg")
}

func compareResource() fyne.Resource {
	return mustAsset("compare.svg")
}

func proxyResource() fyne.Resource {
	return mustAsset("proxy.svg")
}

func agentResource() fyne.Resource {
	return mustAsset("agent.svg")
}

func themedImage(resource fyne.Resource, width, height float32) *canvas.Image {
	img := canvas.NewImageFromResource(resource)
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(width, height))
	return img
}

func themedIcon(resource fyne.Resource, size float32) *canvas.Image {
	return themedImage(resource, size, size)
}
