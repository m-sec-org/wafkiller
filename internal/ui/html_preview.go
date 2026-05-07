package ui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/net/html"

	"wafbps/internal/model"
)

type htmlPreviewBlock struct {
	Kind string
	Text string
}

func buildHTMLSnapshotPreview(snapshot model.ResponseSnapshot) fyne.CanvasObject {
	if strings.TrimSpace(snapshot.Body) == "" && strings.TrimSpace(snapshot.Raw) == "" {
		label := widget.NewLabel("选中聚类后，这里会显示拦截页面的渲染快照。")
		label.Wrapping = fyne.TextWrapWord
		return container.NewCenter(label)
	}

	preview := extractHTMLPreview(snapshot)

	chromeBar := container.NewHBox(
		animatedSignalLamp(10, accentPink),
		animatedSignalLamp(10, accentAmber),
		animatedSignalLamp(10, accentGreen),
		layout.NewSpacer(),
	)

	urlLabel := widget.NewLabel(emptyFallback(snapshot.URL, "拦截页面预览"))
	urlLabel.Wrapping = fyne.TextWrapWord
	urlLabel.TextStyle = fyne.TextStyle{Bold: true}

	statusText := canvas.NewText(fmt.Sprintf("%d", snapshot.StatusCode), accentGreen)
	statusText.TextSize = 12
	statusText.TextStyle = fyne.TextStyle{Bold: true}

	serverValue := preview.Server
	if serverValue == "" {
		serverValue = "未知服务端"
	}

	metaRow := container.NewGridWithColumns(
		3,
		iconChip(accentBlue, siteResource(), "状态码", fmt.Sprintf("%d", snapshot.StatusCode)),
		iconChip(accentAmber, shieldResource(), "服务端", serverValue),
		iconChip(accentPink, resultResource(), "标题", emptyFallback(preview.Title, "未提取到标题")),
	)

	blocks := make([]fyne.CanvasObject, 0, len(preview.Blocks))
	for _, block := range preview.Blocks {
		blocks = append(blocks, buildHTMLPreviewBlock(block))
	}
	if len(blocks) == 0 {
		fallback := widget.NewLabel("没有提取到可渲染的正文内容。")
		fallback.Wrapping = fyne.TextWrapWord
		blocks = append(blocks, neonPanel(accentMuted, container.NewPadded(fallback)))
	}

	pageCard := neonPanel(accentCyan, container.NewVBox(
		chromeBar,
		widget.NewSeparator(),
		urlLabel,
		metaRow,
		widget.NewSeparator(),
		container.NewVBox(blocks...),
	))

	scroll := container.NewVScroll(pageCard)
	scroll.SetMinSize(fyne.NewSize(0, 280))
	return scroll
}

func buildHTMLPreviewBlock(block htmlPreviewBlock) fyne.CanvasObject {
	text := widget.NewLabel(block.Text)
	text.Wrapping = fyne.TextWrapWord

	switch block.Kind {
	case "h1", "h2", "h3":
		text.TextStyle = fyne.TextStyle{Bold: true}
		return neonPanel(accentBlue, container.NewPadded(text))
	case "button":
		chip := canvas.NewText(block.Text, accentGreen)
		chip.TextSize = 12
		chip.TextStyle = fyne.TextStyle{Bold: true}
		return neonPanel(accentGreen, container.NewPadded(container.NewCenter(chip)))
	case "a":
		link := canvas.NewText(block.Text, accentCyan)
		link.TextSize = 12
		link.TextStyle = fyne.TextStyle{Bold: true}
		return neonPanel(accentCyan, container.NewPadded(link))
	case "li":
		text.SetText("• " + block.Text)
		return neonPanel(accentAmber, container.NewPadded(text))
	default:
		return neonPanel(accentMuted, container.NewPadded(text))
	}
}

type extractedHTMLPreview struct {
	Title  string
	Server string
	Blocks []htmlPreviewBlock
}

func extractHTMLPreview(snapshot model.ResponseSnapshot) extractedHTMLPreview {
	body := strings.TrimSpace(snapshot.Body)
	if body == "" {
		body = rawBody(snapshot.Raw)
	}

	preview := extractedHTMLPreview{
		Title:  strings.TrimSpace(snapshot.Title),
		Server: headerValueFromRaw(snapshot.Headers, "Server"),
	}
	if body == "" {
		return preview
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return fallbackHTMLPreview(body, preview)
	}

	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil || len(preview.Blocks) >= 10 {
			return
		}
		if node.Type == html.ElementNode {
			tag := strings.ToLower(node.Data)
			switch tag {
			case "script", "style", "noscript", "svg":
				return
			case "title":
				if preview.Title == "" {
					preview.Title = normalizedNodeText(node)
				}
				return
			case "h1", "h2", "h3", "p", "li", "button", "a", "blockquote":
				text := normalizedNodeText(node)
				if text != "" && !seen[text] {
					seen[text] = true
					preview.Blocks = append(preview.Blocks, htmlPreviewBlock{Kind: tag, Text: text})
				}
				return
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
			if len(preview.Blocks) >= 10 {
				return
			}
		}
	}
	walk(doc)

	if preview.Title == "" && len(preview.Blocks) > 0 {
		preview.Title = preview.Blocks[0].Text
	}
	if len(preview.Blocks) == 0 {
		return fallbackHTMLPreview(body, preview)
	}
	return preview
}

func fallbackHTMLPreview(body string, preview extractedHTMLPreview) extractedHTMLPreview {
	lines := splitPreviewLines(stripHTMLTags(body), 8)
	for _, line := range lines {
		preview.Blocks = append(preview.Blocks, htmlPreviewBlock{Kind: "p", Text: line})
	}
	if preview.Title == "" && len(preview.Blocks) > 0 {
		preview.Title = preview.Blocks[0].Text
	}
	return preview
}

func normalizedNodeText(node *html.Node) string {
	var parts []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n == nil {
			return
		}
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				parts = append(parts, text)
			}
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "script" || tag == "style" || tag == "noscript" {
				return
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

func stripHTMLTags(raw string) string {
	doc, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return raw
	}
	return normalizedNodeText(doc)
}

func splitPreviewLines(text string, limit int) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}

	out := make([]string, 0, limit)
	current := strings.Builder{}
	for _, word := range words {
		if current.Len()+len(word)+1 > 84 && current.Len() > 0 {
			out = append(out, current.String())
			if len(out) >= limit {
				return out
			}
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 && len(out) < limit {
		out = append(out, current.String())
	}
	return out
}

func rawBody(raw string) string {
	if raw == "" {
		return ""
	}
	if parts := strings.SplitN(raw, "\n\n", 2); len(parts) == 2 {
		return parts[1]
	}
	return raw
}

func headerValueFromRaw(headers string, name string) string {
	target := strings.ToLower(strings.TrimSpace(name)) + ":"
	for _, line := range strings.Split(headers, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), target) {
			return strings.TrimSpace(trimmed[len(target):])
		}
	}
	return ""
}
