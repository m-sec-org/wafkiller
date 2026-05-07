package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"wafbps/internal/config"
	"wafbps/internal/downstreamproxy"
	"wafbps/internal/netutil"
)

func (d *dashboard) proxyUpstreamURL() string {
	endpoint := d.cfg.Proxy.Upstream
	if !endpoint.Enabled {
		return ""
	}
	return netutil.BuildProxyURL(endpoint.Scheme, endpoint.Host, endpoint.Port, endpoint.Username, endpoint.Password)
}

func (d *dashboard) proxyUpstreamSummary() string {
	endpoint := d.cfg.Proxy.Upstream
	if !endpoint.Enabled || strings.TrimSpace(endpoint.Host) == "" {
		return "直连"
	}
	return fmt.Sprintf("%s://%s:%d", netutil.NormalizeProxyScheme(endpoint.Scheme), endpoint.Host, effectiveProxyPort(endpoint.Scheme, endpoint.Port))
}

func (d *dashboard) proxyDownstreamSummary() string {
	endpoint := d.cfg.Proxy.Downstream
	if !endpoint.Enabled {
		return "未启用"
	}
	host := strings.TrimSpace(endpoint.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s:%d", netutil.NormalizeProxyScheme(endpoint.Scheme), host, effectiveProxyPort(endpoint.Scheme, endpoint.Port))
}

func (d *dashboard) proxyDownstreamCertSummary() string {
	cert := strings.TrimSpace(d.cfg.Proxy.Downstream.CertificatePath)
	key := strings.TrimSpace(d.cfg.Proxy.Downstream.PrivateKeyPath)
	switch {
	case cert != "" && key != "":
		return fmt.Sprintf("证书 %s | 私钥 %s", filepath.Base(cert), filepath.Base(key))
	case cert != "":
		return fmt.Sprintf("仅证书 %s", filepath.Base(cert))
	case key != "":
		return fmt.Sprintf("仅私钥 %s", filepath.Base(key))
	default:
		return "未导入 HTTPS 证书"
	}
}

func (d *dashboard) proxyAuditLogPath() string {
	return filepath.Join(d.workspaceRootDir(), "data", "proxy", "traffic.jsonl")
}

func (d *dashboard) downstreamCertAbsPath() string {
	target := strings.TrimSpace(d.cfg.Proxy.Downstream.CertificatePath)
	if target == "" {
		target = config.Default().Proxy.Downstream.CertificatePath
	}
	return d.resolveWorkspacePath(target)
}

func (d *dashboard) downstreamKeyAbsPath() string {
	target := strings.TrimSpace(d.cfg.Proxy.Downstream.PrivateKeyPath)
	if target == "" {
		target = config.Default().Proxy.Downstream.PrivateKeyPath
	}
	return d.resolveWorkspacePath(target)
}

func (d *dashboard) openProxySettingsDialog() {
	upstreamEnabled := widget.NewCheck("启用上行代理", nil)
	upstreamEnabled.SetChecked(d.cfg.Proxy.Upstream.Enabled)
	upstreamScheme := widget.NewSelect([]string{"http", "https", "socks5"}, nil)
	upstreamScheme.SetSelected(netutil.NormalizeProxyScheme(d.cfg.Proxy.Upstream.Scheme))
	upstreamHost := widget.NewEntry()
	upstreamHost.SetText(strings.TrimSpace(d.cfg.Proxy.Upstream.Host))
	upstreamPort := widget.NewEntry()
	upstreamPort.SetText(proxyPortText(d.cfg.Proxy.Upstream.Scheme, d.cfg.Proxy.Upstream.Port))
	upstreamUser := widget.NewEntry()
	upstreamUser.SetText(strings.TrimSpace(d.cfg.Proxy.Upstream.Username))
	upstreamPass := widget.NewPasswordEntry()
	upstreamPass.SetText(d.cfg.Proxy.Upstream.Password)

	downstreamEnabled := widget.NewCheck("启用下行代理", nil)
	downstreamEnabled.SetChecked(d.cfg.Proxy.Downstream.Enabled)
	downstreamScheme := widget.NewSelect([]string{"http", "https", "socks5"}, nil)
	downstreamScheme.SetSelected(netutil.NormalizeProxyScheme(d.cfg.Proxy.Downstream.Scheme))
	downstreamHost := widget.NewEntry()
	downstreamHost.SetText(strings.TrimSpace(emptyFallback(d.cfg.Proxy.Downstream.Host, "127.0.0.1")))
	downstreamPort := widget.NewEntry()
	downstreamPort.SetText(proxyPortText(d.cfg.Proxy.Downstream.Scheme, d.cfg.Proxy.Downstream.Port))
	downstreamUser := widget.NewEntry()
	downstreamUser.SetText(strings.TrimSpace(d.cfg.Proxy.Downstream.Username))
	downstreamPass := widget.NewPasswordEntry()
	downstreamPass.SetText(d.cfg.Proxy.Downstream.Password)
	downstreamAllowedHostsEntry := widget.NewMultiLineEntry()
	downstreamAllowedHostsEntry.SetText(strings.Join(d.cfg.Proxy.Downstream.AllowedHosts, ","))
	downstreamAllowedHostsEntry.Wrapping = fyne.TextWrapWord
	downstreamAllowedHostsEntry.SetMinRowsVisible(2)

	certStatus := widget.NewLabel(d.proxyDownstreamCertSummary())
	certStatus.Wrapping = fyne.TextWrapWord
	runningStatus := widget.NewLabel(d.proxyRuntimeSummary())
	runningStatus.Wrapping = fyne.TextWrapWord
	cfgWindow := d.app.NewWindow("配置代理")
	cfgWindow.Resize(fyne.NewSize(980, 760))

	var pendingCertName string
	var pendingKeyName string
	var pendingCertData []byte
	var pendingKeyData []byte

	updateCertStatus := func() {
		current := d.proxyDownstreamCertSummary()
		if pendingCertName == "" && pendingKeyName == "" {
			certStatus.SetText(current)
			return
		}
		parts := make([]string, 0, 2)
		if pendingCertName != "" {
			parts = append(parts, "待保存证书 "+pendingCertName)
		}
		if pendingKeyName != "" {
			parts = append(parts, "待保存私钥 "+pendingKeyName)
		}
		certStatus.SetText(strings.Join(parts, " | "))
	}

	importCertBtn := widget.NewButtonWithIcon("导入证书", importResource(), func() {
		d.openProxyFileOpenDialog(cfgWindow, "导入下行 HTTPS 证书", []string{".crt", ".pem", ".cer"}, func(name string, data []byte) {
			pendingCertName = name
			pendingCertData = data
			updateCertStatus()
		})
	})
	importKeyBtn := widget.NewButtonWithIcon("导入私钥", importResource(), func() {
		d.openProxyFileOpenDialog(cfgWindow, "导入下行 HTTPS 私钥", []string{".key", ".pem"}, func(name string, data []byte) {
			pendingKeyName = name
			pendingKeyData = data
			updateCertStatus()
		})
	})
	downloadCertBtn := widget.NewButtonWithIcon("下载证书", exportResource(), func() {
		data, err := d.proxyMaterialData(pendingCertData, d.downstreamCertAbsPath())
		if err != nil {
			dialog.ShowError(err, cfgWindow)
			return
		}
		d.openProxyFileSaveDialog(cfgWindow, "导出下行 HTTPS 证书", "downstream-cert.pem", data)
	})
	downloadKeyBtn := widget.NewButtonWithIcon("下载私钥", exportResource(), func() {
		data, err := d.proxyMaterialData(pendingKeyData, d.downstreamKeyAbsPath())
		if err != nil {
			dialog.ShowError(err, cfgWindow)
			return
		}
		d.openProxyFileSaveDialog(cfgWindow, "导出下行 HTTPS 私钥", "downstream-key.pem", data)
	})
	startBtn := widget.NewButtonWithIcon("启动代理", playResource(), func() {
		if err := d.startDownstreamProxyService(); err != nil {
			dialog.ShowError(err, cfgWindow)
			return
		}
		runningStatus.SetText(d.proxyRuntimeSummary())
	})
	stopBtn := widget.NewButtonWithIcon("停止代理", shieldResource(), func() {
		if err := d.stopDownstreamProxyService(); err != nil {
			dialog.ShowError(err, cfgWindow)
			return
		}
		runningStatus.SetText(d.proxyRuntimeSummary())
	})
	viewTrafficBtn := widget.NewButtonWithIcon("查看流量", resultResource(), func() {
		d.openProxyTrafficViewer()
	})

	refreshHTTPSControls := func() {
		httpsMode := strings.EqualFold(downstreamScheme.Selected, "https")
		if httpsMode {
			importCertBtn.Enable()
			importKeyBtn.Enable()
			downloadCertBtn.Enable()
			downloadKeyBtn.Enable()
			return
		}
		importCertBtn.Disable()
		importKeyBtn.Disable()
		downloadCertBtn.Disable()
		downloadKeyBtn.Disable()
	}
	downstreamScheme.OnChanged = func(_ string) {
		refreshHTTPSControls()
	}
	refreshHTTPSControls()

	upstreamPanel := neonPanel(accentBlue, container.NewVBox(
		widget.NewLabel("上行代理会统一作用于 FOFA、WAF 识别、规则验证和智能体出站请求。留空或关闭即直连。"),
		widget.NewForm(
			widget.NewFormItem("开关", upstreamEnabled),
			widget.NewFormItem("协议", upstreamScheme),
			widget.NewFormItem("主机", upstreamHost),
			widget.NewFormItem("端口", upstreamPort),
			widget.NewFormItem("用户名", upstreamUser),
			widget.NewFormItem("密码", upstreamPass),
		),
	))

	downstreamPanel := neonPanel(accentAmber, container.NewVBox(
		widget.NewLabel("下行代理支持本地监听、流量转发和审计记录，可统一维护协议、监听地址、白名单和 HTTPS 证书材料。"),
		widget.NewForm(
			widget.NewFormItem("开关", downstreamEnabled),
			widget.NewFormItem("协议", downstreamScheme),
			widget.NewFormItem("监听主机", downstreamHost),
			widget.NewFormItem("监听端口", downstreamPort),
			widget.NewFormItem("用户名", downstreamUser),
			widget.NewFormItem("密码", downstreamPass),
			widget.NewFormItem("白名单域名", downstreamAllowedHostsEntry),
		),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("运行状态", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		runningStatus,
		container.NewHBox(startBtn, stopBtn, viewTrafficBtn),
		widget.NewSeparator(),
		widget.NewLabelWithStyle("HTTPS 证书材料", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		certStatus,
		container.NewHBox(importCertBtn, importKeyBtn, layout.NewSpacer(), downloadCertBtn, downloadKeyBtn),
	))

	content := container.NewVBox(upstreamPanel, downstreamPanel)

	saveConfig := func() bool {

		upstreamSchemeValue := netutil.NormalizeProxyScheme(upstreamScheme.Selected)
		upstreamPortValue := sanitizePositiveIntValue(upstreamPort.Text, netutil.DefaultProxyPort(upstreamSchemeValue))
		downstreamSchemeValue := netutil.NormalizeProxyScheme(downstreamScheme.Selected)
		downstreamPortValue := sanitizePositiveIntValue(downstreamPort.Text, netutil.DefaultProxyPort(downstreamSchemeValue))

		d.cfg.Proxy.Upstream.Enabled = upstreamEnabled.Checked
		d.cfg.Proxy.Upstream.Scheme = upstreamSchemeValue
		d.cfg.Proxy.Upstream.Host = strings.TrimSpace(upstreamHost.Text)
		d.cfg.Proxy.Upstream.Port = upstreamPortValue
		d.cfg.Proxy.Upstream.Username = strings.TrimSpace(upstreamUser.Text)
		d.cfg.Proxy.Upstream.Password = upstreamPass.Text

		d.cfg.Proxy.Downstream.Enabled = downstreamEnabled.Checked
		d.cfg.Proxy.Downstream.Scheme = downstreamSchemeValue
		d.cfg.Proxy.Downstream.Host = strings.TrimSpace(emptyFallback(downstreamHost.Text, "127.0.0.1"))
		d.cfg.Proxy.Downstream.Port = downstreamPortValue
		d.cfg.Proxy.Downstream.Username = strings.TrimSpace(downstreamUser.Text)
		d.cfg.Proxy.Downstream.Password = downstreamPass.Text
		d.cfg.Proxy.Downstream.AllowedHosts = splitCSV(downstreamAllowedHostsEntry.Text)
		if strings.TrimSpace(d.cfg.Proxy.Downstream.CertificatePath) == "" {
			d.cfg.Proxy.Downstream.CertificatePath = config.Default().Proxy.Downstream.CertificatePath
		}
		if strings.TrimSpace(d.cfg.Proxy.Downstream.PrivateKeyPath) == "" {
			d.cfg.Proxy.Downstream.PrivateKeyPath = config.Default().Proxy.Downstream.PrivateKeyPath
		}

		if len(pendingCertData) > 0 {
			if err := d.writeProxyMaterial(d.cfg.Proxy.Downstream.CertificatePath, pendingCertData, 0o644); err != nil {
				dialog.ShowError(err, cfgWindow)
				return false
			}
		}
		if len(pendingKeyData) > 0 {
			if err := d.writeProxyMaterial(d.cfg.Proxy.Downstream.PrivateKeyPath, pendingKeyData, 0o600); err != nil {
				dialog.ShowError(err, cfgWindow)
				return false
			}
		}

		if err := config.Save(d.configPath, d.cfg); err != nil {
			dialog.ShowError(err, cfgWindow)
			return false
		}
		if d.proxyService != nil && d.proxyService.Running() {
			_ = d.stopDownstreamProxyService()
			if err := d.startDownstreamProxyService(); err != nil {
				dialog.ShowError(err, cfgWindow)
				return false
			}
		}
		d.refreshCurrentStepView()
		d.setStatus(fmt.Sprintf("代理配置 // 已保存，上行 %s，下行 %s", d.proxyUpstreamSummary(), d.proxyDownstreamSummary()))
		return true
	}

	saveBtn := widget.NewButtonWithIcon("保存", resultResource(), func() {
		if saveConfig() {
			cfgWindow.Close()
		}
	})
	cancelBtn := widget.NewButtonWithIcon("取消", stopResource(), func() {
		cfgWindow.Close()
	})
	actions := container.NewHBox(layout.NewSpacer(), cancelBtn, saveBtn)
	cfgWindow.SetContent(container.NewBorder(nil, actions, nil, nil, content))
	cfgWindow.Show()
}

func (d *dashboard) proxyRuntimeSummary() string {
	if d.proxyService != nil && d.proxyService.Running() {
		return fmt.Sprintf("运行中 | 监听 %s://%s | 审计 %s", netutil.NormalizeProxyScheme(d.cfg.Proxy.Downstream.Scheme), d.proxyService.Addr(), d.proxyAuditLogPath())
	}
	return fmt.Sprintf("未启动 | 预计监听 %s | 审计 %s", d.proxyDownstreamSummary(), d.proxyAuditLogPath())
}

func (d *dashboard) startDownstreamProxyService() error {
	if d.proxyService != nil && d.proxyService.Running() {
		return nil
	}
	cfg := downstreamproxy.Config{
		Scheme:           d.cfg.Proxy.Downstream.Scheme,
		Host:             strings.TrimSpace(emptyFallback(d.cfg.Proxy.Downstream.Host, "127.0.0.1")),
		Port:             effectiveProxyPort(d.cfg.Proxy.Downstream.Scheme, d.cfg.Proxy.Downstream.Port),
		Username:         strings.TrimSpace(d.cfg.Proxy.Downstream.Username),
		Password:         d.cfg.Proxy.Downstream.Password,
		AllowedHosts:     append([]string(nil), d.cfg.Proxy.Downstream.AllowedHosts...),
		CertificatePath:  d.downstreamCertAbsPath(),
		PrivateKeyPath:   d.downstreamKeyAbsPath(),
		UpstreamProxyURL: d.proxyUpstreamURL(),
		AuditLogPath:     d.proxyAuditLogPath(),
	}
	service := downstreamproxy.New(cfg, func(entry downstreamproxy.AuditEntry) {
		d.proxyTrafficMu.Lock()
		d.proxyTrafficEntries = append([]downstreamproxy.AuditEntry{entry}, d.proxyTrafficEntries...)
		if len(d.proxyTrafficEntries) > 200 {
			d.proxyTrafficEntries = d.proxyTrafficEntries[:200]
		}
		d.proxyTrafficMu.Unlock()
	})
	if err := service.Start(); err != nil {
		return err
	}
	d.proxyService = service
	d.setStatus(fmt.Sprintf("下行代理 // 已启动 %s://%s", netutil.NormalizeProxyScheme(d.cfg.Proxy.Downstream.Scheme), service.Addr()))
	return nil
}

func (d *dashboard) stopDownstreamProxyService() error {
	if d.proxyService == nil {
		return nil
	}
	err := d.proxyService.Stop(context.Background())
	d.proxyService = nil
	d.setStatus("下行代理 // 已停止")
	return err
}

func (d *dashboard) openProxyTrafficViewer() {
	d.proxyTrafficMu.Lock()
	rows := append([]downstreamproxy.AuditEntry(nil), d.proxyTrafficEntries...)
	d.proxyTrafficMu.Unlock()
	if len(rows) == 0 {
		rows = d.loadProxyTrafficEntriesFromDisk(200)
	}
	if len(rows) == 0 {
		dialog.ShowInformation("代理流量", "当前还没有可查看的代理流量日志。", d.window)
		return
	}

	selected := 0
	title := widget.NewLabelWithStyle("代理流量明细", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	detail := widget.NewMultiLineEntry()
	detail.Disable()
	detail.SetMinRowsVisible(18)

	list := widget.NewList(
		func() int { return len(rows) },
		func() fyne.CanvasObject {
			line1 := widget.NewLabel("流量")
			line1.TextStyle = fyne.TextStyle{Bold: true}
			line2 := widget.NewLabel("明细")
			line2.Wrapping = fyne.TextWrapOff
			return container.NewVBox(line1, line2)
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			row := rows[id]
			box := item.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(fmt.Sprintf("%s %s", strings.ToUpper(emptyFallback(row.Protocol, "-")), emptyFallback(row.Host, row.URL)))
			box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("%s | %s | %dms | %s", row.Time.Format("01-02 15:04:05"), emptyFallback(row.Method, "-"), row.DurationMS, emptyFallback(row.Error, strconv.Itoa(row.StatusCode))))
		},
	)

	updateDetail := func(index int) {
		if index < 0 || index >= len(rows) {
			return
		}
		selected = index
		row := rows[index]
		lines := []string{
			"时间: " + row.Time.Format(time.RFC3339),
			"协议: " + emptyFallback(row.Protocol, "-"),
			"来源: " + emptyFallback(row.ClientAddr, "-"),
			"方法: " + emptyFallback(row.Method, "-"),
			"URL: " + emptyFallback(row.URL, "-"),
			"Host: " + emptyFallback(row.Host, "-"),
			fmt.Sprintf("状态码: %d", row.StatusCode),
			fmt.Sprintf("耗时: %dms", row.DurationMS),
			fmt.Sprintf("流入/流出: %d / %d", row.BytesIn, row.BytesOut),
			"错误: " + emptyFallback(row.Error, "-"),
			"",
			"请求头:",
			emptyFallback(row.RequestHead, "-"),
			"",
			"请求体:",
			emptyFallback(row.RequestBody, "-"),
			"",
			"响应头:",
			emptyFallback(row.ResponseHead, "-"),
			"",
			"响应体:",
			emptyFallback(row.ResponseBody, "-"),
		}
		detail.SetText(strings.Join(lines, "\n"))
		title.SetText(fmt.Sprintf("代理流量明细 %d/%d", selected+1, len(rows)))
	}
	list.OnSelected = updateDetail
	updateDetail(0)

	viewer := d.app.NewWindow("代理流量")
	viewer.Resize(fyne.NewSize(1180, 760))
	viewer.SetContent(container.NewHSplit(
		neonPanel(accentCyan, list),
		neonPanel(accentBlue, container.NewBorder(title, nil, nil, nil, detail)),
	))
	viewer.Show()
}

func (d *dashboard) loadProxyTrafficEntriesFromDisk(limit int) []downstreamproxy.AuditEntry {
	data, err := os.ReadFile(d.proxyAuditLogPath())
	if err != nil || len(data) == 0 {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	rows := make([]downstreamproxy.AuditEntry, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var row downstreamproxy.AuditEntry
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

func (d *dashboard) openProxyFileOpenDialog(owner fyne.Window, title string, extensions []string, onLoaded func(name string, data []byte)) {
	_ = title
	fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, owner)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()

		data, readErr := io.ReadAll(reader)
		if readErr != nil {
			dialog.ShowError(readErr, owner)
			return
		}
		name := "proxy-material"
		if reader.URI() != nil {
			name = filepath.Base(reader.URI().Path())
		}
		onLoaded(name, data)
	}, owner)
	if len(extensions) > 0 {
		fileDialog.SetFilter(storage.NewExtensionFileFilter(extensions))
	}
	fileDialog.Show()
}

func (d *dashboard) openProxyFileSaveDialog(owner fyne.Window, title, defaultName string, data []byte) {
	_ = title
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, owner)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()
		if _, writeErr := writer.Write(data); writeErr != nil {
			dialog.ShowError(writeErr, owner)
		}
	}, owner)
	saveDialog.SetFileName(defaultName)
	saveDialog.Show()
}

func (d *dashboard) proxyMaterialData(pending []byte, currentPath string) ([]byte, error) {
	if len(pending) > 0 {
		return pending, nil
	}
	currentPath = strings.TrimSpace(currentPath)
	if currentPath == "" {
		return nil, fmt.Errorf("当前没有可导出的证书材料")
	}
	data, err := os.ReadFile(currentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("当前没有可导出的证书材料")
		}
		return nil, err
	}
	return data, nil
}

func (d *dashboard) writeProxyMaterial(target string, data []byte, perm os.FileMode) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("证书材料路径为空")
	}
	resolved := d.resolveWorkspacePath(target)
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return err
	}
	return os.WriteFile(resolved, data, perm)
}

func effectiveProxyPort(scheme string, port int) int {
	if port > 0 {
		return port
	}
	return netutil.DefaultProxyPort(scheme)
}

func proxyPortText(scheme string, port int) string {
	return strconv.Itoa(effectiveProxyPort(scheme, port))
}
