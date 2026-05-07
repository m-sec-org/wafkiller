package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"wafbps/internal/model"
	"wafbps/internal/netutil"
)

const DefaultConfigPath = "config.json"
const MaxFOFASize = 10000

func Default() model.Config {
	return model.Config{
		FOFA: model.FOFAConfig{
			BaseURL:     "https://fofa.info",
			Query:       "waf",
			Size:        2000,
			DefaultPage: 1,
			Fields: []string{
				"host", "ip", "title", "domain", "port", "protocol",
				"server", "product", "header", "country_name", "city", "lastupdatetime",
			},
		},
		App: model.AppSettings{
			ConfigPath:   DefaultConfigPath,
			DatabasePath: "data/wafkiller.db.json",
			WindowTitle:  "WAF Killer",
		},
		Tester: model.TesterSettings{
			TimeoutSeconds:      15,
			Concurrency:         100,
			SnapshotConcurrency: 20,
			VerifyTLS:           true,
			DefaultScheme:       "https",
			BlockStatusCodes:    []int{403, 406, 412, 429, 493, 503},
			BlockKeywords: []string{
				"access denied", "forbidden", "blocked", "waf", "firewall", "suspicious request",
			},
			MaxBodyPreview: 4096,
		},
		Plugin: model.PluginSettings{
			Dir: "plugins",
		},
		Proxy: model.ProxySettings{
			Upstream: model.ProxyEndpoint{
				Enabled: false,
				Scheme:  "http",
			},
			Downstream: model.DownstreamProxySetting{
				Enabled:         false,
				Scheme:          "http",
				Host:            "127.0.0.1",
				Port:            8080,
				AllowedHosts:    []string{},
				CertificatePath: "data/proxy/downstream-cert.pem",
				PrivateKeyPath:  "data/proxy/downstream-key.pem",
			},
		},
		LLMProvider: "openai",
		OpenAI: model.OpenAISettings{
			Enabled:         true,
			BaseURL:         "https://api.openai.com/v1",
			ProxyURL:        "",
			Model:           "gpt-5.4",
			ReasoningEffort: "low",
			TimeoutSeconds:  90,
		},
		Zhipu: model.ZhipuSettings{
			Enabled:         false,
			BaseURL:         "https://open.bigmodel.cn/api/paas/v4",
			ProxyURL:        "",
			Model:           "glm-5.1",
			ReasoningEffort: "low",
			TimeoutSeconds:  90,
		},
		WAFSignatures: []model.WAFSignature{
			{Name: "Cloudflare", Keywords: []string{"cloudflare", "__cf_bm", "cf-ray", "cf-cache-status"}},
			{Name: "Akamai", Keywords: []string{"akamai", "akamaighost", "ghost"}},
			{Name: "AWS WAF", Keywords: []string{"awswaf", "awselb", "x-amzn-waf"}},
			{Name: "ModSecurity", Keywords: []string{"mod_security", "modsecurity"}},
			{Name: "F5 BIG-IP ASM", Keywords: []string{"bigip", "x-waf-event-info", "f5"}},
			{Name: "SafeLine", Keywords: []string{"safeline", "chaitin", "雷池"}},
			{Name: "AliYun WAF", Keywords: []string{"aliyunwaf", "aliyun", "yundun"}},
			{Name: "Tencent WAF", Keywords: []string{"tencent", "edgeone", "waf.tencent"}},
		},
		Variables: map[string]string{
			"PAYLOAD":    "' or 1=1 --",
			"USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		},
	}
}

func Load(path string) (model.Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.App.ConfigPath = path
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.App.ConfigPath == "" {
		cfg.App.ConfigPath = path
	}
	applyDefaults(&cfg)
	return cfg, nil
}

func Save(path string, cfg model.Config) error {
	if path == "" {
		path = DefaultConfigPath
	}
	cfg.App.ConfigPath = path
	applyDefaults(&cfg)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	return os.WriteFile(path, data, 0o644)
}

func applyDefaults(cfg *model.Config) {
	def := Default()

	if cfg.FOFA.BaseURL == "" {
		cfg.FOFA.BaseURL = def.FOFA.BaseURL
	}
	if cfg.FOFA.Query == "" {
		cfg.FOFA.Query = def.FOFA.Query
	}
	if cfg.FOFA.Size <= 0 {
		cfg.FOFA.Size = def.FOFA.Size
	} else if cfg.FOFA.Size > MaxFOFASize {
		cfg.FOFA.Size = MaxFOFASize
	}
	if cfg.FOFA.DefaultPage <= 0 {
		cfg.FOFA.DefaultPage = def.FOFA.DefaultPage
	}
	if len(cfg.FOFA.Fields) == 0 {
		cfg.FOFA.Fields = def.FOFA.Fields
	}
	if cfg.App.WindowTitle == "" {
		cfg.App.WindowTitle = def.App.WindowTitle
	}
	if cfg.App.ConfigPath == "" {
		cfg.App.ConfigPath = DefaultConfigPath
	}
	if cfg.App.DatabasePath == "" {
		cfg.App.DatabasePath = def.App.DatabasePath
	}
	if cfg.Tester.TimeoutSeconds <= 0 {
		cfg.Tester.TimeoutSeconds = def.Tester.TimeoutSeconds
	}
	if cfg.Tester.Concurrency <= 0 {
		cfg.Tester.Concurrency = def.Tester.Concurrency
	}
	if cfg.Tester.SnapshotConcurrency <= 0 {
		cfg.Tester.SnapshotConcurrency = def.Tester.SnapshotConcurrency
	}
	if cfg.Tester.DefaultScheme == "" {
		cfg.Tester.DefaultScheme = def.Tester.DefaultScheme
	}
	if len(cfg.Tester.BlockStatusCodes) == 0 {
		cfg.Tester.BlockStatusCodes = def.Tester.BlockStatusCodes
	}
	if len(cfg.Tester.BlockKeywords) == 0 {
		cfg.Tester.BlockKeywords = def.Tester.BlockKeywords
	}
	if cfg.Tester.MaxBodyPreview <= 0 {
		cfg.Tester.MaxBodyPreview = def.Tester.MaxBodyPreview
	}
	if cfg.Plugin.Dir == "" {
		cfg.Plugin.Dir = def.Plugin.Dir
	}
	if cfg.Proxy.Upstream.Scheme == "" {
		cfg.Proxy.Upstream.Scheme = def.Proxy.Upstream.Scheme
	}
	if cfg.Proxy.Downstream.Scheme == "" {
		cfg.Proxy.Downstream.Scheme = def.Proxy.Downstream.Scheme
	}
	if cfg.Proxy.Downstream.Host == "" {
		cfg.Proxy.Downstream.Host = def.Proxy.Downstream.Host
	}
	if cfg.Proxy.Downstream.Port <= 0 {
		cfg.Proxy.Downstream.Port = def.Proxy.Downstream.Port
	}
	if cfg.Proxy.Downstream.AllowedHosts == nil {
		cfg.Proxy.Downstream.AllowedHosts = def.Proxy.Downstream.AllowedHosts
	}
	if cfg.Proxy.Downstream.CertificatePath == "" {
		cfg.Proxy.Downstream.CertificatePath = def.Proxy.Downstream.CertificatePath
	}
	if cfg.Proxy.Downstream.PrivateKeyPath == "" {
		cfg.Proxy.Downstream.PrivateKeyPath = def.Proxy.Downstream.PrivateKeyPath
	}
	migrateLegacyProviderProxy(cfg)
	if cfg.LLMProvider == "" {
		cfg.LLMProvider = def.LLMProvider
	}
	if cfg.OpenAI.BaseURL == "" {
		cfg.OpenAI.BaseURL = def.OpenAI.BaseURL
	}
	if cfg.OpenAI.ProxyURL == "" {
		cfg.OpenAI.ProxyURL = def.OpenAI.ProxyURL
	}
	if cfg.OpenAI.Model == "" {
		cfg.OpenAI.Model = def.OpenAI.Model
	}
	if cfg.OpenAI.ReasoningEffort == "" {
		cfg.OpenAI.ReasoningEffort = def.OpenAI.ReasoningEffort
	}
	if cfg.OpenAI.TimeoutSeconds <= 0 {
		cfg.OpenAI.TimeoutSeconds = def.OpenAI.TimeoutSeconds
	}
	if cfg.Zhipu.BaseURL == "" {
		cfg.Zhipu.BaseURL = def.Zhipu.BaseURL
	}
	if cfg.Zhipu.ProxyURL == "" {
		cfg.Zhipu.ProxyURL = def.Zhipu.ProxyURL
	}
	if cfg.Zhipu.Model == "" {
		cfg.Zhipu.Model = def.Zhipu.Model
	}
	if cfg.Zhipu.ReasoningEffort == "" {
		cfg.Zhipu.ReasoningEffort = def.Zhipu.ReasoningEffort
	}
	if cfg.Zhipu.TimeoutSeconds <= 0 {
		cfg.Zhipu.TimeoutSeconds = def.Zhipu.TimeoutSeconds
	}
	if len(cfg.WAFSignatures) == 0 {
		cfg.WAFSignatures = def.WAFSignatures
	}
	if cfg.Variables == nil {
		cfg.Variables = def.Variables
	}
}

func migrateLegacyProviderProxy(cfg *model.Config) {
	if stringsTrimmed(cfg.Proxy.Upstream.Host) != "" {
		return
	}
	legacy := firstNonEmpty(
		cfg.OpenAI.ProxyURL,
		cfg.Zhipu.ProxyURL,
	)
	if stringsTrimmed(legacy) == "" {
		return
	}
	parts, err := netutil.ParseProxyParts(legacy)
	if err != nil || parts.Host == "" {
		return
	}
	cfg.Proxy.Upstream.Enabled = true
	cfg.Proxy.Upstream.Scheme = parts.Scheme
	cfg.Proxy.Upstream.Host = parts.Host
	cfg.Proxy.Upstream.Port = parts.Port
	cfg.Proxy.Upstream.Username = parts.Username
	cfg.Proxy.Upstream.Password = parts.Password
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if stringsTrimmed(value) != "" {
			return value
		}
	}
	return ""
}

func stringsTrimmed(value string) string {
	return strings.TrimSpace(value)
}
