package agent

import (
	"net/http"
	"net/url"
	"strings"
)

func configuredProxyFunc(proxyRaw string) func(*http.Request) (*url.URL, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		return parseProxyURL(proxyRaw)
	}
}

func parseProxyURL(proxyRaw string) (*url.URL, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return nil, nil
	}
	if !strings.Contains(proxyRaw, "://") {
		proxyRaw = "http://" + proxyRaw
	}
	return url.Parse(proxyRaw)
}
