package netutil

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ProxyParts struct {
	Scheme   string
	Host     string
	Port     int
	Username string
	Password string
}

func ConfiguredProxyFunc(proxyRaw string) func(*http.Request) (*url.URL, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		return ParseProxyURL(proxyRaw)
	}
}

func ParseProxyURL(proxyRaw string) (*url.URL, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return nil, nil
	}
	if !strings.Contains(proxyRaw, "://") {
		proxyRaw = "http://" + proxyRaw
	}
	return url.Parse(proxyRaw)
}

func NormalizeProxyScheme(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "http", "https", "socks5", "socks5h":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "http"
	}
}

func DefaultProxyPort(scheme string) int {
	switch NormalizeProxyScheme(scheme) {
	case "https":
		return 443
	case "socks5", "socks5h":
		return 1080
	default:
		return 80
	}
}

func BuildProxyURL(scheme, host string, port int, username, password string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	scheme = NormalizeProxyScheme(scheme)
	if port <= 0 {
		port = DefaultProxyPort(scheme)
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	username = strings.TrimSpace(username)
	if username != "" {
		if password != "" {
			u.User = url.UserPassword(username, password)
		} else {
			u.User = url.User(username)
		}
	}
	return u.String()
}

func ParseProxyParts(proxyRaw string) (ProxyParts, error) {
	parsed, err := ParseProxyURL(proxyRaw)
	if err != nil {
		return ProxyParts{}, err
	}
	if parsed == nil {
		return ProxyParts{}, nil
	}

	parts := ProxyParts{
		Scheme: NormalizeProxyScheme(parsed.Scheme),
		Host:   strings.TrimSpace(parsed.Hostname()),
	}
	if portText := strings.TrimSpace(parsed.Port()); portText != "" {
		if port, convErr := strconv.Atoi(portText); convErr == nil {
			parts.Port = port
		}
	}
	if parts.Port <= 0 {
		parts.Port = DefaultProxyPort(parts.Scheme)
	}
	if parsed.User != nil {
		parts.Username = parsed.User.Username()
		parts.Password, _ = parsed.User.Password()
	}
	return parts, nil
}
