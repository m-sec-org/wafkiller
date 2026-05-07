package downstreamproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wafbps/internal/netutil"
)

const maxAuditBodyBytes = 64 * 1024

type Config struct {
	Scheme           string
	Host             string
	Port             int
	Username         string
	Password         string
	AllowedHosts     []string
	CertificatePath  string
	PrivateKeyPath   string
	UpstreamProxyURL string
	AuditLogPath     string
}

type AuditEntry struct {
	Time         time.Time `json:"time"`
	Protocol     string    `json:"protocol"`
	ClientAddr   string    `json:"client_addr"`
	Method       string    `json:"method,omitempty"`
	URL          string    `json:"url,omitempty"`
	Host         string    `json:"host,omitempty"`
	StatusCode   int       `json:"status_code,omitempty"`
	DurationMS   int64     `json:"duration_ms,omitempty"`
	RequestHead  string    `json:"request_head,omitempty"`
	RequestBody  string    `json:"request_body,omitempty"`
	ResponseHead string    `json:"response_head,omitempty"`
	ResponseBody string    `json:"response_body,omitempty"`
	BytesIn      int64     `json:"bytes_in,omitempty"`
	BytesOut     int64     `json:"bytes_out,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type Service struct {
	cfg       Config
	transport *http.Transport
	server    *http.Server
	listener  net.Listener
	cancel    context.CancelFunc
	onAudit   func(AuditEntry)

	mu      sync.RWMutex
	running bool
}

func New(cfg Config, onAudit func(AuditEntry)) *Service {
	cfg.Scheme = netutil.NormalizeProxyScheme(cfg.Scheme)
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port <= 0 {
		cfg.Port = netutil.DefaultProxyPort(cfg.Scheme)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = netutil.ConfiguredProxyFunc(cfg.UpstreamProxyURL)
	transport.ForceAttemptHTTP2 = false
	return &Service{
		cfg:       cfg,
		transport: transport,
		onAudit:   onAudit,
	}
}

func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		cancel()
		return err
	}

	switch s.cfg.Scheme {
	case "https":
		cert, certErr := tls.LoadX509KeyPair(s.cfg.CertificatePath, s.cfg.PrivateKeyPath)
		if certErr != nil {
			_ = ln.Close()
			cancel()
			return fmt.Errorf("加载下行 HTTPS 证书失败: %w", certErr)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	case "socks5":
		s.listener = ln
		s.running = true
		go s.serveSOCKS5(ctx, ln)
		return nil
	}

	server := &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: 15 * time.Second,
	}
	s.server = server
	s.listener = ln
	s.running = true
	go func() {
		_ = server.Serve(ln)
	}()
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	cancel := s.cancel
	server := s.server
	listener := s.listener
	s.running = false
	s.cancel = nil
	s.server = nil
	s.listener = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	var err error
	if server != nil {
		err = server.Shutdown(ctx)
	}
	if listener != nil {
		_ = listener.Close()
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return err
}

func (s *Service) Running() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Service) Addr() string {
	return net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
}

func (s *Service) serveHTTP(w http.ResponseWriter, req *http.Request) {
	startedAt := time.Now()
	if !s.authorized(req.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="wafbps-proxy"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "http",
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			URL:        req.URL.String(),
			Host:       req.Host,
			Error:      "proxy authentication required",
		})
		return
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		s.handleConnect(w, req, startedAt)
		return
	}

	targetURL := req.URL
	if !targetURL.IsAbs() {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		parsed, err := http.NewRequest(req.Method, scheme+"://"+req.Host+req.URL.RequestURI(), nil)
		if err == nil {
			targetURL = parsed.URL
		}
	}
	if !s.allowedHost(targetURL.Hostname()) {
		http.Error(w, "host is not in proxy whitelist", http.StatusForbidden)
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "http",
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			URL:        targetURL.String(),
			Host:       targetURL.Host,
			Error:      "host is not in proxy whitelist",
		})
		return
	}

	requestBody, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()

	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, targetURL.String(), strings.NewReader(string(requestBody)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "http",
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			URL:        targetURL.String(),
			Host:       targetURL.Host,
			Error:      err.Error(),
		})
		return
	}
	outReq.Header = cloneHeader(req.Header)
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")
	outReq.RequestURI = ""

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		s.audit(AuditEntry{
			Time:        time.Now(),
			Protocol:    "http",
			ClientAddr:  req.RemoteAddr,
			Method:      req.Method,
			URL:         targetURL.String(),
			Host:        targetURL.Host,
			DurationMS:  time.Since(startedAt).Milliseconds(),
			RequestHead: proxyRequestHead(req),
			RequestBody: limitText(string(requestBody), maxAuditBodyBytes),
			Error:       err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody)

	s.audit(AuditEntry{
		Time:         time.Now(),
		Protocol:     "http",
		ClientAddr:   req.RemoteAddr,
		Method:       req.Method,
		URL:          targetURL.String(),
		Host:         targetURL.Host,
		StatusCode:   resp.StatusCode,
		DurationMS:   time.Since(startedAt).Milliseconds(),
		RequestHead:  proxyRequestHead(req),
		RequestBody:  limitText(string(requestBody), maxAuditBodyBytes),
		ResponseHead: proxyResponseHead(resp),
		ResponseBody: limitText(string(responseBody), maxAuditBodyBytes),
		BytesIn:      int64(len(requestBody)),
		BytesOut:     int64(len(responseBody)),
	})
}

func (s *Service) handleConnect(w http.ResponseWriter, req *http.Request, startedAt time.Time) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	if !s.allowedHost(strings.TrimSpace(strings.Split(host, ":")[0])) {
		http.Error(w, "host is not in proxy whitelist", http.StatusForbidden)
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "connect",
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			Host:       host,
			Error:      "host is not in proxy whitelist",
		})
		return
	}

	targetConn, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "connect",
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			Host:       host,
			DurationMS: time.Since(startedAt).Milliseconds(),
			Error:      err.Error(),
		})
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = targetConn.Close()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	var bytesIn int64
	var bytesOut int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		bytesIn = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		bytesOut = n
		done <- struct{}{}
	}()
	<-done
	_ = clientConn.Close()
	_ = targetConn.Close()
	s.audit(AuditEntry{
		Time:       time.Now(),
		Protocol:   "connect",
		ClientAddr: req.RemoteAddr,
		Method:     req.Method,
		Host:       host,
		DurationMS: time.Since(startedAt).Milliseconds(),
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
	})
}

func (s *Service) serveSOCKS5(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go s.handleSOCKS5Conn(ctx, conn)
	}
}

func (s *Service) handleSOCKS5Conn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)

	version, err := reader.ReadByte()
	if err != nil || version != 0x05 {
		return
	}
	methodCount, err := reader.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	authRequired := strings.TrimSpace(s.cfg.Username) != ""
	method := byte(0x00)
	if authRequired {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return
	}
	if authRequired {
		if !s.handleSOCKS5Auth(reader, conn) {
			return
		}
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}
	if header[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	host, port, err := readSOCKS5Address(reader, header[3])
	if err != nil {
		return
	}
	if !s.allowedHost(host) {
		_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "socks5",
			ClientAddr: conn.RemoteAddr().String(),
			Host:       net.JoinHostPort(host, strconv.Itoa(port)),
			Error:      "host is not in proxy whitelist",
		})
		return
	}

	targetAddr := net.JoinHostPort(host, strconv.Itoa(port))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		s.audit(AuditEntry{
			Time:       time.Now(),
			Protocol:   "socks5",
			ClientAddr: conn.RemoteAddr().String(),
			Host:       targetAddr,
			Error:      err.Error(),
		})
		return
	}
	defer targetConn.Close()
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	_ = conn.SetDeadline(time.Time{})

	startedAt := time.Now()
	var bytesIn int64
	var bytesOut int64
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(targetConn, reader)
		bytesIn = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, targetConn)
		bytesOut = n
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
	s.audit(AuditEntry{
		Time:       time.Now(),
		Protocol:   "socks5",
		ClientAddr: conn.RemoteAddr().String(),
		Host:       targetAddr,
		DurationMS: time.Since(startedAt).Milliseconds(),
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
	})
}

func (s *Service) handleSOCKS5Auth(reader *bufio.Reader, conn net.Conn) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return false
	}
	userLen := int(header[1])
	username := make([]byte, userLen)
	if _, err := io.ReadFull(reader, username); err != nil {
		return false
	}
	passLenByte, err := reader.ReadByte()
	if err != nil {
		return false
	}
	password := make([]byte, int(passLenByte))
	if _, err := io.ReadFull(reader, password); err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(username, []byte(s.cfg.Username)) != 1 || subtle.ConstantTimeCompare(password, []byte(s.cfg.Password)) != 1 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return false
	}
	_, _ = conn.Write([]byte{0x01, 0x00})
	return true
}

func readSOCKS5Address(reader *bufio.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return net.IP(addr).String(), int(portBytes[0])<<8 | int(portBytes[1]), nil
	case 0x03:
		size, err := reader.ReadByte()
		if err != nil {
			return "", 0, err
		}
		hostBytes := make([]byte, int(size))
		if _, err := io.ReadFull(reader, hostBytes); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return string(hostBytes), int(portBytes[0])<<8 | int(portBytes[1]), nil
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, err
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBytes); err != nil {
			return "", 0, err
		}
		return net.IP(addr).String(), int(portBytes[0])<<8 | int(portBytes[1]), nil
	default:
		return "", 0, fmt.Errorf("unsupported address type")
	}
}

func (s *Service) audit(entry AuditEntry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	if strings.TrimSpace(s.cfg.AuditLogPath) != "" {
		_ = appendAuditLog(s.cfg.AuditLogPath, entry)
	}
	if s.onAudit != nil {
		s.onAudit(entry)
	}
}

func appendAuditLog(path string, entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *Service) authorized(proxyAuthorization string) bool {
	username := strings.TrimSpace(s.cfg.Username)
	if username == "" {
		return true
	}
	proxyAuthorization = strings.TrimSpace(proxyAuthorization)
	if !strings.HasPrefix(strings.ToLower(proxyAuthorization), "basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(proxyAuthorization[6:]))
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[0]), []byte(s.cfg.Username)) == 1 &&
		subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.cfg.Password)) == 1
}

func (s *Service) allowedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if len(s.cfg.AllowedHosts) == 0 {
		return true
	}
	for _, item := range s.cfg.AllowedHosts {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if host == item || strings.HasSuffix(host, "."+item) {
			return true
		}
	}
	return false
}

func proxyRequestHead(req *http.Request) string {
	dump, _ := httputil.DumpRequestOut(req, false)
	return string(dump)
}

func proxyResponseHead(resp *http.Response) string {
	dump, _ := httputil.DumpResponse(resp, false)
	return string(dump)
}

func cloneHeader(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for key, values := range src {
		copied := make([]string, len(values))
		copy(copied, values)
		dst[textproto.CanonicalMIMEHeaderKey(key)] = copied
	}
	return dst
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func limitText(raw string, limit int) string {
	if limit <= 0 || len(raw) <= limit {
		return raw
	}
	return raw[:limit] + "\n...[truncated]..."
}
