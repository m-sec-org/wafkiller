package fofa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wafbps/internal/model"
	"wafbps/internal/netutil"
)

type Client struct {
	httpClient *http.Client
	cfg        model.FOFAConfig
	signatures []model.WAFSignature
}

type apiResponse struct {
	Error   bool       `json:"error"`
	Mode    string     `json:"mode"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`
	Page    int        `json:"page"`
	Results [][]string `json:"results"`
}

type BatchProgress struct {
	Page       int
	BatchSize  int
	TotalCount int
	Sites      []model.Site
}

func NewClient(cfg model.FOFAConfig, signatures []model.WAFSignature, proxyURL string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = netutil.ConfiguredProxyFunc(proxyURL)
	return &Client{
		httpClient: &http.Client{
			Timeout:   25 * time.Second,
			Transport: transport,
		},
		cfg:        cfg,
		signatures: signatures,
	}
}

func (c *Client) SearchSites(ctx context.Context, query string, page, size int) ([]model.Site, error) {
	if c.cfg.Email == "" || c.cfg.APIKey == "" {
		return nil, fmt.Errorf("missing FOFA email or api key")
	}
	if query == "" {
		query = c.cfg.Query
	}
	if page <= 0 {
		page = c.cfg.DefaultPage
	}
	if size <= 0 {
		size = c.cfg.Size
	}
	return c.searchPage(ctx, query, page, size)
}

func (c *Client) SearchSitesBatch(ctx context.Context, query string, page, size, perPage int, onProgress func(BatchProgress)) ([]model.Site, error) {
	if c.cfg.Email == "" || c.cfg.APIKey == "" {
		return nil, fmt.Errorf("missing FOFA email or api key")
	}
	if query == "" {
		query = c.cfg.Query
	}
	if page <= 0 {
		page = c.cfg.DefaultPage
	}
	if size <= 0 {
		size = c.cfg.Size
	}
	if perPage <= 0 {
		perPage = 100
	}
	if perPage > size {
		perPage = size
	}

	sites := make([]model.Site, 0, size)
	currentPage := page
	for len(sites) < size {
		remaining := size - len(sites)
		batchSize := perPage
		if remaining < batchSize {
			batchSize = remaining
		}
		batch, err := c.searchPage(ctx, query, currentPage, batchSize)
		if err != nil {
			return nil, err
		}
		sites = append(sites, batch...)
		if onProgress != nil {
			onProgress(BatchProgress{
				Page:       currentPage,
				BatchSize:  len(batch),
				TotalCount: len(sites),
				Sites:      batch,
			})
		}
		if len(batch) < batchSize {
			break
		}
		currentPage++
	}
	return sites, nil
}

func (c *Client) searchPage(ctx context.Context, query string, page, size int) ([]model.Site, error) {
	base, err := url.Parse(strings.TrimRight(c.cfg.BaseURL, "/") + "/api/v1/search/all")
	if err != nil {
		return nil, err
	}

	params := base.Query()
	params.Set("email", c.cfg.Email)
	params.Set("key", c.cfg.APIKey)
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	params.Set("fields", strings.Join(c.cfg.Fields, ","))
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("size", fmt.Sprintf("%d", size))
	base.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fofa status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload apiResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if payload.Error {
		return nil, fmt.Errorf("fofa error: %s", payload.ErrMsg)
	}

	sites := make([]model.Site, 0, len(payload.Results))
	for _, row := range payload.Results {
		site := c.mapRow(row)
		site.WAF = c.detectWAF(site)
		sites = append(sites, site)
	}
	return sites, nil
}

func (c *Client) mapRow(row []string) model.Site {
	site := model.Site{}
	for idx, field := range c.cfg.Fields {
		if idx >= len(row) {
			continue
		}
		value := strings.TrimSpace(row[idx])
		switch field {
		case "host":
			site.OriginalURL = value
			site.URL = ensureURL(value, site.Protocol)
			site.Host = extractHost(site.URL, value)
		case "ip":
			site.IP = value
		case "title":
			site.Title = value
		case "domain":
			site.Domain = value
		case "port":
			site.Port = value
		case "protocol":
			site.Protocol = value
			if site.URL != "" {
				site.URL = ensureURL(site.URL, value)
				site.Host = extractHost(site.URL, site.Host)
			}
		case "server":
			site.Server = value
		case "product":
			site.Product = value
		case "header":
			site.Header = value
		case "country_name":
			site.Country = value
		case "city":
			site.City = value
		case "lastupdatetime":
			site.LastSeen = value
		}
	}
	if site.URL == "" && site.Host != "" {
		site.URL = ensureURL(site.Host, site.Protocol)
	}
	if site.OriginalURL == "" {
		site.OriginalURL = site.URL
	}
	if site.Host == "" {
		site.Host = extractHost(site.URL, site.Domain)
	}
	return site
}

func (c *Client) detectWAF(site model.Site) string {
	joined := strings.ToLower(strings.Join([]string{
		site.WAF, site.Product, site.Title, site.Server, site.Header, site.Domain,
	}, " "))
	for _, sig := range c.signatures {
		for _, keyword := range sig.Keywords {
			if strings.Contains(joined, strings.ToLower(keyword)) {
				return sig.Name
			}
		}
	}
	if site.Product != "" {
		return site.Product
	}
	return "Unknown"
}

func ensureURL(value string, protocol string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}
	if protocol == "" {
		protocol = "https"
	}
	return protocol + "://" + strings.TrimSpace(value)
}

func extractHost(rawURL, fallback string) string {
	if rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(fallback, "http://"), "https://"))
}
