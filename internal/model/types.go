package model

import "time"

type Config struct {
	FOFA          FOFAConfig        `json:"fofa"`
	App           AppSettings       `json:"app"`
	Tester        TesterSettings    `json:"tester"`
	Plugin        PluginSettings    `json:"plugin"`
	Proxy         ProxySettings     `json:"proxy"`
	LLMProvider   string            `json:"llm_provider"`
	OpenAI        OpenAISettings    `json:"openai"`
	Zhipu         ZhipuSettings     `json:"zhipu"`
	WAFSignatures []WAFSignature    `json:"waf_signatures"`
	Variables     map[string]string `json:"variables"`
}

type FOFAConfig struct {
	Email       string   `json:"email"`
	APIKey      string   `json:"api_key"`
	BaseURL     string   `json:"base_url"`
	Query       string   `json:"query"`
	Size        int      `json:"size"`
	DefaultPage int      `json:"default_page"`
	Fields      []string `json:"fields"`
}

type AppSettings struct {
	ConfigPath   string `json:"config_path"`
	DatabasePath string `json:"database_path"`
	WindowTitle  string `json:"window_title"`
}

type TesterSettings struct {
	TimeoutSeconds      int      `json:"timeout_seconds"`
	Concurrency         int      `json:"concurrency"`
	SnapshotConcurrency int      `json:"snapshot_concurrency"`
	VerifyTLS           bool     `json:"verify_tls"`
	DefaultScheme       string   `json:"default_scheme"`
	BlockStatusCodes    []int    `json:"block_status_codes"`
	BlockKeywords       []string `json:"block_keywords"`
	MaxBodyPreview      int      `json:"max_body_preview"`
}

type PluginSettings struct {
	Dir string `json:"dir"`
}

type ProxySettings struct {
	Upstream   ProxyEndpoint          `json:"upstream"`
	Downstream DownstreamProxySetting `json:"downstream"`
}

type ProxyEndpoint struct {
	Enabled  bool   `json:"enabled"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type DownstreamProxySetting struct {
	Enabled         bool     `json:"enabled"`
	Scheme          string   `json:"scheme"`
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	AllowedHosts    []string `json:"allowed_hosts"`
	CertificatePath string   `json:"certificate_path"`
	PrivateKeyPath  string   `json:"private_key_path"`
}

type OpenAISettings struct {
	Enabled         bool   `json:"enabled"`
	APIKey          string `json:"api_key"`
	BaseURL         string `json:"base_url"`
	ProxyURL        string `json:"proxy_url"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type ZhipuSettings struct {
	Enabled         bool   `json:"enabled"`
	APIKey          string `json:"api_key"`
	BaseURL         string `json:"base_url"`
	ProxyURL        string `json:"proxy_url"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type WAFSignature struct {
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
}

type Site struct {
	Host        string
	OriginalURL string
	URL         string
	Domain      string
	IP          string
	Port        string
	Protocol    string
	Title       string
	Server      string
	Product     string
	WAF         string
	Country     string
	City        string
	Header      string
	LastSeen    string
}

type ResponseSnapshot struct {
	URL        string
	StatusCode int
	Headers    string
	Body       string
	Title      string
	Raw        string
}

type DetectionResult struct {
	Site            Site
	RunAt           time.Time
	DetectedURL     string
	Baseline        ResponseSnapshot
	ProbeA          ResponseSnapshot
	ProbeB          ResponseSnapshot
	SimilarityA     float64
	SimilarityB     float64
	ChangedA        bool
	ChangedB        bool
	HasWAF          bool
	ClusterKey      string
	ClusterLabel    string
	ClusterHint     string
	BlockedResponse ResponseSnapshot
	Error           string
}

type RuleIntent struct {
	Name string
	Args map[string]string
}

type Plugin struct {
	Name                string
	Path                string
	Tags                []string
	Color               string
	Intents             []RuleIntent
	Scheme              string
	PreflightMode       string
	PreflightPrune      *bool
	ValidationMode      string
	SimilarityThreshold float64
	Method              string
	RequestURI          string
	Host                string
	Headers             map[string]string
	Body                string
	Notes               string
	Raw                 string
	LintWarnings        []string
}

type TestResult struct {
	Site         Site
	Plugin       Plugin
	RunAt        time.Time
	StatusCode   int
	Duration     time.Duration
	Verdict      string
	Error        string
	SentRequest  string
	ResponseBody string
	ResponseHead string
	MatchedRule  string
	BaselineSim  float64
	BlockedSim   float64
	DiffRatio    float64
}
