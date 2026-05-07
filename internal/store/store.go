package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"wafbps/internal/model"
)

const CurrentVersion = 1

type Database struct {
	Version      int                           `json:"version"`
	CreatedAt    time.Time                     `json:"created_at"`
	UpdatedAt    time.Time                     `json:"updated_at"`
	Current      Snapshot                      `json:"current"`
	Scans        []ScanRecord                  `json:"scans"`
	Fingerprints map[string]ClusterFingerprint `json:"fingerprints"`
	UsedSamples  map[string]bool               `json:"used_samples"`
}

type Snapshot struct {
	Sites               []model.Site                     `json:"sites"`
	SiteKeys            []string                         `json:"site_keys"`
	Detections          map[string]model.DetectionResult `json:"detections"`
	ClusterLabels       map[string]string                `json:"cluster_labels"`
	ClusterLabelSources map[string]string                `json:"cluster_label_sources"`
	ClusterRuleDetails  map[string]string                `json:"cluster_rule_details"`
	ClusterBaseline     []ClusterBaselineItem            `json:"cluster_baseline"`
	ClusterSnapshots    map[string]string                `json:"cluster_snapshots"`
	IgnoredClusters     map[string]bool                  `json:"ignored_clusters"`
	ClusterCount        int                              `json:"cluster_count"`
	Results             []model.TestResult               `json:"results"`
}

type ScanRecord struct {
	ID             string    `json:"id"`
	Query          string    `json:"query"`
	ChinaOnly      bool      `json:"china_only"`
	Page           int       `json:"page"`
	Size           int       `json:"size"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
	SiteCount      int       `json:"site_count"`
	SuspectedCount int       `json:"suspected_count"`
	ClusterCount   int       `json:"cluster_count"`
	ResultCount    int       `json:"result_count"`
}

type ClusterFingerprint struct {
	Signature        string                 `json:"signature"`
	Label            string                 `json:"label"`
	Source           string                 `json:"source"`
	Hint             string                 `json:"hint"`
	MatchDetail      string                 `json:"match_detail"`
	Snapshot         model.ResponseSnapshot `json:"snapshot"`
	SnapshotCacheKey string                 `json:"snapshot_cache_key"`
	MergeGroup       string                 `json:"merge_group"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

type ClusterBaselineItem struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Signature string `json:"signature"`
}

type Store struct {
	path string
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (Database, error) {
	db := emptyDatabase()
	if s == nil || s.path == "" {
		return db, nil
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return db, nil
		}
		return db, err
	}

	if len(data) == 0 {
		return db, nil
	}

	if err := json.Unmarshal(data, &db); err != nil {
		return db, err
	}
	applyDefaults(&db)
	return db, nil
}

func (s *Store) Save(db Database) error {
	if s == nil || s.path == "" {
		return nil
	}

	applyDefaults(&db)
	db.UpdatedAt = time.Now()
	if db.CreatedAt.IsZero() {
		db.CreatedAt = db.UpdatedAt
	}

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *Store) Reset() error {
	return s.ResetWithFingerprints(nil)
}

func (s *Store) ResetWithFingerprints(fingerprints map[string]ClusterFingerprint) error {
	db := emptyDatabase()
	if len(fingerprints) > 0 {
		db.Fingerprints = cloneFingerprintMap(fingerprints)
	} else if existing, err := s.Load(); err == nil {
		db.Fingerprints = existing.Fingerprints
	}
	if err := s.Save(db); err != nil {
		return err
	}
	return s.SaveStartupCache(StartupCache{})
}

func cloneFingerprintMap(src map[string]ClusterFingerprint) map[string]ClusterFingerprint {
	if len(src) == 0 {
		return map[string]ClusterFingerprint{}
	}
	dst := make(map[string]ClusterFingerprint, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func emptyDatabase() Database {
	now := time.Now()
	return Database{
		Version:   CurrentVersion,
		CreatedAt: now,
		UpdatedAt: now,
		Current: Snapshot{
			Sites:               []model.Site{},
			SiteKeys:            []string{},
			Detections:          map[string]model.DetectionResult{},
			ClusterLabels:       map[string]string{},
			ClusterLabelSources: map[string]string{},
			ClusterRuleDetails:  map[string]string{},
			ClusterBaseline:     []ClusterBaselineItem{},
			ClusterSnapshots:    map[string]string{},
			IgnoredClusters:     map[string]bool{},
			ClusterCount:        0,
			Results:             []model.TestResult{},
		},
		Scans:        []ScanRecord{},
		Fingerprints: map[string]ClusterFingerprint{},
		UsedSamples:  map[string]bool{},
	}
}

func applyDefaults(db *Database) {
	if db.Version <= 0 {
		db.Version = CurrentVersion
	}
	if db.Current.Sites == nil {
		db.Current.Sites = []model.Site{}
	}
	if db.Current.SiteKeys == nil {
		db.Current.SiteKeys = []string{}
	}
	if db.Current.Detections == nil {
		db.Current.Detections = map[string]model.DetectionResult{}
	}
	if db.Current.ClusterLabels == nil {
		db.Current.ClusterLabels = map[string]string{}
	}
	if db.Current.ClusterLabelSources == nil {
		db.Current.ClusterLabelSources = map[string]string{}
	}
	if db.Current.ClusterRuleDetails == nil {
		db.Current.ClusterRuleDetails = map[string]string{}
	}
	if db.Current.ClusterBaseline == nil {
		db.Current.ClusterBaseline = []ClusterBaselineItem{}
	}
	if db.Current.ClusterSnapshots == nil {
		db.Current.ClusterSnapshots = map[string]string{}
	}
	if db.Current.IgnoredClusters == nil {
		db.Current.IgnoredClusters = map[string]bool{}
	}
	if db.Current.ClusterCount < 0 {
		db.Current.ClusterCount = 0
	}
	if db.Current.Results == nil {
		db.Current.Results = []model.TestResult{}
	}
	if db.Scans == nil {
		db.Scans = []ScanRecord{}
	}
	if db.Fingerprints == nil {
		db.Fingerprints = map[string]ClusterFingerprint{}
	}
	if db.UsedSamples == nil {
		db.UsedSamples = map[string]bool{}
	}
}
