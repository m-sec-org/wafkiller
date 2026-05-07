package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type StartupCache struct {
	UpdatedAt         time.Time    `json:"updated_at"`
	SiteCount         int          `json:"site_count"`
	SuspectedCount    int          `json:"suspected_count"`
	ClusterCount      int          `json:"cluster_count"`
	FingerprintCount  int          `json:"fingerprint_count"`
	UnlabeledFPCount  int          `json:"unlabeled_fingerprint_count"`
}

func (s *Store) startupPath() string {
	if s == nil || s.path == "" {
		return ""
	}
	return s.path + ".startup.json"
}

func (s *Store) LoadStartupCache() (StartupCache, error) {
	cache := StartupCache{}
	path := s.startupPath()
	if path == "" {
		return cache, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, err
	}
	if len(data) == 0 {
		return cache, nil
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		return cache, err
	}
	return cache, nil
}

func (s *Store) SaveStartupCache(cache StartupCache) error {
	path := s.startupPath()
	if path == "" {
		return nil
	}
	cache.UpdatedAt = time.Now()
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}
