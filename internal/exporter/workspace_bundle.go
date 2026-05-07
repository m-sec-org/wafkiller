package exporter

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"wafbps/internal/config"
	"wafbps/internal/model"
)

const WorkspaceBundleVersion = 1

type WorkspaceBundleManifest struct {
	BundleVersion    int       `json:"bundle_version"`
	GeneratedAt      time.Time `json:"generated_at"`
	SiteCount        int       `json:"site_count"`
	DetectionCount   int       `json:"detection_count"`
	ResultCount      int       `json:"result_count"`
	PluginCount      int       `json:"plugin_count"`
	FingerprintCount int       `json:"fingerprint_count"`
}

type WorkspaceBundlePaths struct {
	ConfigPath        string
	WAFYAMLPath       string
	DatabasePath      string
	StartupCachePath  string
	PluginDir         string
	DiagnosticLogPath string
	ProxyCertPath     string
	ProxyKeyPath      string
	VirtualFiles      map[string][]byte
}

type WorkspaceBundleProgress struct {
	Current   int
	Total     int
	EntryName string
}

type WorkspaceBundleProgressFunc func(WorkspaceBundleProgress)

type workspaceBundleEntry struct {
	EntryName string
	Data      []byte
	DiskPath  string
}

func ExportWorkspaceBundle(path string, paths WorkspaceBundlePaths, manifest WorkspaceBundleManifest, progress WorkspaceBundleProgressFunc) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("导出路径不能为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()

	entries, err := buildWorkspaceBundleEntries(paths, manifest)
	if err != nil {
		return err
	}

	total := len(entries)
	for index, entry := range entries {
		data := entry.Data
		if data == nil {
			data, err = os.ReadFile(entry.DiskPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return err
			}
		}
		if err := addBundleBytes(zipWriter, entry.EntryName, data); err != nil {
			return err
		}
		if progress != nil {
			progress(WorkspaceBundleProgress{
				Current:   index + 1,
				Total:     total,
				EntryName: entry.EntryName,
			})
		}
	}
	return nil
}

func buildWorkspaceBundleEntries(paths WorkspaceBundlePaths, manifest WorkspaceBundleManifest) ([]workspaceBundleEntry, error) {
	manifest.BundleVersion = WorkspaceBundleVersion
	if manifest.GeneratedAt.IsZero() {
		manifest.GeneratedAt = time.Now()
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	entries := []workspaceBundleEntry{
		{
			EntryName: "bundle_manifest.json",
			Data:      manifestData,
		},
	}

	appendNamedBundleEntry(&entries, "config.json", paths.VirtualFiles, paths.ConfigPath)
	appendNamedBundleEntry(&entries, "waf.yaml", paths.VirtualFiles, paths.WAFYAMLPath)
	appendNamedBundleEntry(&entries, "database.json", paths.VirtualFiles, paths.DatabasePath)
	appendNamedBundleEntry(&entries, "startup_cache.json", paths.VirtualFiles, paths.StartupCachePath)
	appendNamedBundleEntry(&entries, "rule_validation_diagnostics.log", paths.VirtualFiles, paths.DiagnosticLogPath)
	appendNamedBundleEntry(&entries, "proxy/downstream-cert.pem", paths.VirtualFiles, paths.ProxyCertPath)
	appendNamedBundleEntry(&entries, "proxy/downstream-key.pem", paths.VirtualFiles, paths.ProxyKeyPath)
	if err := appendBundleDirEntries(&entries, paths.PluginDir, "plugins"); err != nil {
		return nil, err
	}
	return entries, nil
}

func ImportWorkspaceBundle(path string, currentConfigPath string) (WorkspaceBundleManifest, model.Config, error) {
	manifest := WorkspaceBundleManifest{}
	cfg := config.Default()
	if strings.TrimSpace(path) == "" {
		return manifest, cfg, fmt.Errorf("导入路径不能为空")
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		return manifest, cfg, err
	}
	defer reader.Close()

	index := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		index[filepath.ToSlash(strings.TrimSpace(file.Name))] = file
	}

	if manifestFile, ok := index["bundle_manifest.json"]; ok {
		if data, err := readBundleFile(manifestFile); err == nil {
			_ = json.Unmarshal(data, &manifest)
		}
	}

	configFile, ok := index["config.json"]
	if !ok {
		return manifest, cfg, fmt.Errorf("导入包缺少 config.json")
	}
	configData, err := readBundleFile(configFile)
	if err != nil {
		return manifest, cfg, err
	}
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return manifest, cfg, err
	}

	absConfigPath, err := filepath.Abs(currentConfigPath)
	if err != nil {
		return manifest, cfg, err
	}
	rootDir := filepath.Dir(absConfigPath)
	if err := config.Save(absConfigPath, cfg); err != nil {
		return manifest, cfg, err
	}

	resolvedDBPath := resolveBundleTarget(rootDir, cfg.App.DatabasePath)
	resolvedStartupPath := resolvedDBPath + ".startup.json"
	resolvedPluginDir := resolveBundleTarget(rootDir, cfg.Plugin.Dir)
	resolvedWAFPath := filepath.Join(rootDir, "waf.yaml")
	resolvedDiagPath := filepath.Join(rootDir, "data", "rule_validation_diagnostics.log")
	resolvedProxyCertPath := resolveBundleTarget(rootDir, cfg.Proxy.Downstream.CertificatePath)
	resolvedProxyKeyPath := resolveBundleTarget(rootDir, cfg.Proxy.Downstream.PrivateKeyPath)

	if file, ok := index["waf.yaml"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedWAFPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}
	if file, ok := index["database.json"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedDBPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}
	if file, ok := index["startup_cache.json"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedStartupPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}
	if file, ok := index["rule_validation_diagnostics.log"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedDiagPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}
	if file, ok := index["proxy/downstream-cert.pem"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedProxyCertPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}
	if file, ok := index["proxy/downstream-key.pem"]; ok {
		if data, err := readBundleFile(file); err == nil {
			if err := writeBundleTarget(resolvedProxyKeyPath, data); err != nil {
				return manifest, cfg, err
			}
		} else {
			return manifest, cfg, err
		}
	}

	pluginEntries := make([]*zip.File, 0)
	for name, file := range index {
		if strings.HasPrefix(name, "plugins/") && !strings.HasSuffix(name, "/") {
			pluginEntries = append(pluginEntries, file)
		}
	}
	if len(pluginEntries) > 0 {
		sort.Slice(pluginEntries, func(i, j int) bool {
			return pluginEntries[i].Name < pluginEntries[j].Name
		})
		if err := os.RemoveAll(resolvedPluginDir); err != nil {
			return manifest, cfg, err
		}
		for _, file := range pluginEntries {
			data, err := readBundleFile(file)
			if err != nil {
				return manifest, cfg, err
			}
			rel := strings.TrimPrefix(filepath.ToSlash(file.Name), "plugins/")
			target := filepath.Join(resolvedPluginDir, filepath.FromSlash(rel))
			if err := writeBundleTarget(target, data); err != nil {
				return manifest, cfg, err
			}
		}
	}

	return manifest, cfg, nil
}

func addBundleFileIfExists(zipWriter *zip.Writer, diskPath, entryName string) error {
	if strings.TrimSpace(diskPath) == "" {
		return nil
	}
	data, err := os.ReadFile(diskPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return addBundleBytes(zipWriter, entryName, data)
}

func addBundleNamedContentOrFile(zipWriter *zip.Writer, entryName string, virtual map[string][]byte, diskPath string) error {
	if len(virtual) > 0 {
		if data, ok := virtual[entryName]; ok {
			return addBundleBytes(zipWriter, entryName, data)
		}
	}
	return addBundleFileIfExists(zipWriter, diskPath, entryName)
}

func addBundleDirIfExists(zipWriter *zip.Writer, dirPath, entryRoot string) error {
	if strings.TrimSpace(dirPath) == "" {
		return nil
	}
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}

	files := make([]string, 0, 64)
	if err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(files)
	for _, filePath := range files {
		rel, err := filepath.Rel(dirPath, filePath)
		if err != nil {
			return err
		}
		entryName := filepath.ToSlash(filepath.Join(entryRoot, rel))
		if err := addBundleFileIfExists(zipWriter, filePath, entryName); err != nil {
			return err
		}
	}
	return nil
}

func appendNamedBundleEntry(entries *[]workspaceBundleEntry, entryName string, virtual map[string][]byte, diskPath string) {
	if len(virtual) > 0 {
		if data, ok := virtual[entryName]; ok {
			*entries = append(*entries, workspaceBundleEntry{
				EntryName: entryName,
				Data:      data,
			})
			return
		}
	}

	diskPath = strings.TrimSpace(diskPath)
	if diskPath == "" {
		return
	}
	if _, err := os.Stat(diskPath); err != nil {
		return
	}
	*entries = append(*entries, workspaceBundleEntry{
		EntryName: entryName,
		DiskPath:  diskPath,
	})
}

func appendBundleDirEntries(entries *[]workspaceBundleEntry, dirPath, entryRoot string) error {
	if strings.TrimSpace(dirPath) == "" {
		return nil
	}
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}

	files := make([]string, 0, 64)
	if err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(files)
	for _, filePath := range files {
		rel, err := filepath.Rel(dirPath, filePath)
		if err != nil {
			return err
		}
		*entries = append(*entries, workspaceBundleEntry{
			EntryName: filepath.ToSlash(filepath.Join(entryRoot, rel)),
			DiskPath:  filePath,
		})
	}
	return nil
}

func addBundleBytes(zipWriter *zip.Writer, entryName string, data []byte) error {
	writer, err := zipWriter.Create(filepath.ToSlash(entryName))
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func readBundleFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func resolveBundleTarget(rootDir, target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(rootDir, target)
}

func writeBundleTarget(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
