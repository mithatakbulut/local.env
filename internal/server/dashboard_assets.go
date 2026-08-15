package server

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
)

// dashboardAssets is generated from frontend/ with `npm run build`. Keeping
// the output beside the Go package makes the production binary self-contained.
//
//go:embed ui/dist
var dashboardAssets embed.FS

var hashedDashboardAsset = regexp.MustCompile(`^[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8,}\.(?:css|js)$`)

func (s *Server) dashboardAsset(w http.ResponseWriter, r *http.Request) {
	assetPath := r.PathValue("path")
	if !fs.ValidPath(assetPath) || strings.Contains(assetPath, "/") || !hashedDashboardAsset.MatchString(assetPath) {
		http.NotFound(w, r)
		return
	}

	asset, err := dashboardAssets.ReadFile(path.Join("ui/dist/assets", assetPath))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	contentType := mime.TypeByExtension(path.Ext(assetPath))
	if contentType == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(asset)
}

func dashboardAssetNames() ([]string, error) {
	entries, err := fs.ReadDir(dashboardAssets, "ui/dist/assets")
	if err != nil {
		return nil, err
	}
	assets := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && hashedDashboardAsset.MatchString(entry.Name()) {
			assets = append(assets, entry.Name())
		}
	}
	sort.Strings(assets)
	return assets, nil
}

type dashboardCompiledAssets struct {
	Stylesheet string
	Script     string
}

func dashboardShellAssets() (dashboardCompiledAssets, error) {
	names, err := dashboardAssetNames()
	if err != nil {
		return dashboardCompiledAssets{}, err
	}
	var assets dashboardCompiledAssets
	for _, name := range names {
		switch path.Ext(name) {
		case ".css":
			assets.Stylesheet = name
		case ".js":
			assets.Script = name
		}
	}
	if assets.Stylesheet == "" || assets.Script == "" {
		return dashboardCompiledAssets{}, fs.ErrNotExist
	}
	return assets, nil
}
