package cmd

import (
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

type webServer struct {
	db        *database.DB
	branch    *database.BranchInfo
	templates *webTemplates
}

type ecosystemEntry struct {
	Name  string
	Count int
}

type dashboardData struct {
	Branch     string
	Stats      *database.Stats
	Ecosystems []ecosystemEntry
	VulnStats  map[string]int
}

type dependenciesData struct {
	Branch       string
	Dependencies []database.Dependency
	TotalCount   int
	Query        string
	Ecosystem    string
	Ecosystems   []string
}

type packageData struct {
	Name               string
	Ecosystem          string
	CurrentRequirement string
	CurrentDeps        []database.Dependency
	History            []database.HistoryEntry
	Vulnerabilities    []database.Vulnerability
	Notes              []database.Note
}

func (s *webServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetStats(database.StatsOptions{
		BranchID: s.branch.ID,
		Limit:    10,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var ecos []ecosystemEntry
	for name, count := range stats.DepsByEcosystem {
		ecos = append(ecos, ecosystemEntry{Name: name, Count: count})
	}
	sort.Slice(ecos, func(i, j int) bool {
		return ecos[i].Count > ecos[j].Count
	})

	vulnStats, err := s.db.GetVulnerabilityStats(s.branch.ID)
	if err != nil {
		// Not fatal, just skip vuln display
		vulnStats = nil
	}
	// Only show vuln section if there are actual vulnerabilities
	hasVulns := false
	for _, count := range vulnStats {
		if count > 0 {
			hasVulns = true
			break
		}
	}
	if !hasVulns {
		vulnStats = nil
	}

	data := dashboardData{
		Branch:     s.branch.Name,
		Stats:      stats,
		Ecosystems: ecos,
		VulnStats:  vulnStats,
	}

	if err := s.templates.render(w, "dashboard", data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (s *webServer) handleDependencies(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	ecosystem := r.URL.Query().Get("ecosystem")

	var deps []database.Dependency
	var err error

	deps, err = s.db.GetLatestDependencies(s.branch.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Collect unique ecosystems for the filter dropdown
	ecoSet := make(map[string]bool)
	for _, d := range deps {
		if d.Ecosystem != "" {
			ecoSet[d.Ecosystem] = true
		}
	}
	var ecosystems []string
	for eco := range ecoSet {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)

	// Apply filters
	if ecosystem != "" {
		deps = filterByEcosystem(deps, ecosystem)
	}
	if query != "" {
		var filtered []database.Dependency
		q := strings.ToLower(query)
		for _, d := range deps {
			if strings.Contains(strings.ToLower(d.Name), q) {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	data := dependenciesData{
		Branch:       s.branch.Name,
		Dependencies: deps,
		TotalCount:   len(deps),
		Query:        query,
		Ecosystem:    ecosystem,
		Ecosystems:   ecosystems,
	}

	if err := s.templates.render(w, "dependencies", data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (s *webServer) handlePackage(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.PathValue("ecosystem")
	name := r.PathValue("name")

	if ecosystem == "" || name == "" {
		http.NotFound(w, r)
		return
	}

	// Get current dependency info
	allDeps, err := s.db.GetLatestDependencies(s.branch.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var currentDeps []database.Dependency
	var currentReq string
	for _, d := range allDeps {
		if strings.EqualFold(d.Name, name) && strings.EqualFold(d.Ecosystem, ecosystem) {
			currentDeps = append(currentDeps, d)
			if currentReq == "" {
				currentReq = d.Requirement
			}
		}
	}

	// Get history
	history, err := s.db.GetPackageHistory(database.HistoryOptions{
		BranchID:    s.branch.ID,
		PackageName: name,
		Ecosystem:   ecosystem,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get vulnerabilities
	vulns, err := s.db.GetVulnerabilitiesForPackage(ecosystem, name)
	if err != nil {
		// Not fatal
		vulns = nil
	}

	// Get notes (filter by PURL pattern)
	purl := "pkg:" + strings.ToLower(ecosystem) + "/" + name
	notes, err := s.db.ListNotes("", purl)
	if err != nil {
		// Not fatal
		notes = nil
	}

	if len(currentDeps) == 0 && len(history) == 0 {
		http.NotFound(w, r)
		return
	}

	data := packageData{
		Name:               name,
		Ecosystem:          ecosystem,
		CurrentRequirement: currentReq,
		CurrentDeps:        currentDeps,
		History:            history,
		Vulnerabilities:    vulns,
		Notes:              notes,
	}

	if err := s.templates.render(w, "package", data); err != nil {
		log.Printf("template error: %v", err)
	}
}
