package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func setupWebServer(t *testing.T) (*webServer, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}

	branch, err := db.GetOrCreateBranch("main")
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to create branch: %v", err)
	}

	templates, err := newWebTemplates()
	if err != nil {
		_ = db.Close()
		t.Fatalf("failed to load templates: %v", err)
	}

	srv := &webServer{
		db:        db,
		branch:    branch,
		templates: templates,
	}

	return srv, func() { _ = db.Close() }
}

func setupWebMux(srv *webServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", srv.handleDashboard)
	mux.HandleFunc("GET /dependencies", srv.handleDependencies)
	mux.HandleFunc("GET /package/{ecosystem}/{name...}", srv.handlePackage)
	mux.Handle("GET /static/", http.StripPrefix("/static/", webStaticHandler()))
	return mux
}

func TestWebDashboard(t *testing.T) {
	srv, cleanup := setupWebServer(t)
	defer cleanup()
	mux := setupWebMux(srv)

	t.Run("renders dashboard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "git-pkgs") {
			t.Error("expected 'git-pkgs' in dashboard")
		}
		if !strings.Contains(body, "Commits Analyzed") {
			t.Error("expected stats grid in dashboard")
		}
		if !strings.Contains(body, "text/html") {
			ct := w.Header().Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				t.Errorf("expected text/html content type, got %s", ct)
			}
		}
	})
}

func TestWebDependencies(t *testing.T) {
	srv, cleanup := setupWebServer(t)
	defer cleanup()
	mux := setupWebMux(srv)

	t.Run("renders dependencies page", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dependencies", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Dependencies") {
			t.Error("expected 'Dependencies' heading")
		}
	})

	t.Run("filters by query param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dependencies?q=express", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, `value="express"`) {
			t.Error("expected query to be reflected in form input")
		}
	})

	t.Run("filters by ecosystem", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dependencies?ecosystem=npm", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestWebPackage(t *testing.T) {
	srv, cleanup := setupWebServer(t)
	defer cleanup()
	mux := setupWebMux(srv)

	t.Run("returns 404 for unknown package", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/package/npm/nonexistent-pkg", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestWebStaticFiles(t *testing.T) {
	srv, cleanup := setupWebServer(t)
	defer cleanup()
	mux := setupWebMux(srv)

	tests := []struct {
		path         string
		contentTypes []string
	}{
		{"/static/tailwind.js", []string{"text/javascript", "application/javascript"}},
		{"/static/style.css", []string{"text/css"}},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 for %s, got %d", tc.path, w.Code)
			}

			ct := w.Header().Get("Content-Type")
			found := false
			for _, expected := range tc.contentTypes {
				if strings.Contains(ct, expected) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected content type to be one of %v, got %s", tc.contentTypes, ct)
			}
		})
	}
}

func TestWebTemplates(t *testing.T) {
	t.Run("loads all templates", func(t *testing.T) {
		templates, err := newWebTemplates()
		if err != nil {
			t.Fatalf("failed to load templates: %v", err)
		}

		expectedPages := []string{"dashboard", "dependencies", "package"}
		for _, page := range expectedPages {
			if _, ok := templates.pages[page]; !ok {
				t.Errorf("expected template for page %q", page)
			}
		}
	})
}
