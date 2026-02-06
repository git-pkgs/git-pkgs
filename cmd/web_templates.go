package cmd

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

//go:embed web/templates/**/*.html
var webTemplatesFS embed.FS

//go:embed web/static/*
var webStaticFiles embed.FS

type webTemplates struct {
	pages map[string]*template.Template
}

func newWebTemplates() (*webTemplates, error) {
	pages := make(map[string]*template.Template)

	funcMap := template.FuncMap{
		"add":            func(a, b int) int { return a + b },
		"sub":            func(a, b int) int { return a - b },
		"shortSHA":       shortSHA,
		"lower":          strings.ToLower,
		"ecosystemClass": func(eco string) string { return "ecosystem-" + strings.ToLower(eco) },
		"formatDate": func(s string) string {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return s
			}
			return t.Format("2006-01-02")
		},
	}

	pageFiles, err := webTemplatesFS.ReadDir("web/templates/pages")
	if err != nil {
		return nil, err
	}

	for _, pageFile := range pageFiles {
		if pageFile.IsDir() {
			continue
		}

		pageName := pageFile.Name()
		pageName = pageName[:len(pageName)-len(filepath.Ext(pageName))]

		tmpl, err := template.New("").Funcs(funcMap).ParseFS(webTemplatesFS,
			"web/templates/layout/*.html",
			"web/templates/components/*.html",
			"web/templates/pages/"+pageFile.Name(),
		)
		if err != nil {
			return nil, err
		}

		pages[pageName] = tmpl
	}

	return &webTemplates{pages: pages}, nil
}

func (t *webTemplates) render(w http.ResponseWriter, page string, data any) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, ok := t.pages[page]
	if !ok {
		return http.ErrAbortHandler
	}

	return tmpl.ExecuteTemplate(w, "base", data)
}

func webStaticHandler() http.Handler {
	sub, _ := fs.Sub(webStaticFiles, "web/static")
	return http.FileServer(http.FS(sub))
}
