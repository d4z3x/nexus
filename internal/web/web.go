package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed frontend
var frontendFS embed.FS

func Handler() http.Handler {
	sub, _ := fs.Sub(frontendFS, "frontend")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "" {
			data, err := fs.ReadFile(sub, "index.html")
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}

		http.FileServer(http.FS(sub)).ServeHTTP(w, r)
	})
}
