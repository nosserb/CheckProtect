package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const phishStatsBaseURL = "https://api.phishstats.info/api/phishing"

func phishStatsProxyHandler(client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
		if host == "" {
			http.Error(w, `{"error":"missing host"}`, http.StatusBadRequest)
			return
		}

		host = strings.TrimPrefix(host, "www.")
		whereClause := fmt.Sprintf("(url,like,%s)", host)

		targetURL := phishStatsBaseURL + "?_where=" + url.QueryEscape(whereClause) + "&_sort=-date&_size=20"
		resp, err := client.Get(targetURL)
		if err != nil {
			http.Error(w, `{"error":"upstream unavailable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, `{"error":"cannot read upstream response"}`, http.StatusBadGateway)
			return
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":           "upstream error",
				"upstream_status": resp.StatusCode,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func main() {
	// Chemin vers le dossier du portfolio
	CheckProtectPath := ".."

	client := &http.Client{Timeout: 10 * time.Second}
	http.HandleFunc("/api/phishstats", phishStatsProxyHandler(client))

	// Servir les fichiers statiques
	fs := http.FileServer(http.Dir(CheckProtectPath))
	http.Handle("/", fs)

	// Configuration et démarrage du serveur
	port := os.Getenv("PORT")
	if strings.TrimSpace(port) == "" {
		port = "2525"
	}
	fmt.Printf("Serveur démarré sur http://localhost:%s\n", port)
	fmt.Printf("Serveur CheckProtect depuis: %s\n", CheckProtectPath)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
