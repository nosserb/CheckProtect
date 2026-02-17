package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Chemin vers le dossier du portfolio
	portfolioPath := "../style"

	// Servir les fichiers statiques
	fs := http.FileServer(http.Dir(portfolioPath))
	http.Handle("/", fs)

	// Configuration et démarrage du serveur
	port := "2525"
	fmt.Printf("Serveur démarré sur http://localhost:%s\n", port)
	fmt.Printf("Serveur le portfolio depuis: %s\n", portfolioPath)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
