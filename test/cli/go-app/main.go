package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func main() {
	port := os.Getenv("ENCLAVE_APP_PORT")
	if port == "" {
		port = "7074"
	}

	title := cases.Title(language.English).String("hello enclave")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"ok","message":"%s"}`, title)
	})

	fmt.Printf("listening on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
