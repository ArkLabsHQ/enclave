package main

import (
	"fmt"
	"net/http"
	"os"

	// commit2: uncomment the next line and add to go.mod
	// "golang.org/x/text/language"
)

func main() {
	port := os.Getenv("ENCLAVE_APP_PORT")
	if port == "" {
		port = "7074"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"ok"}`)
	})

	fmt.Printf("listening on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
