package main

import (
	"example.org/kdbx-coordinator/internal/coordinator"
	"log"
	"net/http"
	"os"
)

func main() {
	key := os.Getenv("KDBX_COORDINATOR_TOKEN")
	dir := os.Getenv("KDBX_COORDINATOR_DIR")
	if dir == "" {
		dir = "./encrypted-databases"
	}
	server, err := coordinator.New(dir, key)
	if err != nil {
		log.Fatal(err)
	}
	// Bind to loopback ONLY. TLS must be provided by a verified HTTPS reverse proxy.
	log.Println("listening on 127.0.0.1:8765, TLS required at reverse proxy")
	log.Fatal(http.ListenAndServe("127.0.0.1:8765", server))
}
