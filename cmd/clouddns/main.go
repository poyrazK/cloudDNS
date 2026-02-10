package main

import (
	"log"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

func main() {
	// Listen on 10053 for development (since 53 requires root)
	srv := server.NewServer("0.0.0.0:10053")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
