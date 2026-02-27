package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func main() {
	createCmd := flag.NewFlagSet("create", flag.ExitOnError)
	tenantID := createCmd.String("tenant", "default-tenant", "Tenant ID")
	role := createCmd.String("role", "admin", "Role (admin or reader)")
	name := createCmd.String("name", "generic-key", "Description of the key")
	days := createCmd.Int("days", 365, "Validity in days")

	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	listTenant := listCmd.String("tenant", "default-tenant", "Tenant ID")

	revokeCmd := flag.NewFlagSet("revoke", flag.ExitOnError)
	revokeID := revokeCmd.String("id", "", "API Key UUID to revoke")

	if len(os.Args) < 2 {
		fmt.Println("expected 'create', 'list' or 'revoke' subcommands")
		os.Exit(1)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("failed to close database: %v", err)
		}
	}()

	repo := repository.NewPostgresRepository(db)

	switch os.Args[1] {
	case "create":
		if err := createCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("failed to parse create commands: %v", err)
		}
		generateKey(repo, *tenantID, *role, *name, *days)
	case "list":
		if err := listCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("failed to parse list commands: %v", err)
		}
		listKeys(repo, *listTenant)
	case "revoke":
		if err := revokeCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("failed to parse revoke commands: %v", err)
		}
		revokeKey(repo, *revokeID)
	default:
		fmt.Println("expected 'create', 'list' or 'revoke' subcommands")
		os.Exit(1)
	}
}

func generateKey(repo *repository.PostgresRepository, tenantID, role, name string, days int) {
	rawKey := make([]byte, 16)
	if _, err := rand.Read(rawKey); err != nil {
		log.Fatal(err)
	}
	keyString := "cdns_" + hex.EncodeToString(rawKey)

	hash := sha256.Sum256([]byte(keyString))
	keyHash := hex.EncodeToString(hash[:])

	id := uuid.New().String()
	expiresAt := time.Now().AddDate(0, 0, days)

	apiKey := &domain.APIKey{
		ID:        id,
		TenantID:  tenantID,
		Name:      name,
		KeyHash:   keyHash,
		KeyPrefix: keyString[:8],
		Role:      domain.Role(role),
		Active:    true,
		CreatedAt: time.Now(),
		ExpiresAt: &expiresAt,
	}

	if err := repo.CreateAPIKey(context.Background(), apiKey); err != nil {
		log.Fatalf("failed to save API key: %v", err)
	}

	fmt.Printf("API Key Created Successfully!\n")
	fmt.Printf("---------------------------\n")
	fmt.Printf("ID:         %s\n", id)
	fmt.Printf("Tenant:     %s\n", tenantID)
	fmt.Printf("Role:       %s\n", role)
	fmt.Printf("Expires:    %v\n", expiresAt.Format(time.RFC3339))
	fmt.Printf("VALUE:      %s\n", keyString)
	fmt.Printf("---------------------------\n")
	fmt.Printf("CAUTION: This is the only time the key will be shown.\n")
}

func listKeys(repo *repository.PostgresRepository, tenantID string) {
	keys, err := repo.ListAPIKeys(context.Background(), tenantID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("API Keys for Tenant: %s\n", tenantID)
	fmt.Printf("%-36s %-15s %-10s %-8s %-6s\n", "ID", "Name", "Role", "Prefix", "Status")
	for _, k := range keys {
		status := "active"
		if !k.Active {
			status = "revoked"
		}
		fmt.Printf("%-36s %-15s %-10s %-8s %-6s\n", k.ID, k.Name, k.Role, k.KeyPrefix, status)
	}
}

func revokeKey(repo *repository.PostgresRepository, id string) {
	if id == "" {
		log.Fatal("ID is required for revocation")
	}
	if err := repo.DeleteAPIKey(context.Background(), id); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("API Key %s revoked (deleted)\n", id)
}
