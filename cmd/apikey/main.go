package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	repo := repository.NewPostgresRepository(db)
	if err := run(os.Args, os.Stdout, repo); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, repo ports.DNSRepository) error {
	createCmd := flag.NewFlagSet("create", flag.ContinueOnError)
	createCmd.SetOutput(io.Discard)
	tenantID := createCmd.String("tenant", "default-tenant", "Tenant ID")
	role := createCmd.String("role", "admin", "Role (admin or reader)")
	name := createCmd.String("name", "generic-key", "Description of the key")
	days := createCmd.Int("days", 365, "Validity in days")

	listCmd := flag.NewFlagSet("list", flag.ContinueOnError)
	listCmd.SetOutput(io.Discard)
	listTenant := listCmd.String("tenant", "default-tenant", "Tenant ID")

	revokeCmd := flag.NewFlagSet("revoke", flag.ContinueOnError)
	revokeCmd.SetOutput(io.Discard)
	revokeID := revokeCmd.String("id", "", "API Key UUID to revoke")

	if len(args) < 2 {
		return fmt.Errorf("expected 'create', 'list' or 'revoke' subcommands")
	}

	switch args[1] {
	case "create":
		if err := createCmd.Parse(args[2:]); err != nil {
			return err
		}
		return generateKey(repo, *tenantID, *role, *name, *days, out)
	case "list":
		if err := listCmd.Parse(args[2:]); err != nil {
			return err
		}
		return listKeys(repo, *listTenant, out)
	case "revoke":
		if err := revokeCmd.Parse(args[2:]); err != nil {
			return err
		}
		return revokeKey(repo, *revokeID, out)
	default:
		return fmt.Errorf("unknown subcommand: %s", args[1])
	}
}

func generateKey(repo ports.DNSRepository, tenantID, role, name string, days int, out io.Writer) error {
	rawKey := make([]byte, 16)
	if _, err := rand.Read(rawKey); err != nil {
		return err
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
		return fmt.Errorf("failed to save API key: %w", err)
	}

	_, _ = fmt.Fprintf(out, "API Key Created Successfully!\n")
	_, _ = fmt.Fprintf(out, "---------------------------\n")
	_, _ = fmt.Fprintf(out, "ID:         %s\n", id)
	_, _ = fmt.Fprintf(out, "Tenant:     %s\n", tenantID)
	_, _ = fmt.Fprintf(out, "Role:       %s\n", role)
	_, _ = fmt.Fprintf(out, "Expires:    %v\n", expiresAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "VALUE:      %s\n", keyString)
	_, _ = fmt.Fprintf(out, "---------------------------\n")
	_, _ = fmt.Fprintf(out, "CAUTION: This is the only time the key will be shown.\n")
	return nil
}

func listKeys(repo ports.DNSRepository, tenantID string, out io.Writer) error {
	keys, err := repo.ListAPIKeys(context.Background(), tenantID)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "API Keys for Tenant: %s\n", tenantID)
	_, _ = fmt.Fprintf(out, "%-36s %-15s %-10s %-8s %-6s\n", "ID", "Name", "Role", "Prefix", "Status")
	for _, k := range keys {
		status := "active"
		if !k.Active {
			status = "revoked"
		}
		_, _ = fmt.Fprintf(out, "%-36s %-15s %-10s %-8s %-6s\n", k.ID, k.Name, k.Role, k.KeyPrefix, status)
	}
	return nil
}

func revokeKey(repo ports.DNSRepository, id string, out io.Writer) error {
	if id == "" {
		return fmt.Errorf("ID is required for revocation")
	}
	if err := repo.DeleteAPIKey(context.Background(), id); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "API Key %s revoked (deleted)\n", id)
	return nil
}
