#!/bin/bash
# =============================================================================
# cloudDNS — GCP Infrastructure Setup Script
# Region: europe-west3 (Frankfurt)
# =============================================================================
# Usage:
#   1. Set GCP_PROJECT below to your project ID
#   2. Run: chmod +x infra/setup.sh && ./infra/setup.sh
#
# This script is idempotent — safe to run multiple times.
# Free tier friendly: ~$45/mo against your $300/90-day credit.
# =============================================================================

set -euo pipefail

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
GCP_PROJECT="${GCP_PROJECT:-your-gcp-project-id}"
GCP_REGION="europe-west3"
GCP_ZONE="europe-west3-a"

DB_INSTANCE="clouddns-db"
DB_NAME="clouddns"
DB_USER="clouddns-user"
# Password is prompted at runtime — never stored in this file
if [ -z "${DB_PASSWORD:-}" ]; then
  read -rsp "Enter a strong database password: " DB_PASSWORD
  echo ""
fi

REDIS_INSTANCE="clouddns-cache"
STATIC_IP_NAME="clouddns-ip"
ARTIFACT_REPO="clouddns"
# ─────────────────────────────────────────────────────────────────────────────

echo "🔧 Configuring gcloud for project: $GCP_PROJECT"
gcloud config set project "$GCP_PROJECT"
gcloud config set compute/region "$GCP_REGION"
gcloud config set compute/zone "$GCP_ZONE"

# ─── Step 1: Enable APIs ────────────────────────────────────────────────────
echo "📡 Enabling required GCP APIs..."
gcloud services enable \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  compute.googleapis.com \
  artifactregistry.googleapis.com \
  container.googleapis.com

# ─── Step 2: Cloud SQL (PostgreSQL 16) ──────────────────────────────────────
echo "🐘 Creating Cloud SQL instance..."
if gcloud sql instances describe "$DB_INSTANCE" &>/dev/null; then
  echo "  ✅ Cloud SQL instance '$DB_INSTANCE' already exists, skipping."
else
  gcloud sql instances create "$DB_INSTANCE" \
    --database-version=POSTGRES_16 \
    --tier=db-f1-micro \
    --region="$GCP_REGION" \
    --storage-type=SSD \
    --storage-size=10GB \
    --storage-auto-increase
  echo "  ✅ Cloud SQL instance created."
fi

echo "🗄️  Creating database '$DB_NAME'..."
gcloud sql databases create "$DB_NAME" --instance="$DB_INSTANCE" 2>/dev/null || \
  echo "  ✅ Database '$DB_NAME' already exists."

if gcloud sql users list --instance="$DB_INSTANCE" --project="$GCP_PROJECT" | grep -q "$DB_USER"; then
    echo "👤 User $DB_USER already exists, updating password..."
    gcloud sql users set-password "$DB_USER" "%" \
      --instance="$DB_INSTANCE" \
      --password="$DB_PASSWORD" \
      --project="$GCP_PROJECT"
else
    echo "👤 Creating cloudDNS database user..."
    gcloud sql users create "$DB_USER" "%" \
      --instance="$DB_INSTANCE" \
      --password="$DB_PASSWORD" \
      --project="$GCP_PROJECT"
fi
echo "  ✅ User '$DB_USER' configured."

# ─── Step 3: Memorystore (Redis 7.2) ────────────────────────────────────────
echo "🔴 Creating Memorystore Redis instance..."
if gcloud redis instances describe "$REDIS_INSTANCE" --region="$GCP_REGION" &>/dev/null; then
  echo "  ✅ Redis instance '$REDIS_INSTANCE' already exists, skipping."
else
  gcloud redis instances create "$REDIS_INSTANCE" \
    --size=1 \
    --region="$GCP_REGION" \
    --redis-version=redis_7_2 \
    --tier=basic
  echo "  ✅ Redis instance created."
fi

REDIS_HOST=$(gcloud redis instances describe "$REDIS_INSTANCE" \
  --region="$GCP_REGION" \
  --format="value(host)" 2>/dev/null || echo "pending")
echo "  Redis host: $REDIS_HOST"

# ─── Step 4: Static External IP ─────────────────────────────────────────────
echo "🌐 Reserving static external IP..."
if gcloud compute addresses describe "$STATIC_IP_NAME" --region="$GCP_REGION" &>/dev/null; then
  echo "  ✅ Static IP '$STATIC_IP_NAME' already exists."
else
  gcloud compute addresses create "$STATIC_IP_NAME" --region="$GCP_REGION"
  echo "  ✅ Static IP reserved."
fi

STATIC_IP=$(gcloud compute addresses describe "$STATIC_IP_NAME" \
  --region="$GCP_REGION" \
  --format="value(address)")
echo "  Static IP: $STATIC_IP"

# ─── Step 5: Firewall Rules ─────────────────────────────────────────────────
echo "🔥 Creating firewall rules..."

# DNS (UDP + TCP port 53) — open to the world
gcloud compute firewall-rules create allow-dns \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=udp:53,tcp:53 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=clouddns-node \
  --description="Allow DNS queries" 2>/dev/null || \
  echo "  ✅ Firewall rule 'allow-dns' already exists."

# DNS over TLS (TCP port 853) — open to the world
gcloud compute firewall-rules create allow-dot \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:853 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=clouddns-node \
  --description="Allow DNS over TLS" 2>/dev/null || \
  echo "  ✅ Firewall rule 'allow-dot' already exists."

# Management API (TCP port 8080) — restricted!
# Replace 0.0.0.0/0 with your own IP for security
# 4. Create Firewall rule for Management API
if [ -z "$MGMT_API_SOURCE_RANGE" ]; then
    echo "❌ MGMT_API_SOURCE_RANGE is not set. For security, please provide an explicit CIDR (e.g. your IP/32)."
    exit 1
fi

if gcloud compute firewall-rules describe allow-clouddns-api &>/dev/null; then
  echo "  ✅ Firewall rule 'allow-clouddns-api' already exists."
else
  gcloud compute firewall-rules create allow-clouddns-api \
    --project="$GCP_PROJECT" \
    --network=default \
    --allow=tcp:8080 \
    --source-ranges="$MGMT_API_SOURCE_RANGE" \
    --target-tags=clouddns-node \
    --description="Allow management API traffic (restricted to MGMT_API_SOURCE_RANGE)"
  echo "  ✅ Firewall rule 'allow-clouddns-api' created."
fi

# ─── Step 6: Artifact Registry ──────────────────────────────────────────────
echo "📦 Creating Artifact Registry repository..."
if gcloud artifacts repositories describe "$ARTIFACT_REPO" \
  --location="$GCP_REGION" &>/dev/null; then
  echo "  ✅ Repository '$ARTIFACT_REPO' already exists."
else
  gcloud artifacts repositories create "$ARTIFACT_REPO" \
    --repository-format=docker \
    --location="$GCP_REGION" \
    --description="cloudDNS container images"
  echo "  ✅ Repository created."
fi

# ─── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  ✅ GCP Infrastructure Setup Complete!"
echo "=============================================="
echo ""
echo "  Region:      $GCP_REGION (Frankfurt)"
echo "  Cloud SQL:   $DB_INSTANCE ($DB_NAME)"
echo "  Redis:       $REDIS_HOST"
echo "  Static IP:   $STATIC_IP"
echo "  Registry:    ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${ARTIFACT_REPO}"
echo ""
echo "  Next steps:"
echo "    1. Initialize the DB schema via Cloud SQL Proxy:"
echo "       cloud-sql-proxy ${GCP_PROJECT}:${GCP_REGION}:${DB_INSTANCE} --port=15432"
echo "       psql \"postgresql://${DB_USER}:PASSWORD@localhost:15432/${DB_NAME}\" -f internal/adapters/repository/schema.sql"
echo ""
echo "    2. Push the Docker image:"
echo "       gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev"
echo "       docker tag clouddns:latest ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${ARTIFACT_REPO}/clouddns:latest"
echo "       docker push ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${ARTIFACT_REPO}/clouddns:latest"
echo ""
echo "    3. Deploy to GKE (Phase 3)"
echo "=============================================="
