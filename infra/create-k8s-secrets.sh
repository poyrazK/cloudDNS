#!/bin/bash
# =============================================================================
# cloudDNS — Create Kubernetes Secrets from GCP Secret Manager
# =============================================================================
# Run this script BEFORE `kubectl apply -f infra/k8s/`
# It pulls the real secret values from GCP Secret Manager and injects them
# directly into the Kubernetes cluster — the values NEVER touch the filesystem.
# =============================================================================

set -euo pipefail

GCP_PROJECT="${GCP_PROJECT:-thecloud-clouddns}"

echo "🔑 Pulling secrets from GCP Secret Manager..."

DB_URL=$(gcloud secrets versions access latest \
  --secret="clouddns-database-url" \
  --project="$GCP_PROJECT")

echo "✅ Got database-url from Secret Manager"

echo "🚀 Creating Kubernetes secret (values stay in memory, never written to disk)..."
kubectl create secret generic clouddns-secrets \
  --from-literal=database-url="$DB_URL" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Kubernetes secret 'clouddns-secrets' created/updated successfully!"
echo ""
echo "You can now run: kubectl apply -f infra/k8s/"
