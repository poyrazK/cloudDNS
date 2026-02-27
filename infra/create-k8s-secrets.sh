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

# Configurable namespace
NAMESPACE="${NAMESPACE:-default}"
echo "Using namespace: $NAMESPACE"

# 2. Inject into Kubernetes
# We use --dry-run=client -o yaml | kubectl apply to avoid "already exists" errors
kubectl create secret generic clouddns-secrets \
  --from-literal=database-url="$DB_URL" \
  --namespace="$NAMESPACE" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Kubernetes secret 'clouddns-secrets' created/updated successfully!"
echo ""
echo "You can now run: kubectl apply -f infra/k8s/"
