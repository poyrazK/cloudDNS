// Package api provides HTTP handlers for the cloudDNS REST API.
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler handles HTTP requests for zone and record management.
type Handler struct {
	svc         ports.DNSService
	repo        ports.DNSRepository
	tenantLimiter *tenantLimiter
}

// New creates and returns a new Handler instance.
func New(svc ports.DNSService, repo ports.DNSRepository) *Handler {
	return &Handler{
		svc:          svc,
		repo:         repo,
		tenantLimiter: NewTenantLimiter(100, 200, 100000), // 100 writes/sec, burst 200, max 100k tenants
	}
}

// RegisterRoutes registers the API routes with the provided ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public Routes
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /metrics", h.Metrics)

	// Middleware
	auth := AuthMiddleware(h.repo)
	admin := RequireRole(domain.RoleAdmin)
	rateLimit := RateLimitMiddleware(h.tenantLimiter)

	// Protected Routes (scoped by tenant_id from auth key)
	// Write operations are rate-limited per tenant
	mux.Handle("POST /zones", auth(rateLimit(admin(http.HandlerFunc(h.CreateZone)))))
	mux.Handle("GET /zones", auth(http.HandlerFunc(h.ListZones)))
	mux.Handle("GET /zones/{id}/records", auth(http.HandlerFunc(h.ListRecordsForZone)))
	mux.Handle("DELETE /zones/{id}", auth(rateLimit(admin(http.HandlerFunc(h.DeleteZone)))))
	mux.Handle("POST /zones/{id}/records", auth(rateLimit(admin(http.HandlerFunc(h.CreateRecord)))))
	mux.Handle("DELETE /zones/{zone_id}/records/{id}", auth(rateLimit(admin(http.HandlerFunc(h.DeleteRecord)))))
	mux.Handle("GET /audit-logs", auth(http.HandlerFunc(h.ListAuditLogs)))
}

// Metrics handles Prometheus metrics scraping requests.
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

// HealthCheck handles health check requests.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := "UP"
	details := make(map[string]string)
	checks := h.svc.HealthCheck(r.Context())

	for name, checkErr := range checks {
		if checkErr != nil {
			status = "DEGRADED"
			details[name] = checkErr.Error()
			log.Printf("Health check failed: %s: %v", name, checkErr)
		} else {
			details[name] = "OK"
		}
	}

	resp := map[string]interface{}{
		"status":  status,
		"details": details,
	}

	w.Header().Set("Content-Type", "application/json")
	if status == "DEGRADED" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode health check response: %v", err)
	}
}

// ListAuditLogs retrieves audit entries for a specific tenant via the management API.
func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("ListAuditLogs: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	logs, err := h.svc.ListAuditLogs(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		log.Printf("failed to encode audit logs response: %v", err)
	}
}

// CreateZone handles POST /zones requests.
func (h *Handler) CreateZone(w http.ResponseWriter, r *http.Request) {
	var zone domain.Zone
	if err := json.NewDecoder(r.Body).Decode(&zone); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := domain.ValidateZoneName(zone.Name); err != nil {
		http.Error(w, "Invalid zone name: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract TenantID from Auth context
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("CreateZone: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}
	zone.TenantID = tenantID

	if err := domain.ValidateZoneRole(zone.Role, zone.MasterServer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if zone.Role == "" {
		zone.Role = "master"
	}

	if err := h.svc.CreateZone(r.Context(), &zone); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(zone); err != nil {
		log.Printf("failed to encode zone response: %v", err)
	}
}

// ListZones handles GET /zones requests.
func (h *Handler) ListZones(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("ListZones: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	zones, err := h.svc.ListZones(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(zones); err != nil {
		log.Printf("failed to encode zones response: %v", err)
	}
}

// ListRecordsForZone handles GET /zones/{id}/records requests.
func (h *Handler) ListRecordsForZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("ListRecordsForZone: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	records, err := h.svc.ListRecordsForZone(r.Context(), zoneID, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(records); err != nil {
		log.Printf("failed to encode records response: %v", err)
	}
}

// CreateRecord handles POST /zones/{id}/records requests.
func (h *Handler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")
	var record domain.Record
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := domain.ValidateRecord(&record); err != nil {
		http.Error(w, "Invalid record: "+err.Error(), http.StatusBadRequest)
		return
	}

	record.ZoneID = zoneID

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("CreateRecord: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}
	record.TenantID = tenantID

	if err := h.svc.CreateRecord(r.Context(), &record); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(record); err != nil {
		log.Printf("failed to encode record response: %v", err)
	}
}

// DeleteZone handles DELETE /zones/{id} requests.
func (h *Handler) DeleteZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("DeleteZone: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	if err := h.svc.DeleteZone(r.Context(), id, tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteRecord handles DELETE /zones/{zone_id}/records/{id} requests.
func (h *Handler) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	id := r.PathValue("id")

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		log.Printf("DeleteRecord: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	if err := h.svc.DeleteRecord(r.Context(), id, zoneID, tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
