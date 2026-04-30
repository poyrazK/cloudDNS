// Package api provides HTTP handlers for the cloudDNS REST API.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxBodySize = 1 << 20 // 1MB

// validateContentType checks if Content-Type is application/json.
// Returns true if empty (backward compat) or exactly "application/json".
func validateContentType(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return true
	}
	// Parse media type: split on ";," then trim and lowercase for exact comparison
	mediaType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if strings.ToLower(mediaType) == "application/json" {
		return true
	}
	return false
}

// Handler handles HTTP requests for zone and record management.
type Handler struct {
	svc          ports.DNSService
	repo         ports.DNSRepository
	multiLimiter *multiLimiter
	logger       *slog.Logger
}

// New creates and returns a new Handler instance.
func New(svc ports.DNSService, repo ports.DNSRepository, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:          svc,
		repo:         repo,
		multiLimiter: newMultiLimiter(),
		logger:       logger,
	}
}

// RegisterRoutes registers the API routes with the provided ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// CORS middleware
	corsConfig := DefaultCORSConfig()
	cors := CORSMiddleware(corsConfig)

	// Public Routes
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /metrics", h.Metrics)

	// Middleware
	auth := AuthMiddleware(h.repo)
	admin := RequireRole(domain.RoleAdmin)

	// Rate limiters by category
	rateLimitRead := RateLimitMiddleware(h.multiLimiter, categoryRead)
	rateLimitWrite := RateLimitMiddleware(h.multiLimiter, categoryWrite)
	rateLimitDeleteZone := RateLimitMiddleware(h.multiLimiter, categoryDeleteZone)
	rateLimitDeleteRecord := RateLimitMiddleware(h.multiLimiter, categoryDeleteRecord)

	// Protected Routes (scoped by tenant_id from auth key)
	// Read operations - rate limited
	mux.Handle("GET /zones", cors(auth(rateLimitRead(http.HandlerFunc(h.ListZones)))))
	mux.Handle("GET /zones/{id}/records", cors(auth(rateLimitRead(http.HandlerFunc(h.ListRecordsForZone)))))
	mux.Handle("GET /audit-logs", cors(auth(rateLimitRead(http.HandlerFunc(h.ListAuditLogs)))))

	// Write operations - rate limited per tenant
	mux.Handle("POST /zones", cors(auth(rateLimitWrite(admin(http.HandlerFunc(h.CreateZone))))))
	mux.Handle("POST /zones/{id}/records", cors(auth(rateLimitWrite(admin(http.HandlerFunc(h.CreateRecord))))))

	// Delete operations - more restrictive
	mux.Handle("DELETE /zones/{id}", cors(auth(rateLimitDeleteZone(admin(http.HandlerFunc(h.DeleteZone))))))
	mux.Handle("DELETE /zones/{zone_id}/records/{id}", cors(auth(rateLimitDeleteRecord(admin(http.HandlerFunc(h.DeleteRecord))))))
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
			h.logger.Warn("health check failed", "check", name, "error", checkErr)
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
		h.logger.Error("failed to encode health check response", "error", err)
	}
}

// ListAuditLogs retrieves audit entries for a specific tenant via the management API.
func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("ListAuditLogs: missing or invalid tenant ID in context")
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
		h.logger.Error("failed to encode audit logs response", "error", err)
	}
}

// CreateZone handles POST /zones requests.
func (h *Handler) CreateZone(w http.ResponseWriter, r *http.Request) {
	var zone domain.Zone
	if !validateContentType(r) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&zone); err != nil {
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
		h.logger.Warn("CreateZone: missing or invalid tenant ID in context")
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
		h.logger.Error("failed to encode zone response", "error", err)
	}
}

// ListZones handles GET /zones requests.
func (h *Handler) ListZones(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("ListZones: missing or invalid tenant ID in context")
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
		h.logger.Error("failed to encode zones response", "error", err)
	}
}

// ListRecordsForZone handles GET /zones/{id}/records requests.
func (h *Handler) ListRecordsForZone(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("ListRecordsForZone: missing or invalid tenant ID in context")
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
		h.logger.Error("failed to encode records response", "error", err)
	}
}

// CreateRecord handles POST /zones/{id}/records requests.
func (h *Handler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")
	var record domain.Record
	if !validateContentType(r) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&record); err != nil {
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
		h.logger.Warn("CreateRecord: missing or invalid tenant ID in context")
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
		h.logger.Error("failed to encode record response", "error", err)
	}
}

// DeleteZone handles DELETE /zones/{id} requests.
func (h *Handler) DeleteZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("DeleteZone: missing or invalid tenant ID in context")
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
		h.logger.Warn("DeleteRecord: missing or invalid tenant ID in context")
		http.Error(w, "Unauthorized: missing tenant context", http.StatusUnauthorized)
		return
	}

	if err := h.svc.DeleteRecord(r.Context(), id, zoneID, tenantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
