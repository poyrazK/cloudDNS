// Package api provides HTTP handlers for the cloudDNS REST API.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxBodySize = 1 << 20 // 1MB

// writeJSONError logs the internal error and writes a safe JSON response to the client.
func (h *Handler) writeJSONError(w http.ResponseWriter, status int, publicMsg string, logErr error) {
	if logErr != nil {
		h.logger.Error("API error", "status", status, "error", logErr)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": publicMsg}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode error response", "error", err)
	}
}

// validateContentType checks if Content-Type is application/json.
// Returns true if empty (backward compat) or exactly "application/json".
func validateContentType(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return true
	}
	// Parse media type: split on ";," then trim and lowercase for exact comparison
	mediaType := strings.TrimSpace(strings.Split(contentType, ";")[0])
	return strings.ToLower(mediaType) == "application/json"
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
	mux.Handle("OPTIONS /zones", cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("OPTIONS /zones/{id}/records", cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("OPTIONS /audit-logs", cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	// Write operations - rate limited per tenant
	mux.Handle("POST /zones", cors(auth(rateLimitWrite(admin(http.HandlerFunc(h.CreateZone))))))
	mux.Handle("POST /zones/{id}/records", cors(auth(rateLimitWrite(RequireRole(domain.RoleAdmin, domain.RoleWriter)(http.HandlerFunc(h.CreateRecord))))))
	mux.Handle("PUT /zones/{zone_id}/records/{id}", cors(auth(rateLimitWrite(RequireRole(domain.RoleAdmin, domain.RoleWriter)(http.HandlerFunc(h.UpdateRecord))))))

	// Delete operations - more restrictive
	mux.Handle("DELETE /zones/{id}", cors(auth(rateLimitDeleteZone(admin(http.HandlerFunc(h.DeleteZone))))))
	mux.Handle("DELETE /zones/{zone_id}/records/{id}", cors(auth(rateLimitDeleteRecord(admin(http.HandlerFunc(h.DeleteRecord))))))
	mux.Handle("OPTIONS /zones/{id}", cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("OPTIONS /zones/{zone_id}/records/{id}", cors(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	// Catalog Zones (RFC 9432) - Admin only
	mux.Handle("POST /catalog-zones", cors(auth(rateLimitWrite(admin(http.HandlerFunc(h.CreateCatalogZone))))))
	mux.Handle("GET /catalog-zones", cors(auth(rateLimitRead(admin(http.HandlerFunc(h.ListCatalogZones))))))
	mux.Handle("GET /catalog-zones/{id}", cors(auth(rateLimitRead(admin(http.HandlerFunc(h.GetCatalogZone))))))
	mux.Handle("DELETE /catalog-zones/{id}", cors(auth(rateLimitDeleteZone(admin(http.HandlerFunc(h.DeleteCatalogZone))))))
	mux.Handle("GET /catalog-zones/{id}/entries", cors(auth(rateLimitRead(admin(http.HandlerFunc(h.ListCatalogEntries))))))
	mux.Handle("POST /catalog-zones/{id}/entries", cors(auth(rateLimitWrite(admin(http.HandlerFunc(h.AddCatalogEntry))))))
	mux.Handle("DELETE /catalog-zones/{id}/entries/{zone_name}", cors(auth(rateLimitDeleteZone(admin(http.HandlerFunc(h.RemoveCatalogEntry))))))
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
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&zone); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := domain.ValidateZoneName(zone.Name); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid zone name", err)
		return
	}

	// Extract TenantID from Auth context
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("CreateZone: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}
	zone.TenantID = tenantID

	if err := domain.ValidateZoneRole(zone.Role, zone.MasterServer); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid zone configuration", err)
		return
	}
	if zone.Role == "" {
		zone.Role = "master"
	}

	if err := h.svc.CreateZone(r.Context(), &zone); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
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
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
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
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&record); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := domain.ValidateRecord(&record); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid record", err)
		return
	}

	record.ZoneID = zoneID

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("CreateRecord: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}
	record.TenantID = tenantID

	if err := h.svc.CreateRecord(r.Context(), &record); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(record); err != nil {
		h.logger.Error("failed to encode record response", "error", err)
	}
}

// UpdateRecord handles PUT /zones/{zone_id}/records/{id} requests.
func (h *Handler) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("zone_id")
	id := r.PathValue("id")

	var record domain.Record
	if !validateContentType(r) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&record); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := domain.ValidateRecord(&record); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid record", err)
		return
	}

	record.ID = id
	record.ZoneID = zoneID

	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("UpdateRecord: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}
	record.TenantID = tenantID

	if err := h.svc.UpdateRecord(r.Context(), &record); err != nil {
		// Return 404 for both "not found" and "tenant mismatch" — prevents
		// writers from probing whether record IDs exist under other tenants.
		h.writeJSONError(w, http.StatusNotFound, "Record not found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
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
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	if err := h.svc.DeleteZone(r.Context(), id, tenantID); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
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
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	if err := h.svc.DeleteRecord(r.Context(), id, zoneID, tenantID); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "An internal error occurred", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CreateCatalogZone handles POST /catalog-zones requests.
func (h *Handler) CreateCatalogZone(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("CreateCatalogZone: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	var req struct {
		ZoneName string `json:"zone_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	if req.ZoneName == "" {
		h.writeJSONError(w, http.StatusBadRequest, "zone_name is required", nil)
		return
	}

	catz, err := h.svc.CreateCatalogZone(r.Context(), tenantID, req.ZoneName)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to create catalog zone", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(catz); err != nil {
		h.logger.Error("failed to encode catalog zone response", "error", err)
	}
}

// ListCatalogZones handles GET /catalog-zones requests.
func (h *Handler) ListCatalogZones(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("ListCatalogZones: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	catalogZones, err := h.svc.ListCatalogZones(r.Context(), tenantID)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to list catalog zones", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(catalogZones); err != nil {
		h.logger.Error("failed to encode catalog zones response", "error", err)
	}
}

// GetCatalogZone handles GET /catalog-zones/{id} requests.
func (h *Handler) GetCatalogZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("GetCatalogZone: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	catz, err := h.svc.GetCatalogZone(r.Context(), id)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to get catalog zone", err)
		return
	}
	if catz == nil {
		h.writeJSONError(w, http.StatusNotFound, "Catalog zone not found", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(catz); err != nil {
		h.logger.Error("failed to encode catalog zone response", "error", err)
	}
}

// DeleteCatalogZone handles DELETE /catalog-zones/{id} requests.
func (h *Handler) DeleteCatalogZone(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("DeleteCatalogZone: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	if err := h.svc.DeleteCatalogZone(r.Context(), id, tenantID); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to delete catalog zone", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListCatalogEntries handles GET /catalog-zones/{id}/entries requests.
func (h *Handler) ListCatalogEntries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID, ok := r.Context().Value(CtxTenantID).(string)
	if !ok || tenantID == "" {
		h.logger.Warn("ListCatalogEntries: missing or invalid tenant ID in context")
		h.writeJSONError(w, http.StatusUnauthorized, "Unauthorized: missing tenant context", nil)
		return
	}

	entries, err := h.svc.ListZoneCatalogEntries(r.Context(), id)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to list catalog entries", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		h.logger.Error("failed to encode catalog entries response", "error", err)
	}
}

// AddCatalogEntry handles POST /catalog-zones/{id}/entries requests.
func (h *Handler) AddCatalogEntry(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		ZoneName string `json:"zone_name"`
		ZoneID   string `json:"zone_id"`
		GroupID  string `json:"group_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	if req.ZoneName == "" || req.ZoneID == "" {
		h.writeJSONError(w, http.StatusBadRequest, "zone_name and zone_id are required", nil)
		return
	}

	if err := h.svc.AddZoneToCatalog(r.Context(), id, req.ZoneName, req.ZoneID, req.GroupID); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to add zone to catalog", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// RemoveCatalogEntry handles DELETE /catalog-zones/{id}/entries/{zone_name} requests.
func (h *Handler) RemoveCatalogEntry(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	zoneName := r.PathValue("zone_name")

	if err := h.svc.RemoveZoneFromCatalog(r.Context(), id, zoneName); err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to remove zone from catalog", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
