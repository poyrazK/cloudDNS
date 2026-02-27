package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// APIHandler handles HTTP requests for zone and record management.
type APIHandler struct {
	svc  ports.DNSService
	repo ports.DNSRepository
}

// NewAPIHandler creates and returns a new APIHandler instance.
func NewAPIHandler(svc ports.DNSService, repo ports.DNSRepository) *APIHandler {
	return &APIHandler{svc: svc, repo: repo}
}

// RegisterRoutes registers the API routes with the provided ServeMux.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Public Routes
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /metrics", h.Metrics)

	// Middleware
	auth := AuthMiddleware(h.repo)
	admin := RequireRole(domain.RoleAdmin)

	// Protected Routes (scoped by tenant_id from auth key)
	mux.Handle("POST /zones", auth(admin(http.HandlerFunc(h.CreateZone))))
	mux.Handle("GET /zones", auth(http.HandlerFunc(h.ListZones)))
	mux.Handle("GET /zones/{id}/records", auth(http.HandlerFunc(h.ListRecordsForZone)))
	mux.Handle("DELETE /zones/{id}", auth(admin(http.HandlerFunc(h.DeleteZone))))
	mux.Handle("POST /zones/{id}/records", auth(admin(http.HandlerFunc(h.CreateRecord))))
	mux.Handle("DELETE /zones/{zone_id}/records/{id}", auth(admin(http.HandlerFunc(h.DeleteRecord))))
	mux.Handle("GET /audit-logs", auth(http.HandlerFunc(h.ListAuditLogs)))
}

// Metrics handles Prometheus metrics scraping requests.
func (h *APIHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

// HealthCheck handles health check requests.
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := "UP"
	details := make(map[string]string)
	checks := h.svc.HealthCheck(r.Context())

	for name, checkErr := range checks {
		if checkErr != nil {
			status = "DEGRADED"
			details[name] = checkErr.Error()
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
func (h *APIHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
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

func (h *APIHandler) CreateZone(w http.ResponseWriter, r *http.Request) {
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

func (h *APIHandler) ListZones(w http.ResponseWriter, r *http.Request) {
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

func (h *APIHandler) ListRecordsForZone(w http.ResponseWriter, r *http.Request) {
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

func (h *APIHandler) CreateRecord(w http.ResponseWriter, r *http.Request) {
	zoneID := r.PathValue("id")
	var record domain.Record
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if record.Type == domain.TypeSRV {
		if err := domain.ValidateSRVFields(record.Priority, record.Weight, record.Port, record.Content); err != nil {
			http.Error(w, "Invalid SRV record: "+err.Error(), http.StatusBadRequest)
			return
		}
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

func (h *APIHandler) DeleteZone(w http.ResponseWriter, r *http.Request) {
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

func (h *APIHandler) DeleteRecord(w http.ResponseWriter, r *http.Request) {
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
