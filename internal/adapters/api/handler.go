package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

// APIHandler handles HTTP requests for zone and record management.
type APIHandler struct {
	svc ports.DNSService
}

// NewAPIHandler creates and returns a new APIHandler instance.
func NewAPIHandler(svc ports.DNSService) *APIHandler {
	return &APIHandler{svc: svc}
}

// RegisterRoutes registers the API routes with the provided ServeMux.
func (h *APIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("POST /zones", h.CreateZone)
	mux.HandleFunc("GET /zones", h.ListZones)
	mux.HandleFunc("GET /zones/{id}/records", h.ListRecordsForZone)
	mux.HandleFunc("DELETE /zones/{id}", h.DeleteZone)
	mux.HandleFunc("POST /zones/{id}/records", h.CreateRecord)
	mux.HandleFunc("DELETE /zones/{zone_id}/records/{id}", h.DeleteRecord)
	mux.HandleFunc("GET /audit-logs", h.ListAuditLogs)
}

// HealthCheck handles health check requests.
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.HealthCheck(r.Context()); err != nil {
		http.Error(w, "Degraded: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"UP"}`)); err != nil {
		log.Printf("failed to write health check response: %v", err)
	}
}

// ListAuditLogs retrieves audit entries for a specific tenant via the management API.
func (h *APIHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "default-tenant"
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

	// In a real app, we would get TenantID from Auth context
	if zone.TenantID == "" {
		zone.TenantID = "default-tenant"
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

func (h *APIHandler) ListZones(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "default-tenant"
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
	
	records, err := h.svc.ListRecordsForZone(r.Context(), zoneID)
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
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "default-tenant"
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

	if err := h.svc.DeleteRecord(r.Context(), id, zoneID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
