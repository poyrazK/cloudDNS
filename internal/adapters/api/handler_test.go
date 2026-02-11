package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockDNSService struct {
	zones   []domain.Zone
	records []domain.Record
}

func (m *mockDNSService) CreateZone(ctx context.Context, zone *domain.Zone) error {
	zone.ID = "zone-123"
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockDNSService) CreateRecord(ctx context.Context, record *domain.Record) error {
	record.ID = "rec-456"
	m.records = append(m.records, *record)
	return nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	return nil, nil
}

func (m *mockDNSService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	return m.zones, nil
}

func TestCreateZone(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	
	zoneReq := domain.Zone{Name: "test.com", TenantID: "t1"}
	body, _ := json.Marshal(zoneReq)
	
	req := httptest.NewRequest("POST", "/zones", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	
	handler.CreateZone(w, req)
	
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
	
	var resp domain.Zone
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.ID != "zone-123" {
		t.Errorf("Expected ID zone-123, got %s", resp.ID)
	}
}

func TestListZones(t *testing.T) {
	svc := &mockDNSService{
		zones: []domain.Zone{{ID: "1", Name: "z1.com", TenantID: "t1"}},
	}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/zones?tenant_id=t1", nil)
	w := httptest.NewRecorder()
	
	handler.ListZones(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	var resp []domain.Zone
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 1 {
		t.Errorf("Expected 1 zone, got %d", len(resp))
	}
}

func TestCreateRecord(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	
	recordReq := domain.Record{Name: "www", Type: domain.TypeA, Content: "1.2.3.4"}
	body, _ := json.Marshal(recordReq)
	
	// Note: r.PathValue("id") only works when routed through ServeMux in Go 1.22+
	// For raw handler tests, we might need to manually set context if needed, 
	// but our handler currently just reads the ID from the path.
	req := httptest.NewRequest("POST", "/zones/zone-123/records", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	
	handler.CreateRecord(w, req)
	
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}
