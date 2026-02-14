package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockDNSService struct {
	zones   []domain.Zone
	records []domain.Record
	err     error
}

func (m *mockDNSService) CreateZone(ctx context.Context, zone *domain.Zone) error {
	if m.err != nil {
		return m.err
	}
	zone.ID = "zone-123"
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockDNSService) CreateRecord(ctx context.Context, record *domain.Record) error {
	if m.err != nil {
		return m.err
	}
	record.ID = "rec-456"
	m.records = append(m.records, *record)
	return nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	return nil, m.err
}

func (m *mockDNSService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.zones, nil
}

func (m *mockDNSService) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records, nil
}

func (m *mockDNSService) DeleteZone(ctx context.Context, id, tenantID string) error {
	return m.err
}

func (m *mockDNSService) DeleteRecord(ctx context.Context, id, zoneID string) error {
	return m.err
}

func (m *mockDNSService) ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &domain.Zone{ID: "zone-imported", TenantID: tenantID}, nil
}

func (m *mockDNSService) HealthCheck(ctx context.Context) error {
	return m.err
}

func TestRegisterRoutes(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	// No error means routes were registered correctly with new Go 1.22 patterns
}

func TestHealthCheck(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	handler.HealthCheck(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	expected := `{"status":"UP"}`
	if w.Body.String() != expected {
		t.Errorf("Expected body %s, got %s", expected, w.Body.String())
	}
}

func TestHealthCheck_Degraded(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db down")}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	handler.HealthCheck(w, req)
	
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}
}

func TestCreateZone_BadRequest(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("POST", "/zones", bytes.NewBuffer([]byte("invalid json")))
	w := httptest.NewRecorder()
	
	handler.CreateZone(w, req)
	
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCreateZone_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	handler := NewAPIHandler(svc)
	
	zoneReq := domain.Zone{Name: "test.com"}
	body, _ := json.Marshal(zoneReq)
	req := httptest.NewRequest("POST", "/zones", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	
	handler.CreateZone(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
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
}

func TestListZones_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/zones", nil)
	w := httptest.NewRecorder()
	
	handler.ListZones(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
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
}

func TestCreateRecord_BadRequest(t *testing.T) {
	svc := &mockDNSService{}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("POST", "/zones/z1/records", bytes.NewBuffer([]byte("!!")))
	w := httptest.NewRecorder()
	
	handler.CreateRecord(w, req)
	
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCreateRecord_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	handler := NewAPIHandler(svc)
	
	rec := domain.Record{Name: "www"}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("POST", "/zones/z1/records", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	
	handler.CreateRecord(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestListRecordsForZone(t *testing.T) {
	svc := &mockDNSService{
		records: []domain.Record{{ID: "r1", Name: "www"}},
	}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/zones/z1/records", nil)
	w := httptest.NewRecorder()
	
	handler.ListRecordsForZone(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestListRecordsForZone_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("GET", "/zones/z1/records", nil)
	w := httptest.NewRecorder()
	
	handler.ListRecordsForZone(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDeleteZone_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("DELETE", "/zones/z1", nil)
	w := httptest.NewRecorder()
	
	handler.DeleteZone(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDeleteRecord_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	handler := NewAPIHandler(svc)
	
	req := httptest.NewRequest("DELETE", "/zones/z1/records/r1", nil)
	w := httptest.NewRecorder()
	
	handler.DeleteRecord(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}
