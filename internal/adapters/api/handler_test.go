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
	"github.com/poyrazK/cloudDNS/internal/testutil"
)

const (
	testTenantID = "t1"
	zonesPath    = "/zones"
	recordsPath  = "/zones/z1/records"
	status200Err = "Expected status 200, got %d"
	status500Err = "Expected status 500, got %d"
)

type mockDNSService struct {
	zones   []domain.Zone
	records []domain.Record
	err     error
}

func (m *mockDNSService) CreateZone(_ context.Context, zone *domain.Zone) error {
	if m.err != nil {
		return m.err
	}
	zone.ID = "zone-123"
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockDNSService) CreateRecord(_ context.Context, record *domain.Record) error {
	if m.err != nil {
		return m.err
	}
	record.ID = "rec-456"
	m.records = append(m.records, *record)
	return nil
}

func (m *mockDNSService) Resolve(_ context.Context, _ string, _ domain.RecordType, _ string) ([]domain.Record, error) {
	return nil, m.err
}

func (m *mockDNSService) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.zones, nil
}

func (m *mockDNSService) ListRecordsForZone(_ context.Context, _ string) ([]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records, nil
}

func (m *mockDNSService) DeleteZone(_ context.Context, _, _ string) error {
	return m.err
}

func (m *mockDNSService) DeleteRecord(_ context.Context, _, _ string) error {
	return m.err
}

func (m *mockDNSService) ImportZone(_ context.Context, tenantID string, _ io.Reader) (*domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &domain.Zone{ID: "zone-imported", TenantID: tenantID}, nil
}

func (m *mockDNSService) ListAuditLogs(_ context.Context, tenantID string) ([]domain.AuditLog, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []domain.AuditLog{{ID: "123", TenantID: tenantID}}, nil
}

func (m *mockDNSService) HealthCheck(_ context.Context) map[string]error {
	res := make(map[string]error)
	res["postgres"] = m.err
	return res
}

func withTenant(req *http.Request, tenantID string) *http.Request {
	ctx := context.WithValue(req.Context(), CtxTenantID, tenantID)
	return req.WithContext(ctx)
}

// TestRegisterRoutes verifies that API routes are correctly registered.
func TestRegisterRoutes(_ *testing.T) {
	svc := &testutil.MockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	// No error means routes were registered correctly with new Go 1.22 patterns
}

func TestHealthCheck(t *testing.T) {
	svc := &testutil.MockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	svc.On("HealthCheck").Return(map[string]error{"postgres": nil}).Once()

	handler.HealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	expected := `{"details":{"postgres":"OK"},"status":"UP"}` + "\n"
	actual := w.Body.String()
	if actual != expected {
		t.Errorf("Expected body %q, got %q", expected, actual)
	}
}

func TestHealthCheckDegraded(t *testing.T) {
	svc := &testutil.MockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	svc.On("HealthCheck").Return(map[string]error{"postgres": errors.New("db down")}).Once()

	handler.HealthCheck(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503, got %d", w.Code)
	}
}

func TestCreateZoneBadRequest(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer([]byte("invalid json")))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateZone(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCreateZoneInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	zoneReq := domain.Zone{Name: "test.com."}
	body, _ := json.Marshal(zoneReq)
	req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateZone(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestCreateZoneSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	zoneReq := domain.Zone{Name: "test.com.", TenantID: testTenantID}
	body, _ := json.Marshal(zoneReq)

	req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateZone(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}

func TestCreateZoneValidation(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	tests := []struct {
		name    string
		payload string
		want    int
	}{
		{"Valid FQDN", `{"name": "example.com."}`, http.StatusCreated},
		{"Valid Case Insensitive", `{"name": "ExAmPlE.CoM."}`, http.StatusCreated},
		{"Invalid Missing Dot", `{"name": "example.com"}`, http.StatusBadRequest},
		{"Invalid Empty", `{"name": ""}`, http.StatusBadRequest},
		{"Invalid Root Zone", `{"name": "."}`, http.StatusCreated}, // Root is valid if svc handles it
		{"Invalid Characters", `{"name": "invalid_chars.com."}`, http.StatusBadRequest},
		{"Invalid Label Start Hyphen", `{"name": "-invalid.com."}`, http.StatusBadRequest},
		{"Invalid Label End Hyphen", `{"name": "invalid-.com."}`, http.StatusBadRequest},
		{"Invalid Long Label", `{"name": "thislabeliswaytoolongandexceedsthemaximumlengthofsixtythreecharacters.com."}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer([]byte(tt.payload)))
			req = withTenant(req, testTenantID)
			w := httptest.NewRecorder()
			handler.CreateZone(w, req)
			if w.Code != tt.want {
				t.Errorf("CreateZone(%s) status = %d, want %d", tt.name, w.Code, tt.want)
			}
		})
	}
}

func TestListZonesInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", zonesPath, nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListZones(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestListZonesSuccess(t *testing.T) {
	svc := &mockDNSService{
		zones: []domain.Zone{{ID: "1", Name: "z1.com", TenantID: testTenantID}},
	}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", zonesPath, nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListZones(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(status200Err, w.Code)
	}
}

func TestCreateRecordBadRequest(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer([]byte("!!")))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateRecord(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestCreateRecordInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	rec := domain.Record{Name: "www"}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateRecord(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestListRecordsForZoneSuccess(t *testing.T) {
	svc := &mockDNSService{
		records: []domain.Record{{ID: "r1", Name: "www"}},
	}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", recordsPath, nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListRecordsForZone(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(status200Err, w.Code)
	}
}

func TestListRecordsForZoneInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", recordsPath, nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListRecordsForZone(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestDeleteZoneInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("DELETE", "/zones/z1", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteZone(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestDeleteRecordInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("DELETE", "/zones/z1/records/r1", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteRecord(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestMetrics(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.Metrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(status200Err, w.Code)
	}
}
