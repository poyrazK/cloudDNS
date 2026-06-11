package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/testutil"
	"github.com/stretchr/testify/mock"
)

const (
	testTenantID = "t1"
	zonesPath    = "/zones"
	recordsPath  = "/zones/z1/records"
	status200Err = "Expected status 200, got %d"
	status500Err = "Expected status 500, got %d"
)

type mockDNSService struct {
	zones          []domain.Zone
	records        []domain.Record
	catalogs       []domain.CatalogZone
	catalogEntries []domain.ZoneCatalogEntry
	err            error
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

func (m *mockDNSService) ListRecordsForZone(_ context.Context, _, _ string) ([]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.records, nil
}

func (m *mockDNSService) DeleteZone(_ context.Context, _, _ string) error {
	return m.err
}

func (m *mockDNSService) DeleteRecord(_ context.Context, _, _, _ string) error {
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

func (m *mockDNSService) GetRecordsToProbe(_ context.Context) ([]domain.Record, error) {
	return nil, m.err
}

func (m *mockDNSService) GetRecordsToProbeStreaming(_ context.Context) (ports.RecordIterator, error) {
	return nil, m.err
}

func (m *mockDNSService) UpdateRecordHealth(_ context.Context, _ string, _ domain.HealthStatus, _ string) error {
	return m.err
}

func (m *mockDNSService) UpdateRecord(_ context.Context, record *domain.Record) error {
	if m.err != nil {
		return m.err
	}
	record.ID = "rec-updated"
	return nil
}

func (m *mockDNSService) HealthCheck(_ context.Context) map[string]error {
	res := make(map[string]error)
	res["postgres"] = m.err
	return res
}

func (m *mockDNSService) CreateCatalogZone(_ context.Context, _, _ string) (*domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	catz := &domain.CatalogZone{ID: "catz-new", TenantID: "t1", ZoneName: "catalog.example.com.", Version: "1", Serial: 1}
	m.catalogs = append(m.catalogs, *catz)
	return catz, nil
}
func (m *mockDNSService) GetCatalogZone(_ context.Context, id string, _ string) (*domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, c := range m.catalogs {
		if c.ID == id {
			return &c, nil
		}
	}
	return nil, nil
}
func (m *mockDNSService) ListCatalogZones(_ context.Context, _ string) ([]domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.catalogs, nil
}
func (m *mockDNSService) DeleteCatalogZone(_ context.Context, _, _ string) error { return m.err }
func (m *mockDNSService) AddZoneToCatalog(_ context.Context, _, _, _, _, _ string) error { return m.err }
func (m *mockDNSService) RemoveZoneFromCatalog(_ context.Context, _, _, _ string) error { return m.err }
func (m *mockDNSService) ListZoneCatalogEntries(_ context.Context, _, _ string) ([]domain.ZoneCatalogEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.catalogEntries, nil
}
func (m *mockDNSService) PollCatalogZone(_ context.Context, _, _ string) ([]domain.ZoneCatalogEntry, error) { return nil, nil }
func (m *mockDNSService) SyncZonesFromCatalog(_ context.Context, _, _ string) error { return nil }

func withTenant(req *http.Request, tenantID string) *http.Request {
	ctx := context.WithValue(req.Context(), CtxTenantID, tenantID)
	return req.WithContext(ctx)
}

// TestRegisterRoutes verifies that API routes are correctly registered.
func TestRegisterRoutes(_ *testing.T) {
	svc := &testutil.MockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	// No error means routes were registered correctly with new Go 1.22 patterns
}

func TestHealthCheck(t *testing.T) {
	svc := &testutil.MockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300}
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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

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
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/zones/z1/records/r1", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteRecord(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestListAuditLogsSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/audit", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(status200Err, w.Code)
	}
}

func TestListAuditLogsInternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("fail")}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/audit", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListAuditLogs(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf(status500Err, w.Code)
	}
}

func TestCreateRecordSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateRecord(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}

func TestCreateRecordValidation(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	tests := []struct {
		name    string
		payload string
		want    int
	}{
		{"Valid A", `{"name": "www.test.com.", "type": "A", "content": "1.2.3.4"}`, http.StatusCreated},
		{"Invalid IP", `{"name": "www.test.com.", "type": "A", "content": "invalid"}`, http.StatusBadRequest},
		{"Invalid Type", `{"name": "www.test.com.", "type": "INVALID", "content": "1.2.3.4"}`, http.StatusBadRequest},
		{"Missing Name", `{"type": "A", "content": "1.2.3.4"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer([]byte(tt.payload)))
			req = withTenant(req, testTenantID)
			w := httptest.NewRecorder()
			handler.CreateRecord(w, req)
			if w.Code != tt.want {
				t.Errorf("CreateRecord(%s) status = %d, want %d", tt.name, w.Code, tt.want)
			}
		})
	}
}

func TestUpdateRecordSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 300}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("PUT", "/zones/z1/records/r1", bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.UpdateRecord(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestUpdateRecordNotFound(t *testing.T) {
	svc := &mockDNSService{err: errors.New("not found")}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 300}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("PUT", "/zones/z1/records/r1", bytes.NewBuffer(body))
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.UpdateRecord(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestUpdateRecordMissingTenant(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 300}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("PUT", "/zones/z1/records/r1", bytes.NewBuffer(body))
	// No withTenant call — missing tenant context
	w := httptest.NewRecorder()

	handler.UpdateRecord(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestUpdateRecordInvalidContentType(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	rec := domain.Record{Name: "www.test.com.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 300}
	body, _ := json.Marshal(rec)
	req := httptest.NewRequest("PUT", "/zones/z1/records/r1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "text/plain")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.UpdateRecord(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Expected status 415, got %d", w.Code)
	}
}

func TestUpdateRecordInvalidBody(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("PUT", "/zones/z1/records/r1", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.UpdateRecord(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDeleteZoneSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/zones/z1", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteZone(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDeleteRecordSuccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/zones/z1/records/r1", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteRecord(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestUnauthorizedAccess(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	endpoints := []struct {
		name   string
		method string
		path   string
		body   string
		fn     http.HandlerFunc
	}{
		{"CreateZone", "POST", "/zones", `{"name": "example.com."}`, handler.CreateZone},
		{"ListZones", "GET", "/zones", "", handler.ListZones},
		{"ListRecords", "GET", "/zones/z1/records", "", handler.ListRecordsForZone},
		{"DeleteZone", "DELETE", "/zones/z1", "", handler.DeleteZone},
		{"CreateRecord", "POST", "/zones/z1/records", `{"name": "www.example.com.", "type": "A", "content": "1.2.3.4"}`, handler.CreateRecord},
		{"DeleteRecord", "DELETE", "/zones/z1/records/r1", "", handler.DeleteRecord},
		{"ListAudit", "GET", "/audit", "", handler.ListAuditLogs},
	}

	for _, tt := range endpoints {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBuffer([]byte(tt.body))
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			// No tenant context
			w := httptest.NewRecorder()
			tt.fn(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: Expected 401, got %d. Body: %s", tt.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.Metrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf(status200Err, w.Code)
	}
}

func TestCreateZone_InvalidContentType(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := []byte(`{"name": "test.com."}`)
	req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "text/plain")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateZone(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Expected status 415, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateRecord_InvalidContentType(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := []byte(`{"name": "www.test.com.", "type": "A", "content": "1.2.3.4"}`)
	req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "text/plain")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateRecord(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Expected status 415, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateZone_BodySizeLimit(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	// Create a payload larger than 1MB
	largeBody := make([]byte, maxBodySize+100)
	for i := range largeBody {
		largeBody[i] = ' '
	}
	// Make it valid JSON by wrapping in object
	largeBody[0] = '{'
	largeBody[len(largeBody)-1] = '}'

	req := httptest.NewRequest("POST", zonesPath, bytes.NewBuffer(largeBody))
	req.Header.Set("Content-Type", "application/json")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateZone(w, req)

	// Should fail due to body size limit (io.EOF from LimitReader exhaustion)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateRecord_BodySizeLimit(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	// Create a payload larger than 1MB
	largeBody := make([]byte, maxBodySize+100)
	for i := range largeBody {
		largeBody[i] = ' '
	}
	largeBody[0] = '{'
	largeBody[len(largeBody)-1] = '}'

	req := httptest.NewRequest("POST", recordsPath, bytes.NewBuffer(largeBody))
	req.Header.Set("Content-Type", "application/json")
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateRecord(w, req)

	// Should fail due to body size limit
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateCatalogZone_Success(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "catalog.example.com."}`))
	req := httptest.NewRequest("POST", "/catalog-zones", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateCatalogZone(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d. Body: %s", w.Code, w.Body.String())
	}
	var catz domain.CatalogZone
	if err := json.Unmarshal(w.Body.Bytes(), &catz); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
	}
	if catz.ID == "" {
		t.Errorf("expected catalog zone ID to be set")
	}
}

func TestCreateCatalogZone_MissingZoneName(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{}`))
	req := httptest.NewRequest("POST", "/catalog-zones", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateCatalogZone(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateCatalogZone_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "catalog.example.com."}`))
	req := httptest.NewRequest("POST", "/catalog-zones", body)
	// No tenant context
	w := httptest.NewRecorder()

	handler.CreateCatalogZone(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCreateCatalogZone_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "catalog.example.com."}`))
	req := httptest.NewRequest("POST", "/catalog-zones", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.CreateCatalogZone(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestListCatalogZones_Success(t *testing.T) {
	svc := &mockDNSService{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog1.example.com.", Version: "1", Serial: 1},
			{ID: "catz-2", TenantID: "t1", ZoneName: "catalog2.example.com.", Version: "1", Serial: 1},
		},
	}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListCatalogZones(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	var catalogs []domain.CatalogZone
	if err := json.Unmarshal(w.Body.Bytes(), &catalogs); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
	}
	if len(catalogs) != 2 {
		t.Errorf("expected 2 catalogs, got %d", len(catalogs))
	}
}

func TestListCatalogZones_Empty(t *testing.T) {
	svc := &mockDNSService{catalogs: []domain.CatalogZone{}}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListCatalogZones(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestListCatalogZones_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones", nil)
	// No tenant context
	w := httptest.NewRecorder()

	handler.ListCatalogZones(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestGetCatalogZone_Success(t *testing.T) {
	svc :=&mockDNSService{
		catalogs: []domain.CatalogZone{
			{ID: "catz-123", TenantID: "t1", ZoneName: "catalog.example.com.", Version: "1", Serial: 1},
		},
	}
	repo := &testutil.MockRepo{}
	repo.On("GetAPIKeyByHash", mock.Anything, mock.Anything).Return(&domain.APIKey{
		ID:        "key-1",
		TenantID:  "t1",
		Role:      domain.RoleAdmin,
		Active:    true,
		ExpiresAt: nil,
		CreatedAt: time.Now(),
	}, nil).Maybe()
	handler := New(svc, repo, slog.Default())

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/catalog-zones/catz-123", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	var catz domain.CatalogZone
	if err := json.Unmarshal(w.Body.Bytes(), &catz); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
	}
	if catz.ID != "catz-123" {
		t.Errorf("expected catalog zone ID 'catz-123', got %s", catz.ID)
	}
}

func TestGetCatalogZone_NotFound(t *testing.T) {
	svc := &mockDNSService{catalogs: []domain.CatalogZone{}}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones/non-existent", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.GetCatalogZone(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestGetCatalogZone_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones/catz-123", nil)
	// No tenant context
	w := httptest.NewRecorder()

	handler.GetCatalogZone(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestDeleteCatalogZone_Success(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/catalog-zones/catz-123", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.DeleteCatalogZone(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestDeleteCatalogZone_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/catalog-zones/catz-123", nil)
	// No tenant context
	w := httptest.NewRecorder()

	handler.DeleteCatalogZone(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAddCatalogEntry_Success(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "zone1.example.com.", "zone_id": "uuid-1", "group_id": "group1"}`))
	req := httptest.NewRequest("POST", "/catalog-zones/catz-123/entries", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.AddCatalogEntry(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAddCatalogEntry_MissingFields(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	// Missing zone_id
	body := bytes.NewBuffer([]byte(`{"zone_name": "zone1.example.com."}`))
	req := httptest.NewRequest("POST", "/catalog-zones/catz-123/entries", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.AddCatalogEntry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAddCatalogEntry_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "zone1.example.com.", "zone_id": "uuid-1"}`))
	req := httptest.NewRequest("POST", "/catalog-zones/catz-123/entries", body)
	// No tenant context
	w := httptest.NewRecorder()

	handler.AddCatalogEntry(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAddCatalogEntry_InvalidJSON(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{invalid json}`))
	req := httptest.NewRequest("POST", "/catalog-zones/catz-123/entries", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.AddCatalogEntry(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAddCatalogEntry_ServiceError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("service error")}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	body := bytes.NewBuffer([]byte(`{"zone_name": "zone1.example.com.", "zone_id": "uuid-1"}`))
	req := httptest.NewRequest("POST", "/catalog-zones/catz-123/entries", body)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.AddCatalogEntry(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestRemoveCatalogEntry_Success(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/catalog-zones/catz-123/entries/zone1.example.com.", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.RemoveCatalogEntry(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestRemoveCatalogEntry_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("DELETE", "/catalog-zones/catz-123/entries/zone1.example.com.", nil)
	// No tenant context
	w := httptest.NewRecorder()

	handler.RemoveCatalogEntry(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestListCatalogEntries_Success(t *testing.T) {
	svc := &mockDNSService{
		catalogEntries: []domain.ZoneCatalogEntry{
			{ZoneName: "zone1.example.com.", ZoneID: "uuid-1", GroupID: "g1"},
			{ZoneName: "zone2.example.com.", ZoneID: "uuid-2"},
		},
	}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones/catz-123/entries", nil)
	req = withTenant(req, testTenantID)
	w := httptest.NewRecorder()

	handler.ListCatalogEntries(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}
	var entries []domain.ZoneCatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestListCatalogEntries_Unauthorized(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	req := httptest.NewRequest("GET", "/catalog-zones/catz-123/entries", nil)
	// No tenant context
	w := httptest.NewRecorder()

	handler.ListCatalogEntries(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCatalogHandler_InternalError(t *testing.T) {
	svc := &mockDNSService{err: errors.New("db error")}
	repo := &testutil.MockRepo{}
	handler := New(svc, repo, slog.Default())

	tests := []struct {
		name string
		fn   http.HandlerFunc
		path string
		body string
	}{
		{"ListCatalogZones", handler.ListCatalogZones, "/catalog-zones", ""},
		{"GetCatalogZone", handler.GetCatalogZone, "/catalog-zones/catz-123", ""},
		{"ListCatalogEntries", handler.ListCatalogEntries, "/catalog-zones/catz-123/entries", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBuffer([]byte(tt.body))
			}
			req := httptest.NewRequest("GET", tt.path, body)
			req = withTenant(req, testTenantID)
			w := httptest.NewRecorder()
			tt.fn(w, req)
			if w.Code != http.StatusInternalServerError {
				t.Errorf("%s: expected 500, got %d", tt.name, w.Code)
			}
		})
	}
}

func TestNewWithNilLogger(t *testing.T) {
	svc :=&mockDNSService{}
	repo := &testutil.MockRepo{}
	// Passing nil logger should not panic and should use slog.Default()
	handler := New(svc, repo, nil)
	if handler == nil {
		t.Error("expected non-nil handler")
	}
	if handler.logger == nil {
		t.Error("expected logger to be set to slog.Default()")
	}
}
