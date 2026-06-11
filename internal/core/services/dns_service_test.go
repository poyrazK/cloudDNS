package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

type testRecordIterator struct {
	records []domain.Record
	index   int
}

func (it *testRecordIterator) Next() bool {
	if it.index >= len(it.records) {
		return false
	}
	it.index++
	return true
}

func (it *testRecordIterator) Record() domain.Record {
	return it.records[it.index-1]
}

func (it *testRecordIterator) Err() error {
	return nil
}

func (it *testRecordIterator) Close() error {
	return nil
}

type mockRepo struct {
	zones          []domain.Zone
	records        []domain.Record
	catalogs       []domain.CatalogZone
	catalogEntries []domain.ZoneCatalogEntry
	err            error
}

func (m *mockRepo) GetRecords(_ context.Context, name string, qType domain.RecordType, _ string) ([]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == name && (qType == "" || r.Type == qType) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) GetRecordsByNames(_ context.Context, names []string, qType domain.RecordType, _ string) (map[string][]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make(map[string][]domain.Record)
	for _, name := range names {
		for _, r := range m.records {
			if r.Name == name && (qType == "" || r.Type == qType) {
				result[name] = append(result[name], r)
			}
		}
	}
	return result, nil
}

func (m *mockRepo) GetIPsForName(_ context.Context, name string, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	var res []string
	for _, r := range m.records {
		if r.Name == name && r.Type == domain.TypeA {
			res = append(res, r.Content)
		}
	}
	return res, nil
}

func (m *mockRepo) GetZone(_ context.Context, name string) (*domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, z := range m.zones {
		if z.Name == name {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) GetZoneLongestMatch(_ context.Context, qName string) (*domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, z := range m.zones {
		if strings.HasSuffix(qName, z.Name) || qName == z.Name {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) GetRecord(_ context.Context, id string, zoneID string, tenantID string) (*domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, r := range m.records {
		if r.ID == id && r.ZoneID == zoneID {
			return &r, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) ListRecordsForZone(_ context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	var res []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) ListRecordsForZoneStreaming(_ context.Context, zoneID string, tenantID string) (ports.RecordIterator, error) {
	records, err := m.ListRecordsForZone(context.Background(), zoneID, tenantID)
	if err != nil {
		return nil, err
	}
	return &sliceRecordIterator{records: records, index: 0}, nil
}

type sliceRecordIterator struct {
	records []domain.Record
	index   int
}

func (it *sliceRecordIterator) Next() bool {
	if it.index >= len(it.records) {
		return false
	}
	it.index++
	return true
}

func (it *sliceRecordIterator) Err() error {
	return nil
}

func (it *sliceRecordIterator) Record() domain.Record {
	return it.records[it.index-1]
}

func (it *sliceRecordIterator) Close() error {
	return nil
}

func (m *mockRepo) CreateZone(_ context.Context, zone *domain.Zone) error {
	if m.err != nil {
		return m.err
	}
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockRepo) CreateZoneWithRecords(_ context.Context, zone *domain.Zone, records []domain.Record) error {
	if m.err != nil {
		return m.err
	}
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}

func (m *mockRepo) CreateRecord(_ context.Context, record *domain.Record) error {
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, *record)
	return nil
}

func (m *mockRepo) BatchCreateRecords(_ context.Context, records []domain.Record) error {
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, records...)
	return nil
}

func (m *mockRepo) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.zones, nil
}

func (m *mockRepo) DeleteZone(_ context.Context, _, _ string) error      { return m.err }
func (m *mockRepo) DeleteRecord(_ context.Context, _, _, _ string) error { return m.err }

func (m *mockRepo) DeleteRecordsByNameAndType(_ context.Context, _, _ string, _ domain.RecordType) error {
	return m.err
}

func (m *mockRepo) DeleteRecordsByName(_ context.Context, _, _ string) error {
	return m.err
}

func (m *mockRepo) DeleteRecordsForZone(_ context.Context, _ string) error {
	return m.err
}

func (m *mockRepo) DeleteRecordSpecific(_ context.Context, _, _ string, _ domain.RecordType, _ string) error {
	return m.err
}

func (m *mockRepo) RecordZoneChange(_ context.Context, _ *domain.ZoneChange) error {
	return m.err
}

func (m *mockRepo) ListZoneChanges(_ context.Context, _ string, _ uint32) ([]domain.ZoneChange, error) {
	return nil, m.err
}

func (m *mockRepo) GetIXFRChain(_ context.Context, _ string, _, _ uint32) ([]domain.IXFRChunk, error) {
	return nil, m.err
}

func (m *mockRepo) ApplyZoneUpdate(_ context.Context, _ string, _ []domain.UpdateOperation, _ []domain.ZoneChange) (uint32, error) {
	return 0, m.err
}

func (m *mockRepo) SaveAuditLog(_ context.Context, _ *domain.AuditLog) error { return m.err }
func (m *mockRepo) GetAuditLogs(_ context.Context, tenantID string) ([]domain.AuditLog, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []domain.AuditLog{{
		ID:           "audit-1",
		TenantID:     tenantID,
		Action:       "CREATE_ZONE",
		ResourceType: "ZONE",
		ResourceID:   "zone-123",
		CreatedAt:    time.Now(),
	}}, nil
}
func (m *mockRepo) Ping(_ context.Context) error { return m.err }

func (m *mockRepo) CreateKey(_ context.Context, _ *domain.DNSSECKey) error { return m.err }
func (m *mockRepo) ListKeysForZone(_ context.Context, _ string) ([]domain.DNSSECKey, error) {
	return nil, m.err
}
func (m *mockRepo) UpdateKey(_ context.Context, _ *domain.DNSSECKey) error { return m.err }
func (m *mockRepo) GetDNSKEYs(_ context.Context, _ string) ([]domain.Record, error) { return nil, nil }

func (m *mockRepo) GetAPIKeyByHash(_ context.Context, _ string) (*domain.APIKey, error) {
	return nil, m.err
}
func (m *mockRepo) CreateAPIKey(_ context.Context, _ *domain.APIKey) error { return m.err }
func (m *mockRepo) ListAPIKeys(_ context.Context, _ string) ([]domain.APIKey, error) {
	return nil, m.err
}
func (m *mockRepo) DeleteAPIKey(_ context.Context, _ string, _ string) error { return m.err }

func (m *mockRepo) GetRecordsToProbeStreaming(_ context.Context) (ports.RecordIterator, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.records) == 0 {
		// Default to probe record if no records seeded (for backward compat with tests)
		return &testRecordIterator{records: []domain.Record{{ID: "probe-1"}}}, nil
	}
	return &testRecordIterator{records: m.records}, nil
}

func (m *mockRepo) UpdateRecordHealth(_ context.Context, _ string, _ domain.HealthStatus, _ string) error {
	return m.err
}

func (m *mockRepo) UpdateRecord(_ context.Context, record *domain.Record) error {
	return m.err
}

func (m *mockRepo) CreateCatalogZone(_ context.Context, catz *domain.CatalogZone) error {
	if m.err != nil {
		return m.err
	}
	m.catalogs = append(m.catalogs, *catz)
	return nil
}
func (m *mockRepo) GetCatalogZone(_ context.Context, catalogID string, tenantID string) (*domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, c := range m.catalogs {
		if c.ID == catalogID && c.TenantID == tenantID {
			return &c, nil
		}
	}
	return nil, nil
}
func (m *mockRepo) GetCatalogZoneByName(_ context.Context, zoneName string, tenantID string) (*domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, c := range m.catalogs {
		if c.ZoneName == zoneName && c.TenantID == tenantID {
			return &c, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) ListCatalogZones(_ context.Context, tenantID string) ([]domain.CatalogZone, error) {
	if m.err != nil {
		return nil, m.err
	}
	var result []domain.CatalogZone
	for _, c := range m.catalogs {
		if c.TenantID == tenantID {
			result = append(result, c)
		}
	}
	return result, nil
}
func (m *mockRepo) UpdateCatalogZoneVersion(_ context.Context, catalogID string, version string, serial uint32) error {
	if m.err != nil {
		return m.err
	}
	for i := range m.catalogs {
		if m.catalogs[i].ID == catalogID {
			m.catalogs[i].Version = version
			m.catalogs[i].Serial = serial
			return nil
		}
	}
	return nil
}
func (m *mockRepo) DeleteCatalogZone(_ context.Context, catalogID string, tenantID string) error {
	if m.err != nil {
		return m.err
	}
	m.catalogs = filterCatalogs(m.catalogs, catalogID, tenantID)
	return nil
}
func (m *mockRepo) ListZoneCatalogEntries(_ context.Context, catalogID string, tenantID string) ([]domain.ZoneCatalogEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.catalogEntries, nil
}
func (m *mockRepo) AddZoneToCatalog(_ context.Context, catalogID string, tenantID string, entry *domain.ZoneCatalogEntry) error {
	if m.err != nil {
		return m.err
	}
	m.catalogEntries = append(m.catalogEntries, *entry)
	return nil
}
func (m *mockRepo) RemoveZoneFromCatalog(_ context.Context, catalogID string, tenantID string, zoneName string) error {
	if m.err != nil {
		return m.err
	}
	var remaining []domain.ZoneCatalogEntry
	for _, e := range m.catalogEntries {
		if e.ZoneName != zoneName {
			remaining = append(remaining, e)
		}
	}
	m.catalogEntries = remaining
	return nil
}
func (m *mockRepo) CreateZoneFromCatalog(_ context.Context, zone *domain.Zone, records []domain.Record) error {
	if m.err != nil {
		return m.err
	}
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}
func (m *mockRepo) DeleteZoneByCatalogName(_ context.Context, catalogZoneName string, tenantID string) error {
	if m.err != nil {
		return m.err
	}
	m.zones = filterZonesByCatalogName(m.zones, catalogZoneName, tenantID)
	return nil
}
func (m *mockRepo) GetZoneByCatalogName(_ context.Context, catalogZoneName string, tenantID string) (*domain.Zone, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, z := range m.zones {
		if z.CatalogZoneName != nil && *z.CatalogZoneName == catalogZoneName && z.TenantID == tenantID {
			return &z, nil
		}
	}
	return nil, nil
}

func filterCatalogs(catalogs []domain.CatalogZone, id, tenantID string) []domain.CatalogZone {
	var result []domain.CatalogZone
	for _, c := range catalogs {
		if !(c.ID == id && c.TenantID == tenantID) {
			result = append(result, c)
		}
	}
	return result
}

func filterZonesByCatalogName(zones []domain.Zone, catalogZoneName, tenantID string) []domain.Zone {
	var result []domain.Zone
	for _, z := range zones {
		if z.CatalogZoneName == nil || *z.CatalogZoneName != catalogZoneName || z.TenantID != tenantID {
			result = append(result, z)
		}
	}
	return result
}

func TestDNSService_ExtraMethods(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	// 1. Test ListAuditLogs
	logs, err := svc.ListAuditLogs(ctx, "t1")
	if err != nil || len(logs) != 1 {
		t.Errorf("ListAuditLogs failed: %v", err)
	}

	// 2. Test GetRecordsToProbeStreaming
	iter, err := svc.GetRecordsToProbeStreaming(ctx)
	if err != nil {
		t.Errorf("GetRecordsToProbeStreaming failed: %v", err)
	}
	defer iter.Close()
	count := 0
	for iter.Next() {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}

	// 3. Test UpdateRecordHealth
	err = svc.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "")
	if err != nil {
		t.Errorf("UpdateRecordHealth failed: %v", err)
	}

	// 4. Test HealthCheck (Repo Ping)
	checks := svc.HealthCheck(ctx)
	if err, ok := checks["postgres"]; !ok || err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}

	// 5. Test Error paths
	repo.err = errors.New("db error")
	_, err = svc.ListAuditLogs(ctx, "t1")
	if err == nil {
		t.Error("Expected error for ListAuditLogs")
	}
	_, err = svc.GetRecordsToProbeStreaming(ctx)
	if err == nil {
		t.Error("Expected error for GetRecordsToProbeStreaming")
	}
	err = svc.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "")
	if err == nil {
		t.Error("Expected error for UpdateRecordHealth")
	}
	checks = svc.HealthCheck(ctx)
	if err, ok := checks["postgres"]; !ok || err == nil {
		t.Error("Expected error for HealthCheck")
	}
}

func TestCreateZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)

	// Case 1: Name with dot
	zone := &domain.Zone{Name: "example.com.", TenantID: "t1"}
	err := svc.CreateZone(context.Background(), zone)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if zone.Name != "example.com." {
		t.Errorf("Expected example.com., got %s", zone.Name)
	}

	// Case 2: Name without dot
	zone2 := &domain.Zone{Name: "nodot.com", TenantID: "t1"}
	err = svc.CreateZone(context.Background(), zone2)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if zone2.Name != "nodot.com." {
		t.Errorf("Expected nodot.com., got %s", zone2.Name)
	}

	if zone.ID == "" {
		t.Errorf("Expected UUID to be generated")
	}
}

func TestDeleteZone(t *testing.T) {
	repo := &auditMockRepo{}
	svc := NewDNSService(repo, nil)

	err := svc.DeleteZone(context.Background(), "z1", "t1")
	if err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}

	if len(repo.logs) != 1 {
		t.Fatalf("Expected 1 audit log, got %d", len(repo.logs))
	}
	if repo.logs[0].Action != "DELETE_ZONE" {
		t.Errorf("Expected action DELETE_ZONE, got %s", repo.logs[0].Action)
	}
}

func TestDeleteRecord(t *testing.T) {
	repo := &auditMockRepo{}
	svc := NewDNSService(repo, nil)

	err := svc.DeleteRecord(context.Background(), "r1", "z1", "t1")
	if err != nil {
		t.Fatalf("DeleteRecord failed: %v", err)
	}

	if len(repo.logs) != 1 {
		t.Fatalf("Expected 1 audit log, got %d", len(repo.logs))
	}
	if repo.logs[0].Action != "DELETE_RECORD" {
		t.Errorf("Expected action DELETE_RECORD, got %s", repo.logs[0].Action)
	}
}

func TestImportZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)

	zoneFile := `
$ORIGIN import.test.
$TTL 3600
@   IN  SOA ns1.import.test. admin.import.test. 1 2 3 4 5
www IN  A   1.2.3.4
`
	ctx := context.Background()
	zone, err := svc.ImportZone(ctx, "t1", strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("ImportZone failed: %v", err)
	}

	if zone.Name != "import.test." {
		t.Errorf("Expected zone name import.test., got %s", zone.Name)
	}

	// Verify records were created in repo
	if len(repo.records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(repo.records))
	}
}

func TestImportZone_Error(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)

	// Malformed (missing fields)
	malformed := "$ORIGIN test.com.\nwww A"
	_, err := svc.ImportZone(context.Background(), "t1", strings.NewReader(malformed))

	if err != nil {
		t.Errorf("Expected skip/partial rather than fatal err, got %v", err)
	}
}

func TestResolve_Wildcard(t *testing.T) {
	repo := &mockRepo{
		records: []domain.Record{
			{Name: "*.example.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300},
		},
	}
	svc := NewDNSService(repo, nil)

	// Test direct hit on wildcard
	recs, err := svc.Resolve(context.Background(), "www.example.test.", domain.TypeA, "8.8.8.8")
	if err != nil || len(recs) != 1 {
		t.Fatalf("Wildcard resolution failed: %v", err)
	}
	if recs[0].Name != "www.example.test." {
		t.Errorf("Expected name to be rewritten to www.example.test., got %s", recs[0].Name)
	}

	// Test deeper level hit
	recs, _ = svc.Resolve(context.Background(), "a.b.example.test.", domain.TypeA, "8.8.8.8")
	if len(recs) != 1 {
		t.Errorf("Wildcard resolution failed")
	}
}

func TestListZones(t *testing.T) {
	repo := &mockRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "z1.test."},
			{ID: "z2", Name: "z2.test."},
		},
	}
	svc := NewDNSService(repo, nil)

	zones, err := svc.ListZones(context.Background(), "t1")
	if err != nil || len(zones) != 2 {
		t.Errorf("ListZones failed")
	}
}

func TestHealthCheck(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)

	checks := svc.HealthCheck(context.Background())
	if err, ok := checks["postgres"]; !ok || err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

func TestListRecordsForZone(t *testing.T) {
	repo := &mockRepo{
		records: []domain.Record{
			{ID: "r1", ZoneID: "z1", Name: "www.z1.test.", Type: domain.TypeA},
			{ID: "r2", ZoneID: "z2", Name: "www.z2.test.", Type: domain.TypeA},
		},
	}
	svc := NewDNSService(repo, nil)

	recs, err := svc.ListRecordsForZone(context.Background(), "z1", "")
	if err != nil {
		t.Fatalf("ListRecordsForZone failed: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "r1" {
		t.Errorf("Expected only r1 for zone z1, got %d records", len(recs))
	}
}

func TestServiceErrorPaths(t *testing.T) {
	repo := &mockRepo{err: errors.New("db error")}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	if err := svc.CreateZone(ctx, &domain.Zone{Name: "test."}); err == nil {
		t.Errorf("Expected error in CreateZone")
	}
	if err := svc.CreateRecord(ctx, &domain.Record{}); err == nil {
		t.Errorf("Expected error in CreateRecord")
	}
	if _, err := svc.Resolve(ctx, "test.", domain.TypeA, ""); err == nil {
		t.Errorf("Expected error in Resolve")
	}
	if _, err := svc.ListZones(ctx, ""); err == nil {
		t.Errorf("Expected error in ListZones")
	}
	if err := svc.DeleteZone(ctx, "z1", ""); err == nil {
		t.Errorf("Expected error in DeleteZone")
	}
	if err := svc.DeleteRecord(ctx, "r1", "", ""); err == nil {
		t.Errorf("Expected error in DeleteRecord")
	}
	if _, err := svc.ImportZone(ctx, "", strings.NewReader("")); err == nil {
		t.Errorf("Expected error in ImportZone")
	}
}

func TestResolve_SmartEngine(t *testing.T) {
	repo := &mockRepo{
		records: []domain.Record{
			{ID: "r1", Name: "www.test.", Type: domain.TypeA, Content: "1.1.1.1", HealthStatus: domain.HealthStatusHealthy},
			{ID: "r2", Name: "www.test.", Type: domain.TypeA, Content: "2.2.2.2", HealthStatus: domain.HealthStatusUnhealthy},
			{ID: "r3", Name: "www.test.", Type: domain.TypeA, Content: "3.3.3.3", HealthStatus: domain.HealthStatusUnknown},
		},
	}
	svc := NewDNSService(repo, nil)

	// Case 1: Filter out Unhealthy, keep Healthy and Unknown
	recs, err := svc.Resolve(context.Background(), "www.test.", domain.TypeA, "8.8.8.8")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("Expected 2 records (healthy + unknown), got %d", len(recs))
	}
	for _, r := range recs {
		if r.Content == "2.2.2.2" {
			t.Errorf("Unhealthy record was not filtered out")
		}
	}

	// Case 2: Fallback - All are unhealthy
	repo.records = []domain.Record{
		{ID: "r1", Name: "fail.test.", Type: domain.TypeA, Content: "1.1.1.1", HealthStatus: domain.HealthStatusUnhealthy},
		{ID: "r2", Name: "fail.test.", Type: domain.TypeA, Content: "2.2.2.2", HealthStatus: domain.HealthStatusUnhealthy},
	}
	recs, err = svc.Resolve(context.Background(), "fail.test.", domain.TypeA, "8.8.8.8")
	if err != nil {
		t.Fatalf("Resolve failed in fallback: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("Expected fallback to return all 2 records, got %d", len(recs))
	}
}

func TestGetRecordsToProbeStreaming(t *testing.T) {
	repo := &mockRepo{
		records: []domain.Record{
			{ID: "r1", Name: "probe1.test.", Type: domain.TypeA, HealthCheckTarget: "http://probe1.test"},
			{ID: "r2", Name: "probe2.test.", Type: domain.TypeA, HealthCheckTarget: "http://probe2.test"},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	iter, err := svc.GetRecordsToProbeStreaming(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if iter == nil {
		t.Fatal("Expected iterator, got nil")
	}

	// Should be able to iterate
	count := 0
	for iter.Next() {
		count++
		_ = iter.Record()
	}
	if count != 2 {
		t.Errorf("Expected 2 records, got %d", count)
	}

	if err := iter.Err(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	iter.Close()
}

func TestCreateCatalogZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	catz, err := svc.CreateCatalogZone(ctx, "t1", "catalog.example.com.")
	if err != nil {
		t.Fatalf("CreateCatalogZone failed: %v", err)
	}
	if catz.ID == "" {
		t.Errorf("expected generated ID")
	}
	if catz.TenantID != "t1" {
		t.Errorf("expected tenant_id t1, got %s", catz.TenantID)
	}
	if catz.ZoneName != "catalog.example.com." {
		t.Errorf("expected zone_name 'catalog.example.com.', got %s", catz.ZoneName)
	}
	if catz.Version != "1" {
		t.Errorf("expected version '1', got %s", catz.Version)
	}
	if catz.Serial != 1 {
		t.Errorf("expected serial 1, got %d", catz.Serial)
	}
	if len(repo.catalogs) != 1 {
		t.Errorf("expected 1 catalog in repo, got %d", len(repo.catalogs))
	}
}

func TestGetCatalogZone(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.", Version: "1", Serial: 1},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	// Correct tenant
	got, err := svc.GetCatalogZone(ctx, "catz-1", "t1")
	if err != nil {
		t.Fatalf("GetCatalogZone failed: %v", err)
	}
	if got == nil || got.ID != "catz-1" {
		t.Errorf("expected catz-1, got %+v", got)
	}

	// Wrong tenant
	gotWrong, errWrong := svc.GetCatalogZone(ctx, "catz-1", "t2")
	if errWrong != nil {
		t.Fatalf("GetCatalogZone with wrong tenant returned error: %v", errWrong)
	}
	if gotWrong != nil {
		t.Errorf("expected nil for wrong tenant, got %+v", gotWrong)
	}

	// Non-existent
	gotMissing, errMissing := svc.GetCatalogZone(ctx, "non-existent", "t1")
	if errMissing != nil {
		t.Fatalf("GetCatalogZone for non-existent returned error: %v", errMissing)
	}
	if gotMissing != nil {
		t.Errorf("expected nil for non-existent, got %+v", gotMissing)
	}
}

func TestListCatalogZones(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog1.example.com."},
			{ID: "catz-2", TenantID: "t1", ZoneName: "catalog2.example.com."},
			{ID: "catz-3", TenantID: "t2", ZoneName: "catalog3.example.com."},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	t1Catalogs, err := svc.ListCatalogZones(ctx, "t1")
	if err != nil {
		t.Fatalf("ListCatalogZones(t1) failed: %v", err)
	}
	if len(t1Catalogs) != 2 {
		t.Errorf("expected 2 catalogs for t1, got %d", len(t1Catalogs))
	}

	t2Catalogs, err := svc.ListCatalogZones(ctx, "t2")
	if err != nil {
		t.Fatalf("ListCatalogZones(t2) failed: %v", err)
	}
	if len(t2Catalogs) != 1 {
		t.Errorf("expected 1 catalog for t2, got %d", len(t2Catalogs))
	}

	emptyCatalogs, err := svc.ListCatalogZones(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ListCatalogZones for nonexistent tenant failed: %v", err)
	}
	if len(emptyCatalogs) != 0 {
		t.Errorf("expected 0 catalogs for nonexistent tenant, got %d", len(emptyCatalogs))
	}
}

func TestDeleteCatalogZone(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com."},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	err := svc.DeleteCatalogZone(ctx, "catz-1", "t1")
	if err != nil {
		t.Fatalf("DeleteCatalogZone failed: %v", err)
	}
	if len(repo.catalogs) != 0 {
		t.Errorf("expected 0 catalogs after delete, got %d", len(repo.catalogs))
	}
}

func TestAddZoneToCatalog(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.", Serial: 1, Version: "1"},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	err := svc.AddZoneToCatalog(ctx, "catz-1", "t1", "zone1.example.com.", "zone-uuid-1", "group1")
	if err != nil {
		t.Fatalf("AddZoneToCatalog failed: %v", err)
	}

	// Verify entry was added
	if len(repo.catalogEntries) != 1 {
		t.Errorf("expected 1 catalog entry, got %d", len(repo.catalogEntries))
	}
	if repo.catalogEntries[0].ZoneName != "zone1.example.com." {
		t.Errorf("expected zone_name 'zone1.example.com.', got %s", repo.catalogEntries[0].ZoneName)
	}

	// Verify serial was incremented
	if repo.catalogs[0].Serial != 2 {
		t.Errorf("expected serial 2 after add, got %d", repo.catalogs[0].Serial)
	}
}

func TestRemoveZoneFromCatalog(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.", Serial: 1, Version: "1"},
		},
		catalogEntries: []domain.ZoneCatalogEntry{
			{ZoneName: "foo.example.com.", ZoneID: "uuid-foo"},
			{ZoneName: "bar.example.com.", ZoneID: "uuid-bar"},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	err := svc.RemoveZoneFromCatalog(ctx, "catz-1", "t1", "foo.example.com.")
	if err != nil {
		t.Fatalf("RemoveZoneFromCatalog failed: %v", err)
	}

	// Verify foo was removed, bar remains
	if len(repo.catalogEntries) != 1 {
		t.Errorf("expected 1 remaining entry, got %d", len(repo.catalogEntries))
	}
	if repo.catalogEntries[0].ZoneName != "bar.example.com." {
		t.Errorf("expected remaining entry 'bar.example.com.', got %s", repo.catalogEntries[0].ZoneName)
	}

	// Verify serial was incremented
	if repo.catalogs[0].Serial != 2 {
		t.Errorf("expected serial 2 after remove, got %d", repo.catalogs[0].Serial)
	}
}

func TestListZoneCatalogEntries(t *testing.T) {
	repo := &mockRepo{
		catalogEntries: []domain.ZoneCatalogEntry{
			{ZoneName: "foo.example.com.", ZoneID: "uuid-1", GroupID: "g1"},
			{ZoneName: "bar.example.com.", ZoneID: "uuid-2"},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	entries, err := svc.ListZoneCatalogEntries(ctx, "catz-1", "t1")
	if err != nil {
		t.Fatalf("ListZoneCatalogEntries failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestCatalogZone_TenantIsolation(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com."},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	// t2 should not see t1's catalog
	got, err := svc.GetCatalogZone(ctx, "catz-1", "t2")
	if err != nil {
		t.Fatalf("GetCatalogZone returned error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for cross-tenant access, got %+v", got)
	}
}

func TestCatalogZone_SerialIncrement(t *testing.T) {
	repo := &mockRepo{
		catalogs: []domain.CatalogZone{
			{ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.", Serial: 1, Version: "1"},
		},
	}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	// AddZoneToCatalog increments serial
	err := svc.AddZoneToCatalog(ctx, "catz-1", "t1", "zone1.example.com.", "zone-uuid-1", "")
	if err != nil {
		t.Fatalf("AddZoneToCatalog failed: %v", err)
	}
	if repo.catalogs[0].Serial != 2 {
		t.Errorf("expected serial 2 after add, got %d", repo.catalogs[0].Serial)
	}
	if repo.catalogs[0].Version != "1" {
		t.Errorf("version should not change on add, got %s", repo.catalogs[0].Version)
	}

	// RemoveZoneFromCatalog increments serial
	err = svc.RemoveZoneFromCatalog(ctx, "catz-1", "t1", "zone1.example.com.")
	if err != nil {
		t.Fatalf("RemoveZoneFromCatalog failed: %v", err)
	}
	if repo.catalogs[0].Serial != 3 {
		t.Errorf("expected serial 3 after remove, got %d", repo.catalogs[0].Serial)
	}
}

func TestCatalogZoneService_ErrorPaths(t *testing.T) {
	repo := &mockRepo{err: errors.New("db error")}
	svc := NewDNSService(repo, nil)
	ctx := context.Background()

	if _, err := svc.CreateCatalogZone(ctx, "t1", "catalog.example.com."); err == nil {
		t.Error("expected error in CreateCatalogZone")
	}
	if _, err := svc.GetCatalogZone(ctx, "catz-1", "t1"); err == nil {
		t.Error("expected error in GetCatalogZone")
	}
	if _, err := svc.ListCatalogZones(ctx, "t1"); err == nil {
		t.Error("expected error in ListCatalogZones")
	}
	if err := svc.DeleteCatalogZone(ctx, "catz-1", "t1"); err == nil {
		t.Error("expected error in DeleteCatalogZone")
	}
	if err := svc.AddZoneToCatalog(ctx, "catz-1", "t1", "zone.example.com.", "uuid", ""); err == nil {
		t.Error("expected error in AddZoneToCatalog")
	}
	if err := svc.RemoveZoneFromCatalog(ctx, "catz-1", "t1", "zone.example.com."); err == nil {
		t.Error("expected error in RemoveZoneFromCatalog")
	}
	if _, err := svc.ListZoneCatalogEntries(ctx, "catz-1", "t1"); err == nil {
		t.Error("expected error in ListZoneCatalogEntries")
	}
}

