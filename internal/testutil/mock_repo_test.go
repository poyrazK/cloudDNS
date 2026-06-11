package testutil

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

func TestMockRepo_GetRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("GetRecords", "test", domain.TypeA, "1.1").Return([]domain.Record{}, nil)
	recs, err := m.GetRecords(context.Background(), "test", domain.TypeA, "1.1")
	if err != nil || len(recs) != 0 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_GetIPsForName(t *testing.T) {
	m := new(MockRepo)
	m.On("GetIPsForName", "test", "1.1").Return([]string{"1.2.3.4"}, nil)
	ips, err := m.GetIPsForName(context.Background(), "test", "1.1")
	if err != nil || len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_GetZone(t *testing.T) {
	m := new(MockRepo)
	m.On("GetZone", "test").Return(&domain.Zone{ID: "z1"}, nil)
	z, err := m.GetZone(context.Background(), "test")
	if err != nil || z.ID != "z1" {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_GetRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("GetRecord", "id", "zone", "tenant").Return(&domain.Record{ID: "r1"}, nil)
	r, err := m.GetRecord(context.Background(), "id", "zone", "tenant")
	if err != nil || r.ID != "r1" {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_ListRecordsForZone(t *testing.T) {
	m := new(MockRepo)
	m.On("ListRecordsForZone", "zone", "tenant").Return([]domain.Record{{ID: "r1"}}, nil)
	recs, err := m.ListRecordsForZone(context.Background(), "zone", "tenant")
	if err != nil || len(recs) != 1 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_CreateZone(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateZone", mock.Anything).Return(nil)
	err := m.CreateZone(context.Background(), &domain.Zone{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_CreateZoneWithRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateZoneWithRecords", mock.Anything, mock.Anything).Return(nil)
	err := m.CreateZoneWithRecords(context.Background(), &domain.Zone{}, []domain.Record{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_CreateRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateRecord", mock.Anything).Return(nil)
	err := m.CreateRecord(context.Background(), &domain.Record{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_BatchCreateRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("BatchCreateRecords", mock.Anything).Return(nil)
	err := m.BatchCreateRecords(context.Background(), []domain.Record{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_ListZones(t *testing.T) {
	m := new(MockRepo)
	m.On("ListZones", "tenant").Return([]domain.Zone{{ID: "z1"}}, nil)
	zones, err := m.ListZones(context.Background(), "tenant")
	if err != nil || len(zones) != 1 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_DeleteZone(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteZone", "zone", "tenant").Return(nil)
	err := m.DeleteZone(context.Background(), "zone", "tenant")
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_DeleteRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecord", "record", "zone", "tenant").Return(nil)
	err := m.DeleteRecord(context.Background(), "record", "zone", "tenant")
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_DeleteRecordsByNameAndType(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsByNameAndType", "zone", "name", domain.TypeA).Return(nil)
	err := m.DeleteRecordsByNameAndType(context.Background(), "zone", "name", domain.TypeA)
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_DeleteRecordsByName(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsByName", "zone", "name").Return(nil)
	err := m.DeleteRecordsByName(context.Background(), "zone", "name")
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_DeleteRecordSpecific(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordSpecific", "zone", "name", domain.TypeA, "content").Return(nil)
	err := m.DeleteRecordSpecific(context.Background(), "zone", "name", domain.TypeA, "content")
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_RecordZoneChange(t *testing.T) {
	m := new(MockRepo)
	m.On("RecordZoneChange", mock.Anything).Return(nil)
	err := m.RecordZoneChange(context.Background(), &domain.ZoneChange{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_ListZoneChanges(t *testing.T) {
	m := new(MockRepo)
	m.On("ListZoneChanges", "zone", uint32(1)).Return([]domain.ZoneChange{{ID: "c1"}}, nil)
	changes, err := m.ListZoneChanges(context.Background(), "zone", 1)
	if err != nil || len(changes) != 1 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_SaveAuditLog(t *testing.T) {
	m := new(MockRepo)
	m.On("SaveAuditLog", mock.Anything).Return(nil)
	err := m.SaveAuditLog(context.Background(), &domain.AuditLog{})
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_GetIXFRChain(t *testing.T) {
	m := new(MockRepo)
	m.On("GetIXFRChain", "z1", uint32(1), uint32(2)).Return([]domain.IXFRChunk{{Serial: 2}}, nil)
	chunks, err := m.GetIXFRChain(context.Background(), "z1", 1, 2)
	if err != nil || len(chunks) != 1 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_GetAuditLogs(t *testing.T) {
	m := new(MockRepo)
	m.On("GetAuditLogs", "t1").Return([]domain.AuditLog{{ID: "a1"}}, nil)
	logs, err := m.GetAuditLogs(context.Background(), "t1")
	if err != nil || len(logs) != 1 {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_Ping(t *testing.T) {
	m := new(MockRepo)
	m.On("Ping").Return(nil)
	err := m.Ping(context.Background())
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockRepo_ApplyZoneUpdate(t *testing.T) {
	m := new(MockRepo)
	m.On("ApplyZoneUpdate", "z1", mock.Anything, mock.Anything).Return(uint32(3), nil)
	serial, err := m.ApplyZoneUpdate(context.Background(), "z1", []domain.UpdateOperation{}, []domain.ZoneChange{})
	if err != nil {
		t.Errorf("Mock failed")
	}
	if serial != 3 {
		t.Errorf("Expected serial 3, got %d", serial)
	}
}

func TestMockRepo_DNSSECKeys(t *testing.T) {
	m := new(MockRepo)
	key := &domain.DNSSECKey{ID: "k1"}
	m.On("CreateKey", key).Return(nil)
	err := m.CreateKey(context.Background(), key)
	if err != nil { t.Errorf("CreateKey failed") }

	m.On("ListKeysForZone", "z1").Return([]domain.DNSSECKey{*key}, nil)
	keys, err := m.ListKeysForZone(context.Background(), "z1")
	if err != nil || len(keys) != 1 { t.Errorf("ListKeysForZone failed") }

	m.On("UpdateKey", key).Return(nil)
	err = m.UpdateKey(context.Background(), key)
	if err != nil { t.Errorf("UpdateKey failed") }
}

func TestMockRepo_APIKeys(t *testing.T) {
	m := new(MockRepo)
	key := &domain.APIKey{ID: "ak1"}
	m.On("GetAPIKeyByHash", "h1").Return(key, nil)
	got, err := m.GetAPIKeyByHash(context.Background(), "h1")
	if err != nil || got.ID != "ak1" { t.Errorf("GetAPIKeyByHash failed") }

	m.On("CreateAPIKey", key).Return(nil)
	err = m.CreateAPIKey(context.Background(), key)
	if err != nil { t.Errorf("CreateAPIKey failed") }

	m.On("ListAPIKeys", "t1").Return([]domain.APIKey{*key}, nil)
	keys, err := m.ListAPIKeys(context.Background(), "t1")
	if err != nil || len(keys) != 1 { t.Errorf("ListAPIKeys failed") }

	m.On("DeleteAPIKey", "t1", "ak1").Return(nil)
	err = m.DeleteAPIKey(context.Background(), "t1", "ak1")
	if err != nil { t.Errorf("DeleteAPIKey failed") }
}

func TestMockRepo_Health(t *testing.T) {
	m := new(MockRepo)
	m.On("UpdateRecordHealth", mock.Anything, "r1", domain.HealthStatusHealthy, "ok").Return(nil)
	err := m.UpdateRecordHealth(context.Background(), "r1", domain.HealthStatusHealthy, "ok")
	if err != nil { t.Errorf("UpdateRecordHealth failed") }

	// Test GetRecordsToProbeStreaming - uses a simple mock iterator
	mockedIter := &mockRecordIterator{records: []domain.Record{{ID: "r1"}}, index: 0}
	m.On("GetRecordsToProbeStreaming", mock.Anything).Return(mockedIter, nil)
	iter, err := m.GetRecordsToProbeStreaming(context.Background())
	if err != nil || iter == nil { t.Errorf("GetRecordsToProbeStreaming failed") }
}

// mockRecordIterator is a simple implementation for testing
type mockRecordIterator struct {
	records []domain.Record
	index   int
}

func (m *mockRecordIterator) Next() bool {
	m.index++
	return m.index <= len(m.records)
}

func (m *mockRecordIterator) Err() error { return nil }

func (m *mockRecordIterator) Record() domain.Record {
	if m.index > 0 && m.index <= len(m.records) {
		return m.records[m.index-1]
	}
	return domain.Record{}
}

func (m *mockRecordIterator) Close() error { return nil }

func TestMockRepo_DeleteRecordsForZone(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsForZone", "z1").Return(nil)
	err := m.DeleteRecordsForZone(context.Background(), "z1")
	if err != nil {
		t.Errorf("Mock failed")
	}
}

func TestMockDNSService(t *testing.T) {
	m := new(MockDNSService)
	ctx := context.Background()
	
	m.On("CreateZone", mock.Anything).Return(nil)
	err := m.CreateZone(ctx, &domain.Zone{})
	if err != nil { t.Errorf("CreateZone failed") }

	m.On("CreateRecord", mock.Anything).Return(nil)
	err = m.CreateRecord(ctx, &domain.Record{})
	if err != nil { t.Errorf("CreateRecord failed") }

	m.On("Resolve", "test.", domain.TypeA, "1.1").Return([]domain.Record{{ID: "r1"}}, nil)
	recs, err := m.Resolve(ctx, "test.", domain.TypeA, "1.1")
	if err != nil || len(recs) != 1 { t.Errorf("Resolve failed") }

	m.On("GetRecordsToProbeStreaming").Return(&mockRecordIterator{records: []domain.Record{{ID: "r1"}}, index: 0}, nil)
	iter, err := m.GetRecordsToProbeStreaming(ctx)
	if err != nil || iter == nil { t.Errorf("GetRecordsToProbeStreaming failed") }

	m.On("UpdateRecordHealth", "r1", domain.HealthStatusHealthy, "ok").Return(nil)
	err = m.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "ok")
	if err != nil { t.Errorf("UpdateRecordHealth failed") }

	m.On("ListZones", "t1").Return([]domain.Zone{{ID: "z1"}}, nil)
	zones, err := m.ListZones(ctx, "t1")
	if err != nil || len(zones) != 1 { t.Errorf("ListZones failed") }

	m.On("ListRecordsForZone", "z1", "t1").Return([]domain.Record{{ID: "r1"}}, nil)
	recs, err = m.ListRecordsForZone(ctx, "z1", "t1")
	if err != nil || len(recs) != 1 { t.Errorf("ListRecordsForZone failed") }

	m.On("DeleteZone", "z1", "t1").Return(nil)
	err = m.DeleteZone(ctx, "z1", "t1")
	if err != nil { t.Errorf("DeleteZone failed") }

	m.On("DeleteRecord", "r1", "z1", "t1").Return(nil)
	err = m.DeleteRecord(ctx, "r1", "z1", "t1")
	if err != nil { t.Errorf("DeleteRecord failed") }

	m.On("ImportZone", "t1", mock.Anything).Return(&domain.Zone{ID: "zi"}, nil)
	z, err := m.ImportZone(ctx, "t1", nil)
	if err != nil || z.ID != "zi" { t.Errorf("ImportZone failed") }

	m.On("ListAuditLogs", "t1").Return([]domain.AuditLog{{ID: "a1"}}, nil)
	logs, err := m.ListAuditLogs(ctx, "t1")
	if err != nil || len(logs) != 1 { t.Errorf("ListAuditLogs failed") }

	m.On("HealthCheck").Return(map[string]error{"postgres": nil})
	checks := m.HealthCheck(ctx)
	if len(checks) != 1 || checks["postgres"] != nil { t.Errorf("HealthCheck failed") }
}

func TestMockRepo_GetCatalogZoneByName(t *testing.T) {
	m := new(MockRepo)
	m.On("GetCatalogZoneByName", "catalog.example.com.", "t1").Return(&domain.CatalogZone{
		ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.", Version: "1", Serial: 1,
	}, nil).Once()

	catz, err := m.GetCatalogZoneByName(context.Background(), "catalog.example.com.", "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catz == nil || catz.ID != "catz-1" {
		t.Errorf("unexpected result: %+v", catz)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_GetCatalogZoneByName_NotFound(t *testing.T) {
	m := new(MockRepo)
	m.On("GetCatalogZoneByName", "nonexistent.example.com.", "t1").Return(nil, nil).Once()

	catz, err := m.GetCatalogZoneByName(context.Background(), "nonexistent.example.com.", "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catz != nil {
		t.Errorf("expected nil, got %+v", catz)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_CatalogZoneMethods(t *testing.T) {
	t.Run("CreateCatalogZone", func(t *testing.T) {
		m := new(MockRepo)
		m.On("CreateCatalogZone", mock.Anything).Return(nil).Once()
		err := m.CreateCatalogZone(context.Background(),&domain.CatalogZone{ID: "catz-1"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("GetCatalogZone", func(t *testing.T) {
		m := new(MockRepo)
		m.On("GetCatalogZone", "catz-1", "t1").Return(&domain.CatalogZone{ID: "catz-1"}, nil).Once()
		catz, err := m.GetCatalogZone(context.Background(), "catz-1", "t1")
		if err != nil || catz == nil || catz.ID != "catz-1" {
			t.Errorf("unexpected result: %+v, err: %v", catz, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("GetCatalogZone_NotFound", func(t *testing.T) {
		m := new(MockRepo)
		m.On("GetCatalogZone", "nonexistent", "t1").Return(nil, nil).Once()
		catz, err := m.GetCatalogZone(context.Background(), "nonexistent", "t1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if catz != nil {
			t.Errorf("expected nil, got %+v", catz)
		}
		m.AssertExpectations(t)
	})

	t.Run("ListCatalogZones", func(t *testing.T) {
		m := new(MockRepo)
		m.On("ListCatalogZones", "t1").Return([]domain.CatalogZone{{ID: "catz-1"}}, nil).Once()
		catzs, err := m.ListCatalogZones(context.Background(), "t1")
		if err != nil || len(catzs) != 1 {
			t.Errorf("unexpected result: %+v, err: %v", catzs, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("UpdateCatalogZoneVersion", func(t *testing.T) {
		m := new(MockRepo)
		m.On("UpdateCatalogZoneVersion", "catz-1", "2", uint32(10)).Return(nil).Once()
		err := m.UpdateCatalogZoneVersion(context.Background(), "catz-1", "2", 10)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("DeleteCatalogZone", func(t *testing.T) {
		m := new(MockRepo)
		m.On("DeleteCatalogZone", "catz-1", "t1").Return(nil).Once()
		err := m.DeleteCatalogZone(context.Background(), "catz-1", "t1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("ListZoneCatalogEntries", func(t *testing.T) {
		m := new(MockRepo)
		entries := []domain.ZoneCatalogEntry{{ZoneName: "zone1.example.com."}}
		m.On("ListZoneCatalogEntries", "catz-1", "t1").Return(entries, nil).Once()
		result, err := m.ListZoneCatalogEntries(context.Background(), "catz-1", "t1")
		if err != nil || len(result) != 1 {
			t.Errorf("unexpected result: %+v, err: %v", result, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("AddZoneToCatalog", func(t *testing.T) {
		m := new(MockRepo)
		entry := &domain.ZoneCatalogEntry{ZoneName: "zone1.example.com."}
		m.On("AddZoneToCatalog", "catz-1", "t1", entry).Return(nil).Once()
		err := m.AddZoneToCatalog(context.Background(), "catz-1", "t1", entry)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("RemoveZoneFromCatalog", func(t *testing.T) {
		m := new(MockRepo)
		m.On("RemoveZoneFromCatalog", "catz-1", "t1", "zone1.example.com.").Return(nil).Once()
		err := m.RemoveZoneFromCatalog(context.Background(), "catz-1", "t1", "zone1.example.com.")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("CreateZoneFromCatalog", func(t *testing.T) {
		m := new(MockRepo)
		m.On("CreateZoneFromCatalog", mock.Anything, mock.Anything).Return(nil).Once()
		err := m.CreateZoneFromCatalog(context.Background(), &domain.Zone{ID: "z1"}, []domain.Record{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("DeleteZoneByCatalogName", func(t *testing.T) {
		m := new(MockRepo)
		m.On("DeleteZoneByCatalogName", "zone1.example.com.", "t1").Return(nil).Once()
		err := m.DeleteZoneByCatalogName(context.Background(), "zone1.example.com.", "t1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("GetZoneByCatalogName", func(t *testing.T) {
		m := new(MockRepo)
		m.On("GetZoneByCatalogName", "zone1.example.com.", "t1").Return(&domain.Zone{ID: "z1"}, nil).Once()
		zone, err := m.GetZoneByCatalogName(context.Background(), "zone1.example.com.", "t1")
		if err != nil || zone == nil || zone.ID != "z1" {
			t.Errorf("unexpected result: %+v, err: %v", zone, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("GetZoneByCatalogName_NotFound", func(t *testing.T) {
		m := new(MockRepo)
		m.On("GetZoneByCatalogName", "nonexistent.example.com.", "t1").Return(nil, nil).Once()
		zone, err := m.GetZoneByCatalogName(context.Background(), "nonexistent.example.com.", "t1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if zone != nil {
			t.Errorf("expected nil, got %+v", zone)
		}
		m.AssertExpectations(t)
	})
}

func TestMockDNSService_CatalogMethods(t *testing.T) {
	t.Run("CreateCatalogZone", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("CreateCatalogZone", mock.Anything, mock.Anything, mock.Anything).Return(&domain.CatalogZone{ID: "catz-1"}, nil).Once()
		catz, err := m.CreateCatalogZone(context.Background(), "catz-1", "t1")
		if err != nil || catz == nil || catz.ID != "catz-1" {
			t.Errorf("unexpected result: %+v, err: %v", catz, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("GetCatalogZone", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("GetCatalogZone", mock.Anything, mock.Anything, mock.Anything).Return(&domain.CatalogZone{ID: "catz-1"}, nil).Once()
		catz, err := m.GetCatalogZone(context.Background(), "catz-1", "t1")
		if err != nil || catz == nil || catz.ID != "catz-1" {
			t.Errorf("unexpected result: %+v, err: %v", catz, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("ListCatalogZones", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("ListCatalogZones", mock.Anything, mock.Anything).Return([]domain.CatalogZone{{ID: "catz-1"}}, nil).Once()
		catzs, err := m.ListCatalogZones(context.Background(), "t1")
		if err != nil || len(catzs) != 1 {
			t.Errorf("unexpected result: %+v, err: %v", catzs, err)
		}
		m.AssertExpectations(t)
	})

	t.Run("DeleteCatalogZone", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("DeleteCatalogZone", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		err := m.DeleteCatalogZone(context.Background(), "catz-1", "t1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("AddZoneToCatalog", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("AddZoneToCatalog", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		err := m.AddZoneToCatalog(context.Background(), "catz-1", "t1", "zone1", "tenant", "192.168.1.1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("RemoveZoneFromCatalog", func(t *testing.T) {
		m := new(MockDNSService)
		m.On("RemoveZoneFromCatalog", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		err := m.RemoveZoneFromCatalog(context.Background(), "catz-1", "t1", "zone1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		m.AssertExpectations(t)
	})

	t.Run("ListZoneCatalogEntries", func(t *testing.T) {
		m := new(MockDNSService)
		entries := []domain.ZoneCatalogEntry{{ZoneName: "zone1.example.com."}}
		m.On("ListZoneCatalogEntries", mock.Anything, mock.Anything, mock.Anything).Return(entries, nil).Once()
		result, err := m.ListZoneCatalogEntries(context.Background(), "catz-1", "t1")
		if err != nil || len(result) != 1 {
			t.Errorf("unexpected result: %+v, err: %v", result, err)
		}
		m.AssertExpectations(t)
	})
}

func TestMockRepo_GetRecordsByNames(t *testing.T) {
	m := new(MockRepo)
	recs := map[string][]domain.Record{"a.example.com.": {{ID: "r1", Name: "a.example.com."}}}
	m.On("GetRecordsByNames", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(recs, nil).Once()
	result, err := m.GetRecordsByNames(context.Background(), []string{"a.example.com.", "b.example.com."}, domain.TypeA, "1.1")
	if err != nil || len(result) != 1 {
		t.Errorf("unexpected result: %+v, err: %v", result, err)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_GetZoneLongestMatch(t *testing.T) {
	m := new(MockRepo)
	m.On("GetZoneLongestMatch", "www.example.com.").Return(&domain.Zone{ID: "z1", Name: "example.com."}, nil).Once()
	zone, err := m.GetZoneLongestMatch(context.Background(), "www.example.com.")
	if err != nil || zone == nil || zone.ID != "z1" {
		t.Errorf("unexpected result: %+v, err: %v", zone, err)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_GetZoneLongestMatch_NotFound(t *testing.T) {
	m := new(MockRepo)
	m.On("GetZoneLongestMatch", "unknown.example.com.").Return(nil, nil).Once()
	zone, err := m.GetZoneLongestMatch(context.Background(), "unknown.example.com.")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if zone != nil {
		t.Errorf("expected nil, got %+v", zone)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_UpdateRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("UpdateRecord", mock.Anything).Return(nil).Once()
	err := m.UpdateRecord(context.Background(), &domain.Record{ID: "r1"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	m.AssertExpectations(t)
}

func TestMockRepo_ListRecordsForZoneStreaming(t *testing.T) {
	m := new(MockRepo)
	iter :=&mockRecordIterator{records: []domain.Record{{ID: "r1"}}, index: 0}
	m.On("ListRecordsForZoneStreaming", mock.Anything, mock.Anything, mock.Anything).Return(iter, nil).Once()
	result, err := m.ListRecordsForZoneStreaming(context.Background(), "z1", "t1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil iterator")
	}
	m.AssertExpectations(t)
}
