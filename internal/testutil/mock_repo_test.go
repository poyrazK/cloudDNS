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
	m.On("ApplyZoneUpdate", "z1", mock.Anything, uint32(2), mock.Anything).Return(nil)
	err := m.ApplyZoneUpdate(context.Background(), "z1", []domain.UpdateOperation{}, 2, []domain.ZoneChange{})
	if err != nil {
		t.Errorf("Mock failed")
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

	m.On("GetRecordsToProbe", mock.Anything).Return([]domain.Record{{ID: "r1"}}, nil)
	probes, err := m.GetRecordsToProbe(context.Background())
	if err != nil || len(probes) != 1 { t.Errorf("GetRecordsToProbe failed") }
}

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

	m.On("GetRecordsToProbe").Return([]domain.Record{{ID: "r1"}}, nil)
	probes, err := m.GetRecordsToProbe(ctx)
	if err != nil || len(probes) != 1 { t.Errorf("GetRecordsToProbe failed") }

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
