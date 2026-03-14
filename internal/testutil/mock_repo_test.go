package testutil

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestMockRepo_GetRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("GetRecords", "test", domain.TypeA, "1.1").Return([]domain.Record{}, nil)
	_, _ = m.GetRecords(context.Background(), "test", domain.TypeA, "1.1")
}

func TestMockRepo_GetIPsForName(t *testing.T) {
	m := new(MockRepo)
	m.On("GetIPsForName", "test", "1.1").Return([]string{"1.2.3.4"}, nil)
	_, _ = m.GetIPsForName(context.Background(), "test", "1.1")
}

func TestMockRepo_GetZone(t *testing.T) {
	m := new(MockRepo)
	m.On("GetZone", "test").Return(&domain.Zone{}, nil)
	_, _ = m.GetZone(context.Background(), "test")
}

func TestMockRepo_GetRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("GetRecord", "id", "zone", "tenant").Return(&domain.Record{}, nil)
	_, _ = m.GetRecord(context.Background(), "id", "zone", "tenant")
}

func TestMockRepo_ListRecordsForZone(t *testing.T) {
	m := new(MockRepo)
	m.On("ListRecordsForZone", "zone", "tenant").Return([]domain.Record{}, nil)
	_, _ = m.ListRecordsForZone(context.Background(), "zone", "tenant")
}

func TestMockRepo_CreateZone(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateZone", &domain.Zone{}).Return(nil)
	_ = m.CreateZone(context.Background(), &domain.Zone{})
}

func TestMockRepo_CreateZoneWithRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateZoneWithRecords", &domain.Zone{}, []domain.Record{}).Return(nil)
	_ = m.CreateZoneWithRecords(context.Background(), &domain.Zone{}, []domain.Record{})
}

func TestMockRepo_CreateRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("CreateRecord", &domain.Record{}).Return(nil)
	_ = m.CreateRecord(context.Background(), &domain.Record{})
}

func TestMockRepo_BatchCreateRecords(t *testing.T) {
	m := new(MockRepo)
	m.On("BatchCreateRecords", []domain.Record{}).Return(nil)
	_ = m.BatchCreateRecords(context.Background(), []domain.Record{})
}

func TestMockRepo_ListZones(t *testing.T) {
	m := new(MockRepo)
	m.On("ListZones", "tenant").Return([]domain.Zone{}, nil)
	_, _ = m.ListZones(context.Background(), "tenant")
}

func TestMockRepo_DeleteZone(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteZone", "zone", "tenant").Return(nil)
	_ = m.DeleteZone(context.Background(), "zone", "tenant")
}

func TestMockRepo_DeleteRecord(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecord", "record", "zone", "tenant").Return(nil)
	_ = m.DeleteRecord(context.Background(), "record", "zone", "tenant")
}

func TestMockRepo_DeleteRecordsByNameAndType(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsByNameAndType", "zone", "name", domain.TypeA).Return(nil)
	_ = m.DeleteRecordsByNameAndType(context.Background(), "zone", "name", domain.TypeA)
}

func TestMockRepo_DeleteRecordsByName(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsByName", "zone", "name").Return(nil)
	_ = m.DeleteRecordsByName(context.Background(), "zone", "name")
}

func TestMockRepo_DeleteRecordSpecific(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordSpecific", "zone", "name", domain.TypeA, "content").Return(nil)
	_ = m.DeleteRecordSpecific(context.Background(), "zone", "name", domain.TypeA, "content")
}

func TestMockRepo_RecordZoneChange(t *testing.T) {
	m := new(MockRepo)
	m.On("RecordZoneChange", &domain.ZoneChange{}).Return(nil)
	_ = m.RecordZoneChange(context.Background(), &domain.ZoneChange{})
}

func TestMockRepo_ListZoneChanges(t *testing.T) {
	m := new(MockRepo)
	m.On("ListZoneChanges", "zone", uint32(1)).Return([]domain.ZoneChange{}, nil)
	_, _ = m.ListZoneChanges(context.Background(), "zone", 1)
}

func TestMockRepo_SaveAuditLog(t *testing.T) {
	m := new(MockRepo)
	m.On("SaveAuditLog", &domain.AuditLog{}).Return(nil)
	_ = m.SaveAuditLog(context.Background(), &domain.AuditLog{})
}

func TestMockRepo_GetIXFRChain(t *testing.T) {
	m := new(MockRepo)
	m.On("GetIXFRChain", "z1", uint32(1), uint32(2)).Return([]domain.IXFRChunk{}, nil)
	_, _ = m.GetIXFRChain(context.Background(), "z1", 1, 2)
}

func TestMockRepo_GetAuditLogs(t *testing.T) {
	m := new(MockRepo)
	m.On("GetAuditLogs", "t1").Return([]domain.AuditLog{}, nil)
	_, _ = m.GetAuditLogs(context.Background(), "t1")
}

func TestMockRepo_Ping(t *testing.T) {
	m := new(MockRepo)
	m.On("Ping").Return(nil)
	_ = m.Ping(context.Background())
}

func TestMockRepo_ApplyZoneUpdate(t *testing.T) {
	m := new(MockRepo)
	m.On("ApplyZoneUpdate", "z1", []domain.UpdateOperation{}, uint32(2), []domain.ZoneChange{}).Return(nil)
	_ = m.ApplyZoneUpdate(context.Background(), "z1", []domain.UpdateOperation{}, 2, []domain.ZoneChange{})
}

func TestMockRepo_DNSSECKeys(t *testing.T) {
	m := new(MockRepo)
	key := &domain.DNSSECKey{ID: "k1"}
	m.On("CreateKey", key).Return(nil)
	_ = m.CreateKey(context.Background(), key)

	m.On("ListKeysForZone", "z1").Return([]domain.DNSSECKey{}, nil)
	_, _ = m.ListKeysForZone(context.Background(), "z1")

	m.On("UpdateKey", key).Return(nil)
	_ = m.UpdateKey(context.Background(), key)
}

func TestMockRepo_APIKeys(t *testing.T) {
	m := new(MockRepo)
	key := &domain.APIKey{ID: "ak1"}
	m.On("GetAPIKeyByHash", "h1").Return(key, nil)
	_, _ = m.GetAPIKeyByHash(context.Background(), "h1")

	m.On("CreateAPIKey", key).Return(nil)
	_ = m.CreateAPIKey(context.Background(), key)

	m.On("ListAPIKeys", "t1").Return([]domain.APIKey{}, nil)
	_, _ = m.ListAPIKeys(context.Background(), "t1")

	m.On("DeleteAPIKey", "t1", "ak1").Return(nil)
	_ = m.DeleteAPIKey(context.Background(), "t1", "ak1")
}

func TestMockRepo_Health(t *testing.T) {
	m := new(MockRepo)
	ctx := context.Background()
	m.On("UpdateRecordHealth", ctx, "r1", domain.HealthStatusHealthy, "ok").Return(nil)
	_ = m.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "ok")

	m.On("GetRecordsToProbe", ctx).Return([]domain.Record{}, nil)
	_, _ = m.GetRecordsToProbe(ctx)
}

func TestMockRepo_DeleteRecordsForZone(t *testing.T) {
	m := new(MockRepo)
	m.On("DeleteRecordsForZone", "z1").Return(nil)
	_ = m.DeleteRecordsForZone(context.Background(), "z1")
}

func TestMockDNSService(t *testing.T) {
	m := new(MockDNSService)
	ctx := context.Background()
	
	m.On("CreateZone", &domain.Zone{}).Return(nil)
	_ = m.CreateZone(ctx, &domain.Zone{})

	m.On("CreateRecord", &domain.Record{}).Return(nil)
	_ = m.CreateRecord(ctx, &domain.Record{})

	m.On("Resolve", "test.", domain.TypeA, "1.1").Return([]domain.Record{}, nil)
	_, _ = m.Resolve(ctx, "test.", domain.TypeA, "1.1")

	m.On("GetRecordsToProbe").Return([]domain.Record{}, nil)
	_, _ = m.GetRecordsToProbe(ctx)

	m.On("UpdateRecordHealth", "r1", domain.HealthStatusHealthy, "ok").Return(nil)
	_ = m.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "ok")

	m.On("ListZones", "t1").Return([]domain.Zone{}, nil)
	_, _ = m.ListZones(ctx, "t1")

	m.On("ListRecordsForZone", "z1", "t1").Return([]domain.Record{}, nil)
	_, _ = m.ListRecordsForZone(ctx, "z1", "t1")

	m.On("DeleteZone", "z1", "t1").Return(nil)
	_ = m.DeleteZone(ctx, "z1", "t1")

	m.On("DeleteRecord", "r1", "z1", "t1").Return(nil)
	_ = m.DeleteRecord(ctx, "r1", "z1", "t1")

	m.On("ImportZone", "t1", nil).Return(&domain.Zone{}, nil)
	_, _ = m.ImportZone(ctx, "t1", nil)

	m.On("ListAuditLogs", "t1").Return([]domain.AuditLog{}, nil)
	_, _ = m.ListAuditLogs(ctx, "t1")

	m.On("HealthCheck").Return(map[string]error{})
	_ = m.HealthCheck(ctx)
}
