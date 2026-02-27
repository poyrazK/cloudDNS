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
	m.On("GetRecord", "id", "zone").Return(&domain.Record{}, nil)
	_, _ = m.GetRecord(context.Background(), "id", "zone")
}

func TestMockRepo_ListRecordsForZone(t *testing.T) {
	m := new(MockRepo)
	m.On("ListRecordsForZone", "zone").Return([]domain.Record{}, nil)
	_, _ = m.ListRecordsForZone(context.Background(), "zone")
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
	m.On("DeleteRecord", "record", "zone").Return(nil)
	_ = m.DeleteRecord(context.Background(), "record", "zone")
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
