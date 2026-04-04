package metrics

import (
	"testing"
)

func TestMetricsDeclarations(t *testing.T) {
	// Simply touch the variables to ensure they are initialized and counted in coverage
	if QueriesTotal == nil {
		t.Error("QueriesTotal is nil")
	}
	if QueryDuration == nil {
		t.Error("QueryDuration is nil")
	}
	if CacheOperations == nil {
		t.Error("CacheOperations is nil")
	}
	if ActiveWorkers == nil {
		t.Error("ActiveWorkers is nil")
	}
	if DBConnectionsActive == nil {
		t.Error("DBConnectionsActive is nil")
	}
	if BGPAnnounced == nil {
		t.Error("BGPAnnounced is nil")
	}
}
