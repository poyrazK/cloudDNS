package metrics

import (
	"testing"
)

func TestMetricsDeclarations(t *testing.T) {
	tests := []struct {
		name   string
		metric interface{}
	}{
		{"QueriesTotal", QueriesTotal},
		{"QueryDuration", QueryDuration},
		{"CacheOperations", CacheOperations},
		{"ActiveWorkers", ActiveWorkers},
		{"DBConnectionsActive", DBConnectionsActive},
		{"BGPAnnounced", BGPAnnounced},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.metric == nil {
				t.Errorf("%s is nil", tt.name)
			}
		})
	}
}
