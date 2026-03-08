package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServer_RunContextCancel(t *testing.T) {
	// Use an ephemeral port
	srv := NewServer("127.0.0.1:0", nil, nil)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Run(ctx)
	}()

	// Let it start
	time.Sleep(100 * time.Millisecond)
	
	// Cancel context
	cancel()
	
	select {
	case err := <-errChan:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Errorf("Server.Run did not return after context cancellation")
	}
}

func TestServer_Run_NoUDP(t *testing.T) {
	// Invalid address should cause started == 0
	srv := NewServer("999.999.999.999:53", nil, nil)
	ctx := context.Background()
	err := srv.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start any UDP listeners")
}
