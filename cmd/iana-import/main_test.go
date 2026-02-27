package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/testutil"
	"github.com/stretchr/testify/mock"
)

func TestRunImport_BadURL(t *testing.T) {
	err := RunImport(context.Background(), nil, "http://invalid.url.test")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestRunImport_BadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	err := RunImport(context.Background(), nil, ts.URL)
	if err == nil {
		t.Error("Expected error for 404 status")
	}
}

func TestRunImport_EmptyDB(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(". 3600 IN SOA ns. ns. 1 2 3 4 5"))
	}))
	defer ts.Close()

	mRepo := new(testutil.MockRepo)

	// Mocking GetZone returning nil to trigger CreateZone
	mRepo.On("GetZone", ".").Return((*domain.Zone)(nil), nil)

	// Fail on CreateZone to test error path
	mRepo.On("CreateZone", mock.AnythingOfType("*domain.Zone")).Return(errors.New("db error"))

	err := RunImport(context.Background(), mRepo, ts.URL)
	if err == nil {
		t.Error("Expected error from CreateZone failure")
	}
}

func TestRunImport_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(". 3600 IN SOA ns. ns. 1 2 3 4 5\n. 3600 IN A 1.2.3.4"))
	}))
	defer ts.Close()

	mRepo := new(testutil.MockRepo)

	existingZone := &domain.Zone{ID: "z1", Name: "."}
	mRepo.On("GetZone", ".").Return(existingZone, nil)

	mRepo.On("BatchCreateRecords", mock.AnythingOfType("[]domain.Record")).Return(nil)

	err := RunImport(context.Background(), mRepo, ts.URL)
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	mRepo.AssertExpectations(t)
}
