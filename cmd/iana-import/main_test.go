package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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

	db, mock, _ := sqlmock.New()
	defer db.Close()

	// Mocking GetZone returning error or nil to trigger CreateZone
	mock.ExpectQuery("SELECT .* FROM dns_zones").WillReturnRows(sqlmock.NewRows(nil))
	// Fail on CreateZone to test error path
	mock.ExpectExec("INSERT INTO dns_zones").WillReturnError(sqlmock.ErrCancelled)

	err := RunImport(context.Background(), db, ts.URL)
	if err == nil {
		t.Error("Expected error from CreateZone failure")
	}
}
