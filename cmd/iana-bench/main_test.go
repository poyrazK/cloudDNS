package main

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRunBench_Errors(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	// 1. Fetch names error
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnError(sqlmock.ErrCancelled)
	err := RunBench(db, "127.0.0.1:10053", 10, 1)
	if err == nil {
		t.Error("Expected error when fetch names fails")
	}

	// 2. No names in DB
	mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(sqlmock.NewRows(nil))
	err = RunBench(db, "127.0.0.1:10053", 10, 1)
	if err == nil {
		t.Error("Expected error when no names found")
	}
}
