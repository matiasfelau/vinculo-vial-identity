package domain_test

import (
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-identity/internal/domain"
)

func TestHasFraudReasonCode(t *testing.T) {
	casos := []struct {
		nombre string
		codes  []string
		want   bool
	}{
		{"NO_VEHICLE", []string{"NO_VEHICLE"}, true},
		{"BURST_MISMATCH", []string{"BURST_MISMATCH"}, true},
		{"PLATE_MISMATCH", []string{"PLATE_MISMATCH"}, true},
		{"fraude entre otros códigos", []string{"EVIDENCE_UNREADABLE", "PLATE_MISMATCH"}, true},
		// RED pero sin culpa del emisor: no penaliza.
		{"EVIDENCE_UNREADABLE solo", []string{"EVIDENCE_UNREADABLE"}, false},
		{"códigos YELLOW", []string{"PLATE_FUZZY", "BURST_UNCERTAIN", "CONTEXT_UNCERTAIN"}, false},
		{"código desconocido", []string{"OTRO"}, false},
		{"minúsculas no coinciden", []string{"no_vehicle"}, false},
		{"sin códigos", nil, false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := domain.HasFraudReasonCode(c.codes); got != c.want {
				t.Errorf("HasFraudReasonCode(%v) = %v, se esperaba %v", c.codes, got, c.want)
			}
		})
	}
}

func TestNewUserNaceConReputacionYReportesEnCero(t *testing.T) {
	u, err := domain.NewUser("a@b.com", "hash", "dni-hash", "dni-enc", time.Now())
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if u.ReputationScore != 0 || u.ReportCount != 0 {
		t.Errorf("reputation_score=%d report_count=%d, se esperaba 0 y 0", u.ReputationScore, u.ReportCount)
	}
}
