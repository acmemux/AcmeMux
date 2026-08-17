package reporting

import (
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/inventory"
)

func TestClassifyHealthBoundaries(t *testing.T) {
	now := time.Date(2035, 4, 5, 6, 7, 8, 900, time.UTC)
	tests := []struct {
		name    string
		expires time.Time
		want    Health
	}{
		{"past", now.Add(-time.Nanosecond), HealthExpired},
		{"exact expiration", now, HealthExpired},
		{"one nanosecond remaining", now.Add(time.Nanosecond), HealthExpiring},
		{"exact thirty days", now.Add(ExpiringWindow), HealthExpiring},
		{"beyond thirty days", now.Add(ExpiringWindow + time.Nanosecond), HealthHealthy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.expires, now); got != test.want {
				t.Fatalf("Classify() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProjectInventoryUsesOneUTCObservation(t *testing.T) {
	observed := time.Date(2035, 4, 5, 8, 7, 6, 5, time.FixedZone("local", 2*60*60))
	projection, err := ProjectInventory([]inventory.Certificate{{
		Name: "wildcard", DNSNames: []string{"*.example.test"}, Issuer: "Example CA",
		ExpiresAt: observed.Add(31 * 24 * time.Hour), NativePath: "/srv/lego/certificates/wildcard.crt",
	}}, observed)
	if err != nil {
		t.Fatal(err)
	}
	if projection.ObservedAt.Location() != time.UTC || len(projection.Certificates) != 1 || projection.Certificates[0].Health != HealthHealthy {
		t.Fatalf("projection = %#v", projection)
	}
}
