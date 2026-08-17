package reporting

import (
	"errors"
	"slices"
	"time"

	"github.com/acmemux/AcmeMux/internal/inventory"
)

const ExpiringWindow = 30 * 24 * time.Hour

type Health string

const (
	HealthHealthy  Health = "healthy"
	HealthExpiring Health = "expiring"
	HealthExpired  Health = "expired"
)

type Certificate struct {
	inventory.Certificate
	Health Health
}

type Inventory struct {
	ObservedAt   time.Time
	Certificates []Certificate
}

func Classify(expiresAt, observedAt time.Time) Health {
	if !expiresAt.After(observedAt) {
		return HealthExpired
	}
	if expiresAt.Sub(observedAt) <= ExpiringWindow {
		return HealthExpiring
	}
	return HealthHealthy
}

func ProjectInventory(certificates []inventory.Certificate, observedAt time.Time) (Inventory, error) {
	observedAt = observedAt.UTC().Round(0)
	if observedAt.IsZero() || observedAt.Year() < 1 || observedAt.Year() > 9999 {
		return Inventory{}, errors.New("inventory observation time is invalid")
	}
	projected := make([]Certificate, len(certificates))
	for index, certificate := range certificates {
		if certificate.Name == "" || certificate.ExpiresAt.IsZero() {
			return Inventory{}, errors.New("certificate evidence is invalid")
		}
		certificate.DNSNames = slices.Clone(certificate.DNSNames)
		certificate.ExpiresAt = certificate.ExpiresAt.UTC().Round(0)
		projected[index] = Certificate{
			Certificate: certificate,
			Health:      Classify(certificate.ExpiresAt, observedAt),
		}
	}
	return Inventory{ObservedAt: observedAt, Certificates: projected}, nil
}
