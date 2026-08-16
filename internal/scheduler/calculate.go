package scheduler

import (
	"errors"
	"fmt"
	"time"

	_ "time/tzdata"
)

// nextOccurrence returns the first daily wall-clock occurrence strictly after
// the supplied UTC instant. Searching actual instants makes DST gaps advance
// to the first valid minute and DST repetitions choose the earlier instant.
func nextOccurrence(after time.Time, location *time.Location, localMinute int) (time.Time, error) {
	if err := canonicalInstant(after, true); err != nil || location == nil || localMinute < 0 || localMinute >= minutesPerDay {
		return time.Time{}, errors.New("daily schedule calculation is invalid")
	}
	local := after.In(location)
	date := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
	for offset := 0; offset < 370; offset++ {
		candidateDate := date.AddDate(0, 0, offset)
		candidate, err := occurrenceOnDate(candidateDate.Year(), candidateDate.Month(), candidateDate.Day(), location, localMinute)
		if err != nil {
			return time.Time{}, err
		}
		if candidate.After(after) {
			return candidate, nil
		}
	}
	return time.Time{}, errors.New("daily schedule has no bounded next occurrence")
}

func occurrenceOnDate(year int, month time.Month, day int, location *time.Location, localMinute int) (time.Time, error) {
	// Every IANA civil day is contained in this UTC window, including unusual
	// historical offset transitions. Minute resolution is the product contract.
	start := time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Add(-24 * time.Hour)
	end := start.Add(72 * time.Hour)
	for instant := start; instant.Before(end); instant = instant.Add(time.Minute) {
		local := instant.In(location)
		if local.Year() != year || local.Month() != month || local.Day() != day || local.Second() != 0 {
			continue
		}
		if local.Hour()*60+local.Minute() >= localMinute {
			return instant.UTC().Round(0), nil
		}
	}
	return time.Time{}, fmt.Errorf("IANA time zone has no valid instant for %04d-%02d-%02d", year, month, day)
}

func occurrenceLocalDate(occurrence time.Time, location *time.Location) string {
	return occurrence.In(location).Format("2006-01-02")
}
