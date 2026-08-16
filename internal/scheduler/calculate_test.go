package scheduler

import (
	"testing"
	"time"
)

func TestNextOccurrenceHandlesDailyZonesAndDaylightSaving(t *testing.T) {
	t.Parallel()
	denver, err := time.LoadLocation("America/Denver")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		after  time.Time
		minute int
		want   time.Time
	}{
		{
			name:  "spring gap advances to first valid minute",
			after: time.Date(2026, 3, 8, 8, 0, 0, 0, time.UTC), minute: 2*60 + 30,
			want: time.Date(2026, 3, 8, 9, 0, 0, 0, time.UTC),
		},
		{
			name:  "fall repetition uses earlier instant",
			after: time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC), minute: 1*60 + 30,
			want: time.Date(2026, 11, 1, 7, 30, 0, 0, time.UTC),
		},
		{
			name:  "completed local occurrence advances one date",
			after: time.Date(2026, 11, 1, 7, 30, 0, 0, time.UTC), minute: 1*60 + 30,
			want: time.Date(2026, 11, 2, 8, 30, 0, 0, time.UTC),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := nextOccurrence(test.after, denver, test.minute)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(test.want) {
				t.Fatalf("next occurrence = %s, want %s", got, test.want)
			}
		})
	}
}

func TestValidateUpdateRejectsUnsafeOrUnavailableZones(t *testing.T) {
	t.Parallel()
	for _, zone := range []string{"", "Local", "../UTC", "America//Denver", "Not/A_Real_Zone"} {
		if _, err := validateUpdate(Update{Enabled: true, TimeZone: zone, LocalMinute: 215}); err == nil {
			t.Fatalf("zone %q was accepted", zone)
		}
	}
}
