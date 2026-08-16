package reporting

import (
	"strings"
	"testing"

	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
)

func TestPresentStateCoversEveryTerminalState(t *testing.T) {
	states := []jobs.State{jobs.StateSucceeded, jobs.StateFailed, jobs.StatePartial, jobs.StateNotAttempted, jobs.StateTimedOut, jobs.StateInterrupted, jobs.StateIncompatible, jobs.StateAmbiguous}
	for _, state := range states {
		presentation, ok := PresentState(state)
		if !ok || presentation.Label == "" || presentation.Summary == "" || presentation.NextAction == "" {
			t.Fatalf("state %q presentation = %#v, %v", state, presentation, ok)
		}
	}
}

func TestRenderOutputBoundsSanitizesAndRedactsRepeatedFields(t *testing.T) {
	input := "token=first\nAUTHORIZATION: Bearer-second\nclient_secret=third\ntoken=first\u202e"
	output := RenderOutput(input)
	for _, secret := range []string{"first", "Bearer-second", "third"} {
		if strings.Contains(output, secret) {
			t.Fatalf("rendered output contains %q: %q", secret, output)
		}
	}
	if strings.Count(output, "[REDACTED]") != 4 || strings.ContainsRune(output, '\u202e') {
		t.Fatalf("rendered output = %q", output)
	}
}
