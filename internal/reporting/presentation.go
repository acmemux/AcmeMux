package reporting

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
)

const maximumRenderedOutput = 256 << 10

var sensitiveAssignment = regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:token|secret|password|hmac|api_key|access_key|authorization)[a-z0-9_]*)[ \t]*([:=])[ \t]*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)

type StatePresentation struct {
	Label      string
	Summary    string
	NextAction string
}

func PresentState(state jobs.State) (StatePresentation, bool) {
	switch state {
	case jobs.StateSucceeded:
		return StatePresentation{"Succeeded", "Upstream lego completed the native workspace evaluation.", "Review current certificate health and no further action is required unless the inventory needs attention."}, true
	case jobs.StateFailed:
		return StatePresentation{"Failed", "Upstream lego reported a failure and later certificate work may not have been attempted.", "Review certificate-level evidence, the refreshed inventory, and the redacted transcript before deciding whether to run again."}, true
	case jobs.StatePartial:
		return StatePresentation{"Partially completed", "Some certificate work completed before upstream lego stopped or failed.", "Review completed, failed, and ambiguous certificates with current native inventory before deciding whether to run again."}, true
	case jobs.StateNotAttempted:
		return StatePresentation{"Not attempted", "The native lego process was not started.", "Resolve the reported runtime, workspace, configuration, or contention condition and prepare a fresh review."}, true
	case jobs.StateTimedOut:
		return StatePresentation{"Timed out", "The bounded operation exceeded its execution deadline and external state may have changed.", "Inspect refreshed native evidence and provider state; do not retry blindly."}, true
	case jobs.StateInterrupted:
		return StatePresentation{"Interrupted", "Service lifetime ended while the operation was running and the operation was not replayed.", "Inspect refreshed native evidence and provider state; prepare a new operation only after the result is understood."}, true
	case jobs.StateIncompatible:
		return StatePresentation{"Incompatible", "The reviewed runtime or native configuration is outside the supported execution boundary.", "Adopt an exact supported lego runtime or change the preserved native configuration to supported choices."}, true
	case jobs.StateAmbiguous:
		return StatePresentation{"Outcome ambiguous", "Available evidence cannot prove one complete native or external outcome.", "Inspect refreshed native evidence and provider state; do not retry blindly."}, true
	default:
		return StatePresentation{}, false
	}
}

// RenderOutput applies a second bounded sanitization and sensitive-field pass
// immediately before upstream text crosses the presentation boundary.
func RenderOutput(value string) string {
	if len(value) > maximumRenderedOutput {
		value = value[:maximumRenderedOutput]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	var builder strings.Builder
	builder.Grow(len(value))
	for len(value) > 0 {
		character, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		if character == utf8.RuneError && size == 1 {
			builder.WriteByte('?')
			continue
		}
		if character != '\n' && character != '\r' && character != '\t' && (unicode.IsControl(character) || unicode.In(character, unicode.Cf)) {
			builder.WriteByte('?')
			continue
		}
		builder.WriteRune(character)
	}
	return sensitiveAssignment.ReplaceAllString(builder.String(), "$1$2[REDACTED]")
}
