package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/scheduler"
)

var localTimePattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

type automaticScheduleResponse struct {
	State            string  `json:"state"`
	Enabled          bool    `json:"enabled"`
	TimeZone         *string `json:"timeZone"`
	LocalTime        *string `json:"localTime"`
	NextEvaluationAt *string `json:"nextEvaluationAt"`
	LastTriggeredAt  *string `json:"lastTriggeredAt"`
	ReasonCode       string  `json:"reasonCode"`
}

type automaticScheduleRequest struct {
	Enabled   bool
	TimeZone  string
	LocalTime string
}

func (endpoints *operationEndpoints) getAutomaticSchedule(response http.ResponseWriter, request *http.Request) {
	if _, ok := endpoints.authorize(response, request, false); !ok {
		return
	}
	value, err := endpoints.scheduler.Get(request.Context())
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	presented, ok := presentAutomaticSchedule(value)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func (endpoints *operationEndpoints) updateAutomaticSchedule(response http.ResponseWriter, request *http.Request) {
	authorization, ok := endpoints.authorize(response, request, true)
	if !ok {
		return
	}
	payload, ok := readAutomaticScheduleRequest(response, request)
	if !ok {
		return
	}
	if !endpoints.reauthorizeMutation(response, request, authorization) {
		return
	}
	minute := int(payload.LocalTime[0]-'0')*600 + int(payload.LocalTime[1]-'0')*60 +
		int(payload.LocalTime[3]-'0')*10 + int(payload.LocalTime[4]-'0')
	value, err := endpoints.scheduler.Update(request.Context(), scheduler.Update{
		Enabled: payload.Enabled, TimeZone: payload.TimeZone, LocalMinute: minute,
	})
	if errors.Is(err, scheduler.ErrInvalid) {
		writeInvalidScheduleRequest(response)
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	presented, ok := presentAutomaticSchedule(value)
	if !ok {
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, presented)
}

func presentAutomaticSchedule(value scheduler.Schedule) (automaticScheduleResponse, bool) {
	if value.State != scheduler.StateDisabled && value.State != scheduler.StateScheduled && value.State != scheduler.StateDue &&
		value.State != scheduler.StateDeferred && value.State != scheduler.StateBlocked || !validOperationText(value.ReasonCode, 64, false) {
		return automaticScheduleResponse{}, false
	}
	result := automaticScheduleResponse{State: string(value.State), Enabled: value.Enabled, ReasonCode: value.ReasonCode}
	if !value.Configured {
		return result, !value.Enabled && value.State == scheduler.StateDisabled
	}
	if !validOperationText(value.TimeZone, 128, false) || !localTimePattern.MatchString(value.LocalTime()) {
		return automaticScheduleResponse{}, false
	}
	zone, local := value.TimeZone, value.LocalTime()
	result.TimeZone, result.LocalTime = &zone, &local
	if value.Enabled {
		if value.NextEvaluation.IsZero() {
			return automaticScheduleResponse{}, false
		}
		formatted := value.NextEvaluation.UTC().Format(time.RFC3339Nano)
		result.NextEvaluationAt = &formatted
	}
	if !value.LastTriggeredAt.IsZero() {
		formatted := value.LastTriggeredAt.UTC().Format(time.RFC3339Nano)
		result.LastTriggeredAt = &formatted
	}
	return result, true
}

func readAutomaticScheduleRequest(response http.ResponseWriter, request *http.Request) (automaticScheduleRequest, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return automaticScheduleRequest{}, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumOperationRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeOperationJSONError(response, err)
		return automaticScheduleRequest{}, false
	}
	defer clear(body)
	if !utf8.Valid(body) {
		writeInvalidScheduleRequest(response)
		return automaticScheduleRequest{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		writeInvalidScheduleRequest(response)
		return automaticScheduleRequest{}, false
	}
	seen := map[string]bool{}
	var result automaticScheduleRequest
	for decoder.More() {
		keyToken, keyErr := decoder.Token()
		key, keyOK := keyToken.(string)
		if keyErr != nil || !keyOK || seen[key] {
			writeInvalidScheduleRequest(response)
			return automaticScheduleRequest{}, false
		}
		seen[key] = true
		switch key {
		case "enabled":
			err = decoder.Decode(&result.Enabled)
		case "timeZone":
			err = decoder.Decode(&result.TimeZone)
		case "localTime":
			err = decoder.Decode(&result.LocalTime)
		default:
			err = errors.New("unknown schedule field")
		}
		if err != nil {
			writeInvalidScheduleRequest(response)
			return automaticScheduleRequest{}, false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 3 || !seen["enabled"] || !seen["timeZone"] ||
		!seen["localTime"] || !validOperationText(result.TimeZone, 128, false) || !localTimePattern.MatchString(result.LocalTime) {
		writeInvalidScheduleRequest(response)
		return automaticScheduleRequest{}, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeInvalidScheduleRequest(response)
		return automaticScheduleRequest{}, false
	}
	return result, true
}

func writeInvalidScheduleRequest(response http.ResponseWriter) {
	writeAPIError(response, http.StatusBadRequest, "invalid_request", "The automatic schedule request is invalid.")
}
