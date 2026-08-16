package redaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"
)

const replacement = "[REDACTED]"

const (
	defaultMaximumValues     = 128
	maximumAllowedValues     = 1024
	defaultMaximumValueBytes = 64 << 10
	maximumAllowedValueBytes = 1 << 20
	defaultMaximumAggregate  = 1 << 20
	maximumAllowedAggregate  = 4 << 20
	maximumAutomatonStates   = 2 << 20
)

// Policy bounds transient observed-secret state.
type Policy struct {
	MaximumValues         int
	MaximumValueBytes     int
	MaximumAggregateBytes int
}

func DefaultPolicy() Policy {
	return Policy{
		MaximumValues: defaultMaximumValues, MaximumValueBytes: defaultMaximumValueBytes,
		MaximumAggregateBytes: defaultMaximumAggregate,
	}
}

// Filter owns transient copies of observed secret encodings.
type Filter struct {
	nodes       []automatonNode
	edges       []automatonEdge
	root        [256]int32
	replacement []byte
}

type automatonNode struct {
	firstEdge int32
	failure   int32
	matchLen  int32
}

type automatonEdge struct {
	next    int32
	sibling int32
	value   byte
}

// New creates a longest-first exact-value filter. Common URL, base64, and JSON
// encodings are included because upstream errors may transform a credential.
func New(values [][]byte, policy Policy) (*Filter, error) {
	if policy.MaximumValues <= 0 || policy.MaximumValues > maximumAllowedValues ||
		policy.MaximumValueBytes <= 0 || policy.MaximumValueBytes > maximumAllowedValueBytes ||
		policy.MaximumAggregateBytes <= 0 || policy.MaximumAggregateBytes > maximumAllowedAggregate {
		return nil, errors.New("redaction policy is invalid")
	}
	if len(values) > policy.MaximumValues {
		return nil, errors.New("too many redaction values")
	}
	variants := make([][]byte, 0, len(values)*4)
	byDigest := make(map[[sha256.Size]byte][]int)
	aggregateBytes := 0
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if len(value) > policy.MaximumValueBytes {
			for _, owned := range variants {
				clear(owned)
			}
			return nil, errors.New("redaction value is too large")
		}
		encoded := encodedVariants(value)
		for _, variant := range encoded {
			if len(variant) == 0 {
				continue
			}
			digest := sha256.Sum256(variant)
			duplicate := false
			for _, index := range byDigest[digest] {
				if bytes.Equal(variants[index], variant) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if aggregateBytes+len(variant) > policy.MaximumAggregateBytes {
				for _, owned := range variants {
					clear(owned)
				}
				for _, transient := range encoded {
					clear(transient)
				}
				return nil, errors.New("redaction variants are too large")
			}
			owned := bytes.Clone(variant)
			variants = append(variants, owned)
			byDigest[digest] = append(byDigest[digest], len(variants)-1)
			aggregateBytes += len(variant)
		}
		for _, transient := range encoded {
			clear(transient)
		}
	}
	sort.Slice(variants, func(left, right int) bool {
		if len(variants[left]) == len(variants[right]) {
			return bytes.Compare(variants[left], variants[right]) < 0
		}
		return len(variants[left]) > len(variants[right])
	})
	filter, err := buildAutomaton(variants)
	for _, variant := range variants {
		clear(variant)
	}
	if err != nil {
		return nil, err
	}
	filter.replacement = []byte(replacement)
	return filter, nil
}

// Bytes returns a redacted copy and never mutates the input.
func (filter *Filter) Bytes(input []byte) []byte {
	if filter == nil || len(filter.nodes) == 0 {
		return bytes.Clone(input)
	}
	result := make([]byte, 0, len(input))
	states := make([]int32, 0, len(input))
	state := int32(0)
	for _, value := range input {
		state = filter.advance(state, value)
		result = append(result, value)
		states = append(states, state)
		matched := int(filter.nodes[state].matchLen)
		if matched == 0 {
			continue
		}
		result = result[:len(result)-matched]
		states = states[:len(states)-matched]
		state = 0
		if len(states) != 0 {
			state = states[len(states)-1]
		}
	}
	clear(states)
	return result
}

func (filter *Filter) String(input string) string {
	return string(filter.Bytes([]byte(input)))
}

// Fields returns a copy with exact curated sensitive keys replaced. It does
// not guess from key spelling; callers supply the manifest-owned key set.
func (filter *Filter) Fields(input map[string]string, sensitiveKeys []string) map[string]string {
	keys := slices.Clone(sensitiveKeys)
	sort.Strings(keys)
	result := make(map[string]string, len(input))
	for key, value := range input {
		if slices.Contains(keys, key) {
			result[key] = filter.String(string(filter.replacement))
			continue
		}
		result[key] = filter.String(value)
	}
	return result
}

// Clear overwrites package-owned variant copies.
func (filter *Filter) Clear() {
	if filter == nil {
		return
	}
	clear(filter.nodes)
	clear(filter.edges)
	filter.nodes = nil
	filter.edges = nil
	filter.root = [256]int32{}
	clear(filter.replacement)
	filter.replacement = nil
}

func buildAutomaton(patterns [][]byte) (*Filter, error) {
	filter := &Filter{nodes: []automatonNode{{firstEdge: -1}}}
	for index := range filter.root {
		filter.root[index] = -1
	}
	for _, pattern := range patterns {
		state := int32(0)
		for _, value := range pattern {
			next := filter.transition(state, value)
			if next < 0 {
				if len(filter.nodes) >= maximumAutomatonStates || len(filter.edges) >= maximumAutomatonStates {
					filter.Clear()
					return nil, errors.New("redaction automaton is too large")
				}
				next = int32(len(filter.nodes))
				filter.nodes = append(filter.nodes, automatonNode{firstEdge: -1})
				filter.edges = append(filter.edges, automatonEdge{
					next: next, sibling: filter.nodes[state].firstEdge, value: value,
				})
				filter.nodes[state].firstEdge = int32(len(filter.edges) - 1)
				if state == 0 {
					filter.root[value] = next
				}
			}
			state = next
		}
		if int32(len(pattern)) > filter.nodes[state].matchLen {
			filter.nodes[state].matchLen = int32(len(pattern))
		}
	}
	queue := make([]int32, 0, len(filter.nodes))
	for edge := filter.nodes[0].firstEdge; edge >= 0; edge = filter.edges[edge].sibling {
		child := filter.edges[edge].next
		filter.nodes[child].failure = 0
		queue = append(queue, child)
	}
	for position := 0; position < len(queue); position++ {
		parent := queue[position]
		for edge := filter.nodes[parent].firstEdge; edge >= 0; edge = filter.edges[edge].sibling {
			value := filter.edges[edge].value
			child := filter.edges[edge].next
			failure := filter.nodes[parent].failure
			for failure != 0 && filter.transition(failure, value) < 0 {
				failure = filter.nodes[failure].failure
			}
			fallback := filter.transition(failure, value)
			if fallback >= 0 && fallback != child {
				filter.nodes[child].failure = fallback
			}
			inherited := filter.nodes[filter.nodes[child].failure].matchLen
			if inherited > filter.nodes[child].matchLen {
				filter.nodes[child].matchLen = inherited
			}
			queue = append(queue, child)
		}
	}
	clear(queue)
	return filter, nil
}

func (filter *Filter) transition(state int32, value byte) int32 {
	if state == 0 {
		return filter.root[value]
	}
	for edge := filter.nodes[state].firstEdge; edge >= 0; edge = filter.edges[edge].sibling {
		if filter.edges[edge].value == value {
			return filter.edges[edge].next
		}
	}
	return -1
}

func (filter *Filter) advance(state int32, value byte) int32 {
	for {
		if next := filter.transition(state, value); next >= 0 {
			return next
		}
		if state == 0 {
			return 0
		}
		state = filter.nodes[state].failure
	}
}

func encodedVariants(value []byte) [][]byte {
	variants := [][]byte{bytes.Clone(value)}
	text := string(value)
	variants = append(variants,
		[]byte(url.QueryEscape(text)),
		[]byte(url.PathEscape(text)),
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
	)
	if encoded, err := json.Marshal(text); err == nil && len(encoded) >= 2 {
		jsonText := bytes.Clone(encoded[1 : len(encoded)-1])
		variants = append(variants, jsonText)
		if bytes.IndexByte(jsonText, '/') >= 0 {
			variants = append(variants, bytes.ReplaceAll(jsonText, []byte{'/'}, []byte{'\\', '/'}))
		}
	}
	// Some diagnostics use RFC3986 spaces while QueryEscape uses plus.
	variants = append(variants, []byte(strings.ReplaceAll(url.QueryEscape(text), "+", "%20")))
	return variants
}
