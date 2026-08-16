package nativeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

var standardTags = map[string]struct{}{
	"":            {},
	"!!map":       {},
	"!!seq":       {},
	"!!str":       {},
	"!!bool":      {},
	"!!int":       {},
	"!!float":     {},
	"!!null":      {},
	"!!timestamp": {},
}

func parseDocument(source []byte, limits Limits) (*yaml.Node, error) {
	if len(source) == 0 {
		return nil, &Error{Code: ErrorSourceEmpty, Detail: "configuration is empty"}
	}
	if len(source) > limits.MaxBytes {
		return nil, &Error{Code: ErrorSourceTooLarge, Detail: "configuration exceeds the byte limit"}
	}
	if !utf8.Valid(source) {
		return nil, &Error{Code: ErrorInvalidUTF8, Detail: "configuration is not valid UTF-8"}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &Error{Code: ErrorSourceEmpty, Detail: "configuration has no YAML document"}
		}
		return nil, &Error{Code: ErrorMalformedYAML, Detail: "configuration is not valid YAML"}
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, &Error{Code: ErrorMalformedYAML, Detail: "configuration has malformed trailing YAML"}
		}
		return nil, &Error{Code: ErrorMultipleDocuments, Detail: "configuration must contain exactly one YAML document"}
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, &Error{Code: ErrorRootNotMapping, Detail: "configuration root must be a mapping"}
	}
	if err := validateNode(&document, limits); err != nil {
		return nil, err
	}
	return &document, nil
}

func validateNode(document *yaml.Node, limits Limits) error {
	type pending struct {
		node  *yaml.Node
		depth int
	}
	stack := []pending{{node: document, depth: 0}}
	count := 0
	for len(stack) > 0 {
		last := len(stack) - 1
		item := stack[last]
		stack = stack[:last]
		count++
		if count > limits.MaxNodes || item.depth > limits.MaxDepth {
			return &Error{Code: ErrorStructureComplex, Detail: "configuration structure exceeds its complexity limit"}
		}
		if item.node.Kind == yaml.AliasNode || item.node.Alias != nil {
			return &Error{Code: ErrorAliasUnsupported, Detail: "YAML aliases are not supported"}
		}
		if _, allowed := standardTags[item.node.Tag]; !allowed {
			return &Error{Code: ErrorTagUnsupported, Detail: "custom YAML tags are not supported"}
		}
		if item.node.Kind == yaml.MappingNode {
			if len(item.node.Content)%2 != 0 {
				return &Error{Code: ErrorMalformedYAML, Detail: "configuration contains an invalid mapping"}
			}
			seen := make(map[string]struct{}, len(item.node.Content)/2)
			for index := 0; index < len(item.node.Content); index += 2 {
				key := item.node.Content[index]
				if key.Value == "<<" || key.Tag == "!!merge" {
					return &Error{Code: ErrorMergeUnsupported, Detail: "YAML merge keys are not supported"}
				}
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					return &Error{Code: ErrorMalformedYAML, Detail: "mapping keys must be strings"}
				}
				if _, duplicate := seen[key.Value]; duplicate {
					return &Error{Code: ErrorDuplicateKey, Detail: "configuration contains a duplicate mapping key"}
				}
				seen[key.Value] = struct{}{}
			}
		}
		for index := len(item.node.Content) - 1; index >= 0; index-- {
			stack = append(stack, pending{node: item.node.Content[index], depth: item.depth + 1})
		}
	}
	return nil
}

func cloneNode(source *yaml.Node) *yaml.Node {
	if source == nil {
		return nil
	}
	result := *source
	result.Content = make([]*yaml.Node, len(source.Content))
	for index, child := range source.Content {
		result.Content[index] = cloneNode(child)
	}
	result.Alias = nil
	return &result
}

func encodeDocument(document *yaml.Node) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode candidate: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close candidate encoder: %w", err)
	}
	return output.Bytes(), nil
}

func mappingValue(mapping *yaml.Node, key string) (*yaml.Node, int, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, -1, false
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1], index, true
		}
	}
	return nil, -1, false
}

func nodeAtPath(root *yaml.Node, path []string) (*yaml.Node, bool) {
	if root != nil && root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	current := root
	for _, key := range path {
		value, _, ok := mappingValue(current, key)
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func setNodeAtPath(document *yaml.Node, path []string, value *yaml.Node, forceReplacement bool) (before *yaml.Node, changed bool, err error) {
	if len(path) == 0 || document == nil || len(document.Content) != 1 {
		return nil, false, &Error{Code: ErrorInvalidChange, Detail: "field selector is invalid"}
	}
	current := document.Content[0]
	for _, key := range path[:len(path)-1] {
		next, _, found := mappingValue(current, key)
		if found {
			if next.Kind != yaml.MappingNode {
				return nil, false, &Error{Code: ErrorInvalidChange, Detail: "field parent is not a mapping"}
			}
			current = next
			continue
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
		next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		current.Content = append(current.Content, keyNode, next)
		current = next
	}
	key := path[len(path)-1]
	existing, keyIndex, found := mappingValue(current, key)
	if found {
		// Secret sets deliberately avoid an equality comparison. A write-only
		// field must take the same reviewed write path whether the submitted
		// value matches the native value or not.
		if !forceReplacement && equalNodeValue(existing, value) {
			return cloneNode(existing), false, nil
		}
		before = cloneNode(existing)
		// Retain comments, anchor and presentation style attached to the edited
		// position while replacing only its typed value.
		value.HeadComment = existing.HeadComment
		value.LineComment = existing.LineComment
		value.FootComment = existing.FootComment
		value.Anchor = existing.Anchor
		if forceReplacement && value.Kind == yaml.ScalarNode && value.Tag == "!!str" {
			// Force a byte-level rewrite even when the confidential scalar is
			// semantically unchanged. Toggling between safe string styles keeps
			// same- and different-value secret submissions indistinguishable to
			// the caller without exposing or comparing the native value.
			if existing.Style == yaml.SingleQuotedStyle {
				value.Style = yaml.DoubleQuotedStyle
			} else {
				value.Style = yaml.SingleQuotedStyle
			}
		} else if value.Kind == existing.Kind {
			value.Style = existing.Style
		}
		current.Content[keyIndex+1] = value
		return before, true, nil
	}
	current.Content = append(current.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
	return nil, true, nil
}

func removeNodeAtPath(document *yaml.Node, path []string) (before *yaml.Node, changed bool, err error) {
	if len(path) == 0 || document == nil || len(document.Content) != 1 {
		return nil, false, &Error{Code: ErrorInvalidChange, Detail: "field selector is invalid"}
	}
	current := document.Content[0]
	for _, key := range path[:len(path)-1] {
		next, _, found := mappingValue(current, key)
		if !found {
			return nil, false, nil
		}
		if next.Kind != yaml.MappingNode {
			return nil, false, &Error{Code: ErrorInvalidChange, Detail: "field parent is not a mapping"}
		}
		current = next
	}
	_, keyIndex, found := mappingValue(current, path[len(path)-1])
	if !found {
		return nil, false, nil
	}
	before = cloneNode(current.Content[keyIndex+1])
	current.Content = slices.Delete(current.Content, keyIndex, keyIndex+2)
	return before, true, nil
}

func equalNodeValue(left, right *yaml.Node) bool {
	if left == nil || right == nil || left.Kind != right.Kind || left.Tag != right.Tag || left.Value != right.Value || len(left.Content) != len(right.Content) {
		return false
	}
	for index := range left.Content {
		if !equalNodeValue(left.Content[index], right.Content[index]) {
			return false
		}
	}
	return true
}

func nodeToAny(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			value, err := nodeToAny(node.Content[index+1])
			if err != nil {
				return nil, err
			}
			result[node.Content[index].Value] = value
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for index, child := range node.Content {
			value, err := nodeToAny(child)
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!timestamp":
			return node.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			var value bool
			if err := node.Decode(&value); err != nil {
				return nil, err
			}
			return value, nil
		case "!!int":
			var signed int64
			if err := node.Decode(&signed); err == nil {
				return signed, nil
			}
			var unsigned uint64
			if err := node.Decode(&unsigned); err != nil {
				return nil, err
			}
			return unsigned, nil
		case "!!float":
			var value float64
			if err := node.Decode(&value); err != nil {
				return nil, err
			}
			return value, nil
		}
	}
	return nil, fmt.Errorf("unsupported YAML node")
}

func valueNode(value any) *yaml.Node {
	node := &yaml.Node{}
	_ = node.Encode(value)
	return node
}

func pointer(path []string) string {
	if len(path) == 0 {
		return "/"
	}
	parts := make([]string, len(path))
	for index, part := range path {
		part = strings.ReplaceAll(part, "~", "~0")
		parts[index] = strings.ReplaceAll(part, "/", "~1")
	}
	return "/" + strings.Join(parts, "/")
}

func position(document *yaml.Node, path []string) (int, int) {
	node, ok := nodeAtPath(document, path)
	if !ok {
		return 0, 0
	}
	return node.Line, node.Column
}
