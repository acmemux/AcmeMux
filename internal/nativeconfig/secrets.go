package nativeconfig

import (
	"bytes"
	"slices"

	"github.com/acmemux/AcmeMux/internal/integrations"
	"go.yaml.in/yaml/v3"
)

// ObservedSecrets returns bounded defensive copies of manifest-owned YAML
// secret values. Callers use them only to construct an operation redaction
// filter and must clear the returned buffers when the operation is prepared.
// Native selectors and values never cross an HTTP or persistence boundary.
func (e *Engine) ObservedSecrets(source []byte) ([][]byte, error) {
	document, err := parseDocument(source, e.limits)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0)
	var walk func(*yaml.Node, []string)
	walk = func(node *yaml.Node, path []string) {
		if node == nil {
			return
		}
		if node.Kind == yaml.MappingNode {
			for index := 0; index+1 < len(node.Content); index += 2 {
				key, value := node.Content[index], node.Content[index+1]
				if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
					continue
				}
				childPath := appendPath(path, key.Value)
				for _, match := range e.matchingFields(childPath, integrations.TargetYAML) {
					if match.spec.Sensitivity() != integrations.SensitivitySecret ||
						value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
						continue
					}
					candidate := []byte(value.Value)
					duplicate := false
					for _, existing := range result {
						if bytes.Equal(existing, candidate) {
							duplicate = true
							break
						}
					}
					if !duplicate {
						result = append(result, slices.Clone(candidate))
					}
					clear(candidate)
				}
				walk(value, childPath)
			}
			return
		}
		for _, child := range node.Content {
			walk(child, path)
		}
	}
	walk(document.Content[0], nil)
	return result, nil
}
