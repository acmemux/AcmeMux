package workspace

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

type nativeReferences struct {
	storage  pathReference
	dotenv   []pathReference
	webroots []pathReference
}

type pathReference struct {
	raw      string
	resolved string
}

func readNativeReferences(ctx context.Context, file *os.File, evidence PathEvidence, workingDirectory string, policy Policy) (nativeReferences, []Diagnostic) {
	if file == nil {
		return nativeReferences{}, nil
	}
	if evidence.Size < 0 || evidence.Size > policy.MaxConfigurationBytes {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationTooLarge, RoleConfiguration, evidence.Path, evidence.Path,
			"configuration exceeds the inspection size limit")}
	}
	before, err := fstat(int(file.Fd()))
	if err != nil {
		return nativeReferences{}, []Diagnostic{diagnostic(CodePathUnavailable, RoleConfiguration, evidence.Path, evidence.Path,
			"configuration metadata could not be rechecked")}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nativeReferences{}, []Diagnostic{diagnostic(CodePathNotReadable, RoleConfiguration, evidence.Path, evidence.Path,
			"configuration could not be read")}
	}
	limited := io.LimitReader(&contextReader{context: ctx, reader: file}, policy.MaxConfigurationBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		code := CodePathNotReadable
		detail := "configuration could not be read"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code = CodeInspectionCanceled
			detail = "inspection was canceled"
		}
		return nativeReferences{}, []Diagnostic{diagnostic(code, RoleConfiguration, evidence.Path, evidence.Path, detail)}
	}
	defer clear(data)
	if int64(len(data)) > policy.MaxConfigurationBytes {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationTooLarge, RoleConfiguration, evidence.Path, evidence.Path,
			"configuration exceeds the inspection size limit")}
	}
	after, err := fstat(int(file.Fd()))
	if err != nil || !sameStableStat(before, after) || int64(len(data)) != before.Size {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeChangedDuringInspection, RoleConfiguration, evidence.Path, evidence.Path,
			"configuration changed while it was read")}
	}
	return parseNativeReferences(data, evidence.Path, workingDirectory, policy)
}

func parseNativeReferences(data []byte, configurationPath, workingDirectory string, policy Policy) (nativeReferences, []Diagnostic) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationMalformed, RoleConfiguration, configurationPath, configurationPath,
			"configuration is not valid YAML")}
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationMalformed, RoleConfiguration, configurationPath, configurationPath,
			"configuration must contain exactly one YAML document")}
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationMalformed, RoleConfiguration, configurationPath, configurationPath,
			"configuration root must be a mapping")}
	}
	if code := validateYAMLTree(document.Content[0], 0, new(int)); code != "" {
		detail := "configuration structure is too complex"
		if code == CodeConfigurationDuplicateKey {
			detail = "configuration contains a duplicate mapping key"
		} else if code == CodeConfigurationMalformed {
			detail = "configuration contains an unsupported YAML structure"
		}
		return nativeReferences{}, []Diagnostic{diagnostic(code, RoleConfiguration, configurationPath, configurationPath, detail)}
	}

	root := document.Content[0]
	storageValue, found, bad := mappingScalar(root, "storage")
	if bad {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleStorage, configurationPath, configurationPath,
			"storage must be a path string")}
	}
	if !found || storageValue == "" {
		storageValue = ".lego"
	}
	storage, err := resolveNativePath(workingDirectory, storageValue)
	if err != nil {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleStorage, configurationPath, configurationPath,
			"storage path is invalid")}
	}
	references := nativeReferences{storage: pathReference{raw: storageValue, resolved: storage}}

	challenges := mappingValue(root, "challenges")
	if challenges == nil || isNullNode(challenges) {
		return references, nil
	}
	if challenges.Kind != yaml.MappingNode {
		return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleConfiguration, configurationPath, configurationPath,
			"challenges must be a mapping")}
	}
	for index := 1; index < len(challenges.Content); index += 2 {
		challenge := challenges.Content[index]
		if isNullNode(challenge) {
			continue
		}
		if challenge.Kind != yaml.MappingNode {
			return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleConfiguration, configurationPath, configurationPath,
				"challenge entries must be mappings")}
		}
		if dns := mappingValue(challenge, "dns"); dns != nil && !isNullNode(dns) {
			if dns.Kind != yaml.MappingNode {
				return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleDotenv, configurationPath, configurationPath,
					"DNS challenge must be a mapping")}
			}
			value, present, invalid := mappingScalar(dns, "envFile")
			if invalid {
				return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleDotenv, configurationPath, configurationPath,
					"dotenv reference must be a path string")}
			}
			if present && value != "" {
				resolved, resolveErr := resolveNativePath(workingDirectory, value)
				if resolveErr != nil {
					return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleDotenv, configurationPath, configurationPath,
						"dotenv path is invalid")}
				}
				references.dotenv = append(references.dotenv, pathReference{raw: value, resolved: resolved})
			}
		}
		if http := mappingValue(challenge, "http"); http != nil && !isNullNode(http) {
			if http.Kind != yaml.MappingNode {
				return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleWebroot, configurationPath, configurationPath,
					"HTTP challenge must be a mapping")}
			}
			value, present, invalid := mappingScalar(http, "webroot")
			if invalid {
				return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleWebroot, configurationPath, configurationPath,
					"webroot reference must be a path string")}
			}
			if present && value != "" {
				resolved, resolveErr := resolveNativePath(workingDirectory, value)
				if resolveErr != nil {
					return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationReferenceInvalid, RoleWebroot, configurationPath, configurationPath,
						"webroot path is invalid")}
				}
				references.webroots = append(references.webroots, pathReference{raw: value, resolved: resolved})
			}
		}
		if len(references.dotenv)+len(references.webroots) > policy.MaxReferencedPaths {
			return nativeReferences{}, []Diagnostic{diagnostic(CodeConfigurationTooComplex, RoleConfiguration, configurationPath, configurationPath,
				"configuration contains too many referenced paths")}
		}
	}
	sortPathReferences(references.dotenv)
	sortPathReferences(references.webroots)
	return references, nil
}

func validateYAMLTree(node *yaml.Node, depth int, count *int) ErrorCode {
	(*count)++
	if *count > maximumYAMLNodes || depth > maximumYAMLDepth {
		return CodeConfigurationTooComplex
	}
	if node.Kind == yaml.AliasNode {
		return CodeConfigurationMalformed
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return CodeConfigurationMalformed
		}
		keys := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return CodeConfigurationMalformed
			}
			if _, exists := keys[key.Value]; exists {
				return CodeConfigurationDuplicateKey
			}
			keys[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if code := validateYAMLTree(child, depth+1, count); code != "" {
			return code
		}
	}
	return ""
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Kind == yaml.ScalarNode && mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func mappingScalar(mapping *yaml.Node, key string) (string, bool, bool) {
	value := mappingValue(mapping, key)
	if value == nil {
		return "", false, false
	}
	if isNullNode(value) {
		return "", true, false
	}
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
		return "", true, true
	}
	return value.Value, true, false
}

func isNullNode(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

func resolveNativePath(workingDirectory, reference string) (string, error) {
	if reference == "" || len(reference) > maximumPathBytes || !utf8.ValidString(reference) || strings.IndexFunc(reference, invalidPathRune) >= 0 {
		return "", &Error{Code: CodeConfigurationReferenceInvalid}
	}
	resolved := reference
	if !filepath.IsAbs(reference) {
		resolved = filepath.Join(workingDirectory, reference)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) || len(resolved) > maximumPathBytes {
		return "", &Error{Code: CodeConfigurationReferenceInvalid}
	}
	return resolved, nil
}

func sortPathReferences(references []pathReference) {
	sort.Slice(references, func(left, right int) bool {
		if references[left].resolved == references[right].resolved {
			return references[left].raw < references[right].raw
		}
		return references[left].resolved < references[right].resolved
	})
}

type contextReader struct {
	context context.Context
	reader  io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.context.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
