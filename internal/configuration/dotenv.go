package configuration

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sgurden-certleap/AcmeMux/internal/dotenv"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

type dotenvDocument struct {
	path     string
	routes   []nativeconfig.DotenvRoute
	allowed  []string
	original []byte
	document *dotenv.Document
}

type dotenvDocuments struct {
	byPath      map[string]*dotenvDocument
	diagnostics []Diagnostic
	invalid     bool
	unsupported bool
}

func (documents *dotenvDocuments) close() {
	if documents == nil {
		return
	}
	for _, document := range documents.byPath {
		if document.document != nil {
			document.document.Clear()
		}
	}
	documents.byPath = nil
	clear(documents.diagnostics)
	documents.diagnostics = nil
}

func loadDotenvDocuments(inspection nativeconfig.Inspection, sources *workspace.SourceSet, allowMissing bool) *dotenvDocuments {
	result := &dotenvDocuments{byPath: make(map[string]*dotenvDocument)}
	if sources == nil {
		result.invalid = true
		return result
	}
	workingDirectory := sources.Selection.Review.WorkingDirectory.Path
	for _, route := range inspection.DotenvRoutes() {
		path, ok := resolveNativeReference(workingDirectory, route.Reference())
		if !ok {
			result.invalid = true
			result.diagnostics = appendBoundedDiagnostic(result.diagnostics, Diagnostic{
				Code: CodeUnsafePath, Severity: SeverityBlocking, Role: RoleFilesystem,
				FieldID: route.FieldID(), Bindings: route.Bindings(),
			})
			continue
		}
		document := result.byPath[path]
		if document == nil {
			document = &dotenvDocument{path: path}
			result.byPath[path] = document
		}
		document.routes = append(document.routes, route)
		document.allowed = append(document.allowed, route.EnvironmentKey())
	}

	sourceByPath := make(map[string]workspace.SourceFile, len(sources.Dotenv))
	for _, source := range sources.Dotenv {
		sourceByPath[source.Path] = source
	}
	for path, managed := range result.byPath {
		sort.Strings(managed.allowed)
		managed.allowed = slices.Compact(managed.allowed)
		source, present := sourceByPath[path]
		if !present && !allowMissing {
			result.invalid = true
			result.diagnostics = appendBoundedDiagnostic(result.diagnostics, Diagnostic{
				Code: CodeSourceChanged, Severity: SeverityBlocking, Role: RoleFilesystem, Path: path,
			})
			continue
		}
		if present {
			managed.original = source.Content
		}
		document, err := dotenv.Parse(managed.original, managed.allowed, dotenv.DefaultPolicy())
		if err != nil {
			result.invalid = true
			result.diagnostics = appendBoundedDiagnostic(result.diagnostics, Diagnostic{
				Code: dotenvDiagnosticCode(err), Severity: SeverityBlocking, Role: RoleDotenv, Path: path,
			})
			continue
		}
		managed.document = document
		if len(document.UnsupportedKeys()) != 0 {
			result.unsupported = true
			result.diagnostics = appendBoundedDiagnostic(result.diagnostics, Diagnostic{
				Code: CodeDotenvKeyNotAllowed, Severity: SeverityBlocking, Role: RoleDotenv, Path: path,
			})
		}
	}
	return result
}

func resolveNativeReference(workingDirectory, reference string) (string, bool) {
	if reference == "" || strings.ContainsRune(reference, 0) {
		return "", false
	}
	var path string
	if filepath.IsAbs(reference) {
		path = filepath.Clean(reference)
	} else {
		path = filepath.Clean(filepath.Join(workingDirectory, reference))
	}
	if !filepath.IsAbs(path) || len(path) == 0 || len(path) >= 4096 {
		return "", false
	}
	return path, true
}

func dotenvDiagnosticCode(err error) DiagnosticCode {
	switch dotenv.CodeOf(err) {
	case dotenv.CodeInvalidUTF8:
		return CodeInvalidUTF8
	case dotenv.CodeTooLarge, dotenv.CodeTooManyLines, dotenv.CodeValueTooLarge:
		return CodeDocumentTooLarge
	case dotenv.CodeDuplicateKey:
		return CodeDotenvDuplicateKey
	case dotenv.CodeKeyNotAllowed:
		return CodeDotenvKeyNotAllowed
	case dotenv.CodeExpansionNotAllowed:
		return CodeDotenvExpansionNotAllowed
	default:
		return CodeDotenvMalformed
	}
}

func applyDotenvPresence(inspection nativeconfig.Inspection, documents *dotenvDocuments) nativeconfig.Inspection {
	if documents == nil {
		return inspection
	}
	presence := make([]nativeconfig.DotenvPresence, 0)
	for _, managed := range documents.byPath {
		if managed.document == nil {
			continue
		}
		for _, route := range managed.routes {
			present, valid := managed.document.ValidatePresence(route.EnvironmentKey(), route.ValidValue)
			presence = append(presence, nativeconfig.DotenvPresence{
				FieldID: route.FieldID(), Bindings: route.Bindings(), Present: present, Valid: valid,
			})
		}
	}
	return inspection.WithDotenvPresence(presence)
}

func applyExternalChanges(
	inspection nativeconfig.Inspection,
	sources *workspace.SourceSet,
	external []nativeconfig.ExternalChange,
) (*dotenvDocuments, []workspace.Replacement, []nativeconfig.ChangeSummary, error) {
	documents := loadDotenvDocuments(inspection, sources, true)
	if documents.invalid {
		return documents, nil, nil, fmt.Errorf("%w: candidate dotenv source", ErrInvalid)
	}
	type routedChange struct {
		change   dotenv.Change
		external nativeconfig.ExternalChange
	}
	changesByPath := make(map[string][]routedChange)
	for _, change := range external {
		path, ok := resolveNativeReference(sources.Selection.Review.WorkingDirectory.Path, change.Reference())
		if !ok {
			return documents, nil, nil, fmt.Errorf("%w: candidate dotenv path", ErrInvalid)
		}
		managed := documents.byPath[path]
		if managed == nil || managed.document == nil {
			return documents, nil, nil, fmt.Errorf("%w: candidate dotenv route", ErrInvalid)
		}
		action := dotenv.ActionRemove
		var value []byte
		if change.Operation() == nativeconfig.OperationSet {
			action = dotenv.ActionReplace
			typed, present := change.Value()
			text, stringValue := typed.String()
			if !present || !stringValue {
				return documents, nil, nil, fmt.Errorf("%w: candidate dotenv value", ErrInvalid)
			}
			value = []byte(text)
		}
		changesByPath[path] = append(changesByPath[path], routedChange{
			change:   dotenv.Change{Key: change.EnvironmentKey(), Action: action, Value: value},
			external: change,
		})
	}

	paths := make([]string, 0, len(changesByPath))
	for path := range changesByPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	replacements := make([]workspace.Replacement, 0, len(paths))
	impactByIdentity := make(map[string]nativeconfig.ChangeSummary)
	for _, path := range paths {
		managed := documents.byPath[path]
		routed := changesByPath[path]
		changes := make([]dotenv.Change, len(routed))
		for index := range routed {
			changes[index] = routed[index].change
		}
		candidate, summaries, err := managed.document.Apply(changes)
		for index := range changes {
			clear(changes[index].Value)
			clear(routed[index].change.Value)
		}
		if err != nil {
			clear(candidate)
			return documents, nil, nil, fmt.Errorf("%w: candidate dotenv edit", ErrInvalid)
		}
		containsSet := false
		for _, item := range routed {
			if item.change.Action == dotenv.ActionReplace {
				containsSet = true
				break
			}
		}
		if !containsSet && bytes.Equal(candidate, managed.original) {
			clear(candidate)
			continue
		}
		for _, summary := range summaries {
			for _, route := range managed.routes {
				if route.EnvironmentKey() != summary.Key {
					continue
				}
				action := nativeconfig.SummarySet
				if summary.Action == dotenv.ActionRemove {
					action = nativeconfig.SummaryRemove
				}
				identity := externalIdentity(route.FieldID(), route.Bindings())
				impactByIdentity[identity] = nativeconfig.ChangeSummary{
					FieldID: route.FieldID(), Bindings: route.Bindings(), Label: route.Label(),
					Target: integrations.TargetDotenv, Action: action, Secret: true,
				}
			}
		}
		replacementDocument, err := dotenv.Parse(candidate, managed.allowed, dotenv.DefaultPolicy())
		if err != nil {
			clear(candidate)
			return documents, nil, nil, fmt.Errorf("%w: validate candidate dotenv", ErrInvalid)
		}
		managed.document.Clear()
		managed.document = replacementDocument
		managed.original = candidate
		replacements = append(replacements, workspace.Replacement{
			Role: workspace.RoleDotenv, Path: path, Content: candidate,
		})
	}
	identities := make([]string, 0, len(impactByIdentity))
	for identity := range impactByIdentity {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	impacts := make([]nativeconfig.ChangeSummary, 0, len(identities))
	for _, identity := range identities {
		impacts = append(impacts, impactByIdentity[identity])
	}
	return documents, replacements, impacts, nil
}

func externalIdentity(fieldID integrations.FieldID, bindings []nativeconfig.Binding) string {
	var identity strings.Builder
	appendIdentityPart := func(value string) {
		identity.WriteString(strconv.Itoa(len(value)))
		identity.WriteByte(':')
		identity.WriteString(value)
		identity.WriteByte(';')
	}
	appendIdentityPart(string(fieldID))
	for _, binding := range bindings {
		appendIdentityPart(string(binding.ID))
		appendIdentityPart(binding.Value)
	}
	return identity.String()
}

func clearReplacements(replacements []workspace.Replacement) {
	for index := range replacements {
		clear(replacements[index].Content)
		replacements[index].Content = nil
	}
}

func appendBoundedDiagnostic(diagnostics []Diagnostic, diagnostic Diagnostic) []Diagnostic {
	const maximumDiagnostics = 256
	if len(diagnostics) >= maximumDiagnostics {
		return diagnostics
	}
	diagnostic.Bindings = slices.Clone(diagnostic.Bindings)
	return append(diagnostics, diagnostic)
}
