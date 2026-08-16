package nativeconfig

import (
	"slices"
	"sort"
	"strings"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"go.yaml.in/yaml/v3"
)

var knownLeafPatterns = [][]string{
	{"storage"}, {"networkStack"}, {"userAgent"},
	{"servers", "*", "url"}, {"servers", "*", "tlsSkipVerify"},
	{"servers", "*", "overallRequestLimit"}, {"servers", "*", "httpTimeout"}, {"servers", "*", "certTimeout"},
	{"accounts", "*", "server"}, {"accounts", "*", "email"}, {"accounts", "*", "keyType"},
	{"accounts", "*", "acceptsTermsOfService"}, {"accounts", "*", "eab", "kid"}, {"accounts", "*", "eab", "hmacKey"},
	{"challenges", "*", "http", "address"}, {"challenges", "*", "http", "delay"},
	{"challenges", "*", "http", "proxyHeader"}, {"challenges", "*", "http", "webroot"},
	{"challenges", "*", "http", "memcachedHosts"}, {"challenges", "*", "http", "s3Bucket"},
	{"challenges", "*", "tls", "address"}, {"challenges", "*", "tls", "delay"},
	{"challenges", "*", "dns", "provider"}, {"challenges", "*", "dns", "dnsTimeout"},
	{"challenges", "*", "dns", "resolvers"}, {"challenges", "*", "dns", "envFile"},
	{"challenges", "*", "dns", "propagation", "disableAuthoritativeNameservers"},
	{"challenges", "*", "dns", "propagation", "disableRecursiveNameservers"},
	{"challenges", "*", "dns", "propagation", "wait"},
	{"challenges", "*", "dnsPersist", "issuerDomainName"}, {"challenges", "*", "dnsPersist", "persistUntil"},
	{"challenges", "*", "dnsPersist", "dnsTimeout"}, {"challenges", "*", "dnsPersist", "resolvers"},
	{"challenges", "*", "dnsPersist", "propagation", "disableAuthoritativeNameservers"},
	{"challenges", "*", "dnsPersist", "propagation", "disableRecursiveNameservers"},
	{"challenges", "*", "dnsPersist", "propagation", "wait"},
	{"certificates", "*", "domains"}, {"certificates", "*", "csr"}, {"certificates", "*", "keyType"},
	{"certificates", "*", "challenge"}, {"certificates", "*", "account"}, {"certificates", "*", "enableCommonName"},
	{"certificates", "*", "preferredChain"}, {"certificates", "*", "profile"},
	{"certificates", "*", "notBefore"}, {"certificates", "*", "notAfter"}, {"certificates", "*", "noBundle"},
	{"certificates", "*", "mustStaple"}, {"certificates", "*", "alwaysDeactivateAuthorizations"},
	{"certificates", "*", "renew", "days"}, {"certificates", "*", "renew", "reuseKey"},
	{"certificates", "*", "renew", "disableRandomSleep"},
	{"certificates", "*", "renew", "ari", "disable"}, {"certificates", "*", "renew", "ari", "waitToRenewDuration"},
	{"certificates", "*", "pfx", "password"}, {"certificates", "*", "pfx", "format"},
	{"hooks", "pre", "command"}, {"hooks", "pre", "timeout"},
	{"hooks", "deploy", "command"}, {"hooks", "deploy", "timeout"},
	{"hooks", "post", "command"}, {"hooks", "post", "timeout"},
	{"log", "level"}, {"log", "format"},
}

func knownPrefix(path []string) bool {
	for _, pattern := range knownLeafPatterns {
		if len(path) > len(pattern) {
			continue
		}
		matched := true
		for index := range path {
			if pattern[index] != "*" && pattern[index] != path[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return len(path) == 0
}

func knownLeaf(path []string) bool {
	for _, pattern := range knownLeafPatterns {
		if len(path) != len(pattern) {
			continue
		}
		matched := true
		for index := range path {
			if pattern[index] != "*" && pattern[index] != path[index] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func compatibleManifestField(spec integrations.FieldSpec) bool {
	selector := spec.Selector()
	pattern := make([]string, len(selector))
	for index, segment := range selector {
		if key, ok := segment.Key(); ok {
			pattern[index] = key
			continue
		}
		if _, ok := segment.Binding(); !ok {
			return false
		}
		pattern[index] = "*"
	}
	if !knownLeaf(pattern) {
		return false
	}
	if spec.Target() == integrations.TargetDotenv {
		return len(pattern) > 0 && pattern[len(pattern)-1] == "envFile" && spec.Kind() == integrations.FieldString
	}
	expected := integrations.FieldString
	last := pattern[len(pattern)-1]
	switch last {
	case "domains", "memcachedHosts", "resolvers":
		expected = integrations.FieldStringList
	case "overallRequestLimit", "httpTimeout", "certTimeout", "dnsTimeout", "days":
		expected = integrations.FieldInteger
	case "tlsSkipVerify", "acceptsTermsOfService", "disableAuthoritativeNameservers",
		"disableRecursiveNameservers", "enableCommonName", "noBundle", "mustStaple",
		"alwaysDeactivateAuthorizations", "reuseKey", "disableRandomSleep", "disable":
		expected = integrations.FieldBoolean
	}
	return spec.Kind() == expected
}

func (e *Engine) projectAndClassify(document *yaml.Node) ([]ProjectedField, []DotenvRoute, []Issue, bool) {
	projection := make([]ProjectedField, 0, len(e.manifest.Fields()))
	routes := make([]DotenvRoute, 0)
	issues := make([]Issue, 0)
	seenProjection := make(map[string]struct{})
	projectionOverflow := false
	unsupportedHTTPBindings := unsupportedHTTPChallengeBindings(document.Content[0])
	unsupportedCertificates := unsupportedCertificateBindings(document.Content[0])
	implicitUnsupportedChallenges := implicitUnsupportedCertificateChallenges(document.Content[0], unsupportedHTTPBindings)
	implicitHTTPBindings := implicitHTTPChallengeBindings(document.Content[0])

	var walk func(*yaml.Node, []string, bool)
	walk = func(node *yaml.Node, path []string, unsupportedAncestor bool) {
		if len(issues) >= e.limits.MaxIssues {
			return
		}
		if node.Kind != yaml.MappingNode {
			return
		}
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			childPath := appendPath(path, key.Value)
			if !knownPrefix(childPath) {
				issues = appendIssue(issues, e.limits.MaxIssues, Issue{
					Class: IssueUnknown, Path: pointer(childPath), Line: key.Line, Column: key.Column,
					Summary:           "Field is not recognized by the admitted lego configuration model.",
					BlocksReplacement: true, BlocksExecution: true,
				})
				continue
			}

			yamlSpec, yamlBindings, yamlManaged := e.manifest.MatchTarget(childPath, integrations.TargetYAML)
			dotenvMatches := e.matchingFields(childPath, integrations.TargetDotenv)
			if yamlManaged {
				suppressProjection := suppressUnsupportedHTTPProjection(yamlSpec, yamlBindings, unsupportedHTTPBindings) ||
					suppressUnsupportedCertificateProjection(yamlSpec, yamlBindings, unsupportedCertificates)
				if projected, ok, supported := projectedFromNode(yamlSpec, yamlBindings, value); ok && !suppressProjection {
					projectionIdentity := projectionKey(projected.FieldID, projected.Bindings)
					if !supported {
						projected.Configured = false
						projected.hasValue = false
						projected.value = integrations.Value{}
						seenProjection[projectionIdentity] = struct{}{}
						issues = appendIssue(issues, e.limits.MaxIssues, Issue{
							Class: IssueUnsupported, Path: pointer(childPath), Line: key.Line, Column: key.Column,
							Summary: "Field value is outside the curated integration contract.", BlocksExecution: true,
						})
						if len(projection) >= e.limits.MaxProjectionFields {
							projectionOverflow = true
						} else {
							projection = append(projection, projected)
						}
					} else if _, duplicate := seenProjection[projectionIdentity]; !duplicate {
						if len(projection) >= e.limits.MaxProjectionFields {
							projectionOverflow = true
						} else {
							projection = append(projection, projected)
							seenProjection[projectionIdentity] = struct{}{}
						}
					}
				}
				if len(dotenvMatches) == 0 {
					continue
				}
			}
			if len(dotenvMatches) > 0 {
				for _, match := range dotenvMatches {
					dotenvSpec := match.spec
					bindings := orderedBindings(dotenvSpec, match.bindings)
					projected := ProjectedField{
						FieldID: dotenvSpec.ID(), Bindings: bindings, Label: dotenvSpec.Label(), Kind: dotenvSpec.Kind(),
						Secret: dotenvSpec.Sensitivity() == integrations.SensitivitySecret,
					}
					key := projectionKey(projected.FieldID, projected.Bindings)
					if _, duplicate := seenProjection[key]; duplicate {
						continue
					}
					if len(projection) >= e.limits.MaxProjectionFields {
						projectionOverflow = true
						continue
					}
					projection = append(projection, projected)
					seenProjection[key] = struct{}{}
					if value.Kind == yaml.ScalarNode && value.Tag == "!!str" && value.Value != "" {
						environmentKey, _ := dotenvSpec.EnvironmentKey()
						routes = append(routes, DotenvRoute{
							fieldID: dotenvSpec.ID(), bindings: bindings, reference: value.Value,
							environmentKey: environmentKey, secret: projected.Secret, spec: dotenvSpec,
						})
					}
				}
				continue
			}

			managedBelow := e.manifest.HasPathPrefixForTarget(childPath, integrations.TargetYAML) ||
				e.manifest.HasPathPrefixForTarget(childPath, integrations.TargetDotenv)
			isContainer := value.Kind == yaml.MappingNode && !knownLeaf(childPath)
			childUnsupported := unsupportedAncestor
			if unsupportedAncestor && notableUnsupportedPath(childPath) && (isContainer || knownLeaf(childPath)) {
				issues = appendIssue(issues, e.limits.MaxIssues, Issue{
					Class: IssueUnsupported, Path: pointer(childPath), Line: key.Line, Column: key.Column,
					Summary:         "Field is recognized by lego but is not managed by this integration.",
					BlocksExecution: true,
				})
			}
			if !unsupportedAncestor && !managedBelow && (isContainer || knownLeaf(childPath)) {
				issues = appendIssue(issues, e.limits.MaxIssues, Issue{
					Class: IssueUnsupported, Path: pointer(childPath), Line: key.Line, Column: key.Column,
					Summary:         "Field is recognized by lego but is not managed by this integration.",
					BlocksExecution: true,
				})
				childUnsupported = true
			}
			if isContainer {
				walk(value, childPath, childUnsupported)
			}
		}
	}
	walk(document.Content[0], nil, false)

	for _, spec := range e.manifest.Fields() {
		bindingSets := bindingSetsForSpec(document.Content[0], spec)
		if isHTTPChallengeSpec(spec) {
			for _, challenge := range implicitHTTPBindings {
				bindings := []Binding{{ID: integrations.BindingChallenge, Value: challenge}}
				if !slices.ContainsFunc(bindingSets, func(existing []Binding) bool {
					return slices.Equal(existing, bindings)
				}) {
					bindingSets = append(bindingSets, bindings)
				}
			}
		}
		if len(spec.BindingIDs()) == 0 {
			bindingSets = [][]Binding{nil}
		}
		for _, bindings := range bindingSets {
			bindingValues := make(map[integrations.BindingID]string, len(bindings))
			for _, binding := range bindings {
				bindingValues[binding.ID] = binding.Value
			}
			if suppressUnsupportedHTTPProjection(spec, bindingValues, unsupportedHTTPBindings) ||
				suppressUnsupportedCertificateProjection(spec, bindingValues, unsupportedCertificates) {
				continue
			}
			key := projectionKey(spec.ID(), bindings)
			if _, present := seenProjection[key]; present {
				continue
			}
			if len(projection) >= e.limits.MaxProjectionFields {
				projectionOverflow = true
				continue
			}
			field := ProjectedField{
				FieldID: spec.ID(), Bindings: bindings, Label: spec.Label(), Kind: spec.Kind(),
				PresenceKnown: spec.Target() == integrations.TargetYAML,
				Secret:        spec.Sensitivity() == integrations.SensitivitySecret,
			}
			if spec.ID() == integrations.FieldCertificateChallenge {
				certificate := bindingValues[integrations.BindingCertificate]
				if challenge, defaulted := implicitUnsupportedChallenges[certificate]; defaulted {
					field.Defaulted = true
					field.Configured = true
					field.value = integrations.StringValue(challenge)
					field.hasValue = true
				}
			}
			if value, ok := spec.Default(); ok {
				field.Defaulted = true
				field.Configured = true
				if !field.Secret {
					field.value = value
					field.hasValue = true
				}
			}
			projection = append(projection, field)
			seenProjection[key] = struct{}{}
		}
	}

	sort.Slice(projection, func(left, right int) bool {
		return projectionKey(projection[left].FieldID, projection[left].Bindings) < projectionKey(projection[right].FieldID, projection[right].Bindings)
	})
	sort.Slice(routes, func(left, right int) bool {
		return projectionKey(routes[left].fieldID, routes[left].bindings) < projectionKey(routes[right].fieldID, routes[right].bindings)
	})
	return projection, routes, issues, projectionOverflow
}

// unsupportedHTTPChallengeBindings identifies native challenge containers
// whose effective provider is outside the core HTTP listener/webroot
// contract. Managed HTTP leaves under those containers remain preserved but
// are not projected, so absent defaults cannot look editable or be submitted
// by a full-form client during an unrelated change.
func unsupportedHTTPChallengeBindings(root *yaml.Node) map[string]struct{} {
	result := make(map[string]struct{})
	challenges, _, ok := mappingValue(root, "challenges")
	if !ok || challenges.Kind != yaml.MappingNode {
		return result
	}
	for index := 0; index+1 < len(challenges.Content); index += 2 {
		name, challenge := challenges.Content[index].Value, challenges.Content[index+1]
		if challenge.Kind != yaml.MappingNode {
			continue
		}
		unsupported := false
		for _, key := range []string{"tls", "dns", "dnsPersist"} {
			if _, _, present := mappingValue(challenge, key); present {
				unsupported = true
			}
		}
		if http, _, present := mappingValue(challenge, "http"); present && http.Kind == yaml.MappingNode {
			for _, key := range []string{"memcachedHosts", "s3Bucket"} {
				if _, _, configured := mappingValue(http, key); configured {
					unsupported = true
				}
			}
		}
		if unsupported {
			result[name] = struct{}{}
		}
	}
	return result
}

func suppressUnsupportedHTTPProjection(
	spec integrations.FieldSpec,
	bindings map[integrations.BindingID]string,
	unsupported map[string]struct{},
) bool {
	challenge, bound := bindings[integrations.BindingChallenge]
	if !bound {
		return false
	}
	if _, blocked := unsupported[challenge]; !blocked {
		return false
	}
	return isHTTPChallengeSpec(spec)
}

func isHTTPChallengeSpec(spec integrations.FieldSpec) bool {
	selector := spec.Selector()
	if len(selector) < 3 {
		return false
	}
	first, firstOK := selector[0].Key()
	binding, bindingOK := selector[1].Binding()
	third, thirdOK := selector[2].Key()
	return firstOK && first == "challenges" && bindingOK && binding == integrations.BindingChallenge &&
		thirdOK && third == "http"
}

func implicitHTTPChallengeBindings(root *yaml.Node) []string {
	if challenges, _, present := mappingValue(root, "challenges"); present {
		if _, _, configured := mappingValue(challenges, "http-01"); configured {
			return nil
		}
	}
	certificates, _, ok := mappingValue(root, "certificates")
	if !ok || certificates.Kind != yaml.MappingNode {
		return nil
	}
	unsupportedCertificates := unsupportedCertificateBindings(root)
	for index := 1; index < len(certificates.Content); index += 2 {
		name := certificates.Content[index-1].Value
		certificate := certificates.Content[index]
		if _, unsupported := unsupportedCertificates[name]; unsupported {
			continue
		}
		challenge, _, present := mappingValue(certificate, "challenge")
		if present && challenge.Kind == yaml.ScalarNode && challenge.Value == "http-01" {
			return []string{"http-01"}
		}
	}
	return nil
}

func unsupportedCertificateBindings(root *yaml.Node) map[string]struct{} {
	result := make(map[string]struct{})
	certificates, _, ok := mappingValue(root, "certificates")
	if !ok || certificates.Kind != yaml.MappingNode {
		return result
	}
	for index := 0; index+1 < len(certificates.Content); index += 2 {
		name, certificate := certificates.Content[index].Value, certificates.Content[index+1]
		if certificate.Kind != yaml.MappingNode {
			continue
		}
		_, _, csr := mappingValue(certificate, "csr")
		_, _, pfx := mappingValue(certificate, "pfx")
		if csr || pfx {
			result[name] = struct{}{}
		}
	}
	return result
}

func implicitUnsupportedCertificateChallenges(root *yaml.Node, unsupportedChallenges map[string]struct{}) map[string]string {
	result := make(map[string]string)
	challenges, _, ok := mappingValue(root, "challenges")
	if !ok || challenges.Kind != yaml.MappingNode || len(challenges.Content) != 2 {
		return result
	}
	challenge := challenges.Content[0].Value
	if _, unsupported := unsupportedChallenges[challenge]; !unsupported {
		return result
	}
	certificates, _, ok := mappingValue(root, "certificates")
	if !ok || certificates.Kind != yaml.MappingNode {
		return result
	}
	unsupportedCertificates := unsupportedCertificateBindings(root)
	for index := 0; index+1 < len(certificates.Content); index += 2 {
		name, certificate := certificates.Content[index].Value, certificates.Content[index+1]
		if certificate.Kind != yaml.MappingNode {
			continue
		}
		if _, unsupported := unsupportedCertificates[name]; unsupported {
			continue
		}
		if _, _, configured := mappingValue(certificate, "challenge"); !configured {
			result[name] = challenge
		}
	}
	return result
}

func suppressUnsupportedCertificateProjection(
	spec integrations.FieldSpec,
	bindings map[integrations.BindingID]string,
	unsupported map[string]struct{},
) bool {
	certificate, bound := bindings[integrations.BindingCertificate]
	if !bound {
		return false
	}
	if _, blocked := unsupported[certificate]; !blocked {
		return false
	}
	selector := spec.Selector()
	if len(selector) < 2 {
		return false
	}
	first, firstOK := selector[0].Key()
	binding, bindingOK := selector[1].Binding()
	return firstOK && first == "certificates" && bindingOK && binding == integrations.BindingCertificate
}

// bindingSetsForSpec enumerates entity identities at the last trusted binding
// selector, independent of whether the optional leaf itself exists. This
// lets forms render absent/defaulted fields for an existing named account,
// challenge, or certificate without accepting a browser-supplied YAML path.
func bindingSetsForSpec(root *yaml.Node, spec integrations.FieldSpec) [][]Binding {
	selector := spec.Selector()
	lastBinding := -1
	for index, segment := range selector {
		if _, ok := segment.Binding(); ok {
			lastBinding = index
		}
	}
	if lastBinding < 0 {
		return nil
	}
	selector = selector[:lastBinding+1]
	result := make([][]Binding, 0)
	values := make(map[integrations.BindingID]string, len(spec.BindingIDs()))
	var walk func(*yaml.Node, int)
	walk = func(node *yaml.Node, index int) {
		if index == len(selector) {
			if _, err := spec.Resolve(values); err != nil {
				return
			}
			result = append(result, orderedBindings(spec, values))
			return
		}
		if node == nil || node.Kind != yaml.MappingNode {
			return
		}
		segment := selector[index]
		if key, ok := segment.Key(); ok {
			child, _, present := mappingValue(node, key)
			if present {
				walk(child, index+1)
			}
			return
		}
		binding, ok := segment.Binding()
		if !ok {
			return
		}
		for childIndex := 0; childIndex+1 < len(node.Content); childIndex += 2 {
			key, child := node.Content[childIndex], node.Content[childIndex+1]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			values[binding] = key.Value
			walk(child, index+1)
			delete(values, binding)
		}
	}
	walk(root, 0)
	return result
}

func notableUnsupportedPath(path []string) bool {
	if len(path) == 0 {
		return false
	}
	if path[len(path)-1] == "provider" {
		return true
	}
	return len(path) >= 3 && path[0] == "certificates" && path[2] == "pfx"
}

type fieldMatch struct {
	spec     integrations.FieldSpec
	bindings map[integrations.BindingID]string
}

func (e *Engine) matchingFields(path []string, target integrations.FieldTarget) []fieldMatch {
	result := make([]fieldMatch, 0)
	for _, spec := range e.manifest.Fields() {
		if spec.Target() != target {
			continue
		}
		if bindings, ok := spec.Match(path); ok {
			result = append(result, fieldMatch{spec: spec, bindings: bindings})
		}
	}
	return result
}

func projectedFromNode(spec integrations.FieldSpec, bindings map[integrations.BindingID]string, node *yaml.Node) (ProjectedField, bool, bool) {
	value, ok := integrationValue(spec.Kind(), node)
	if !ok {
		return ProjectedField{}, false, false
	}
	supported := spec.ValidateValue(value) == nil
	secret := spec.Sensitivity() == integrations.SensitivitySecret
	result := ProjectedField{
		FieldID: spec.ID(), Bindings: orderedBindings(spec, bindings), Label: spec.Label(), Kind: spec.Kind(),
		Present: true, Configured: true, PresenceKnown: true, Secret: secret,
	}
	if !secret {
		result.value = value
		result.hasValue = true
	}
	return result, true, supported
}

func integrationValue(kind integrations.FieldKind, node *yaml.Node) (integrations.Value, bool) {
	if node == nil {
		return integrations.Value{}, false
	}
	switch kind {
	case integrations.FieldString:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
			return integrations.Value{}, false
		}
		return integrations.StringValue(node.Value), true
	case integrations.FieldBoolean:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return integrations.Value{}, false
		}
		var value bool
		if node.Decode(&value) != nil {
			return integrations.Value{}, false
		}
		return integrations.BooleanValue(value), true
	case integrations.FieldInteger:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
			return integrations.Value{}, false
		}
		var value int64
		if node.Decode(&value) != nil {
			return integrations.Value{}, false
		}
		return integrations.IntegerValue(value), true
	case integrations.FieldStringList:
		if node.Kind != yaml.SequenceNode {
			return integrations.Value{}, false
		}
		values := make([]string, len(node.Content))
		for index, child := range node.Content {
			if child.Kind != yaml.ScalarNode || child.Tag != "!!str" {
				return integrations.Value{}, false
			}
			values[index] = child.Value
		}
		return integrations.StringListValue(values), true
	default:
		return integrations.Value{}, false
	}
}

func orderedBindings(spec integrations.FieldSpec, values map[integrations.BindingID]string) []Binding {
	ids := spec.BindingIDs()
	result := make([]Binding, len(ids))
	for index, id := range ids {
		result[index] = Binding{ID: id, Value: values[id]}
	}
	return result
}

func appendPath(path []string, value string) []string {
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = value
	return result
}

func projectionKey(id integrations.FieldID, bindings []Binding) string {
	var builder strings.Builder
	builder.WriteString(string(id))
	for _, binding := range bindings {
		builder.WriteByte(0)
		builder.WriteString(string(binding.ID))
		builder.WriteByte('=')
		builder.WriteString(binding.Value)
	}
	return builder.String()
}

func appendIssue(issues []Issue, limit int, issue Issue) []Issue {
	if len(issues) >= limit {
		return issues
	}
	return append(issues, issue)
}
