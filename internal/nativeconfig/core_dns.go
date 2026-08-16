package nativeconfig

import (
	"fmt"
	"slices"
	"sort"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
)

// WithCoreDNSCredentialValidation applies authentication-combination rules
// after exact dotenv presence has been observed. Existing mixed native files
// remain repairable as unsupported; a reviewed candidate is strict and cannot
// activate an incomplete or mixed authentication mode.
func (i Inspection) WithCoreDNSCredentialValidation(strict bool) Inspection {
	providers := make(map[string]string)
	presence := make(map[string]map[integrations.FieldID]bool)
	values := make(map[string]map[integrations.FieldID]string)
	for _, field := range i.Projection {
		challenge := bindingFor(field.Bindings, integrations.BindingChallenge)
		if challenge == "" {
			continue
		}
		if field.FieldID == integrations.FieldChallengeDNSProvider {
			if value, ok := field.Value(); ok {
				if provider, stringValue := value.String(); stringValue {
					providers[challenge] = provider
				}
			}
			continue
		}
		if _, providerField := integrations.ProviderCodeForField(field.FieldID); !providerField {
			continue
		}
		if presence[challenge] == nil {
			presence[challenge] = make(map[integrations.FieldID]bool)
			values[challenge] = make(map[integrations.FieldID]string)
		}
		presence[challenge][field.FieldID] = field.PresenceKnown && field.Present && field.Configured
		if value, ok := field.Value(); ok {
			if text, stringValue := value.String(); stringValue {
				values[challenge][field.FieldID] = text
			}
		}
	}
	challenges := make([]string, 0, len(providers))
	for challenge := range providers {
		challenges = append(challenges, challenge)
	}
	sort.Strings(challenges)
	for _, challenge := range challenges {
		provider := providers[challenge]
		if !slices.Contains(integrations.SupportedDNSProviders(), provider) {
			continue
		}
		issues := integrations.CoreDNSCredentialIssues(provider, presence[challenge])
		if provider == "azuredns" || provider == "route53" {
			issues = integrations.CloudDNSCredentialIssues(provider, presence[challenge], values[challenge])
		}
		if len(issues) == 0 {
			continue
		}
		class := IssueUnsupported
		if strict {
			class = IssueConstraint
		}
		i.Issues = appendIssue(i.Issues, i.maxIssues, Issue{
			Class:           class,
			Path:            fmt.Sprintf("/challenges/%s/dns/envFile", challenge),
			Summary:         "Provider authentication is incomplete, duplicated, or mixes mutually exclusive alternatives.",
			BlocksExecution: true,
		})
		i.Executable = false
	}
	return i
}

func bindingFor(bindings []Binding, id integrations.BindingID) string {
	for _, binding := range bindings {
		if binding.ID == id {
			return binding.Value
		}
	}
	return ""
}
