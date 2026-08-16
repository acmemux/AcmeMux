package configuration

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const maximumCloudCredentialBytes = int64(64 << 10)

type cloudProjection struct {
	present map[integrations.FieldID]bool
	values  map[integrations.FieldID]string
}

func (service *Service) prepareCloudAccess(
	ctx context.Context,
	evaluated *evaluation,
	intent ExecutionIntent,
) ([]ExecutionCloudAccess, []ExecutionEnvironment, [][]byte, []workspace.PathEvidence, error) {
	challengeProviders := make(map[string]string)
	for _, certificate := range intent.Certificates {
		if certificate.ChallengeKind == "dns-01" && (certificate.ChallengeMode == "azuredns" || certificate.ChallengeMode == "route53") {
			challengeProviders[certificate.ChallengeName] = certificate.ChallengeMode
		}
	}
	if len(challengeProviders) == 0 {
		return nil, nil, nil, nil, nil
	}
	if service.cloudAccess == nil {
		return nil, nil, nil, nil, fmt.Errorf("%w: cloud access inspector", ErrUnavailable)
	}

	names := make([]string, 0, len(challengeProviders))
	for name := range challengeProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	var accesses []ExecutionCloudAccess
	var environment []ExecutionEnvironment
	var secrets [][]byte
	var evidence []workspace.PathEvidence
	complete := false
	defer func() {
		if complete {
			return
		}
		for index := range environment {
			clear(environment[index].Value)
		}
		for index := range secrets {
			clear(secrets[index])
		}
	}()
	for _, name := range names {
		projection := cloudProjectionFor(evaluated.view.Inspection.Projection, name)
		provider := challengeProviders[name]
		var access ExecutionCloudAccess
		var variables []ExecutionEnvironment
		var observed [][]byte
		var paths []workspace.PathEvidence
		var err error
		switch provider {
		case "azuredns":
			access, variables, observed, paths, err = service.prepareAzureAccess(ctx, name, projection)
		case "route53":
			access, variables, observed, paths, err = service.prepareRoute53Access(ctx, name, projection)
		}
		if err != nil {
			return nil, nil, nil, nil, err
		}
		accesses = append(accesses, access)
		environment = append(environment, variables...)
		secrets = append(secrets, observed...)
		evidence = append(evidence, paths...)
	}
	if duplicateEnvironmentName(environment) {
		return nil, nil, nil, nil, fmt.Errorf("%w: cloud environment collision", ErrInvalid)
	}
	complete = true
	return accesses, environment, secrets, evidence, nil
}

func cloudProjectionFor(fields []nativeconfig.ProjectedField, challenge string) cloudProjection {
	result := cloudProjection{present: make(map[integrations.FieldID]bool), values: make(map[integrations.FieldID]string)}
	for _, field := range fields {
		if bindingForExecution(field.Bindings, integrations.BindingChallenge) != challenge {
			continue
		}
		if _, cloud := integrations.ProviderCodeForField(field.FieldID); !cloud {
			continue
		}
		result.present[field.FieldID] = field.PresenceKnown && field.Present && field.Configured
		if value, ok := field.Value(); ok {
			if text, stringValue := value.String(); stringValue {
				result.values[field.FieldID] = text
			}
		}
	}
	return result
}

func bindingForExecution(bindings []nativeconfig.Binding, id integrations.BindingID) string {
	for _, binding := range bindings {
		if binding.ID == id {
			return binding.Value
		}
	}
	return ""
}

func (service *Service) prepareAzureAccess(ctx context.Context, challenge string, projection cloudProjection) (
	ExecutionCloudAccess, []ExecutionEnvironment, [][]byte, []workspace.PathEvidence, error,
) {
	method := projection.values[integrations.FieldAzureAuthMethod]
	access := ExecutionCloudAccess{ChallengeName: challenge, Provider: "azuredns", AuthMode: method}
	var environment []ExecutionEnvironment
	var secrets [][]byte
	var evidence []workspace.PathEvidence
	read := func(path string) (*workspace.ExternalFile, error) {
		file, err := service.cloudAccess.ReadExternalCredential(ctx, path, maximumCloudCredentialBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: unsafe cloud credential file", ErrChanged)
		}
		access.Files = append(access.Files, path)
		evidence = append(evidence, file.Evidence)
		return &file, nil
	}
	switch method {
	case "env":
		if path := projection.values[integrations.FieldAzureClientCertificatePath]; path != "" {
			file, err := read(path)
			if err != nil {
				return ExecutionCloudAccess{}, nil, nil, nil, err
			}
			file.Close()
		}
	case "wli":
		file, err := read(projection.values[integrations.FieldAzureFederatedTokenFile])
		if err != nil {
			return ExecutionCloudAccess{}, nil, nil, nil, err
		}
		token := slices.Clone(bytes.TrimSpace(file.Content))
		file.Close()
		if len(token) == 0 {
			clear(token)
			return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: empty workload token", ErrInvalid)
		}
		secrets = append(secrets, token)
	case "msi":
		if projection.present[integrations.FieldAzureIMDSEndpoint] {
			access.Metadata = "Azure Arc loopback managed-identity endpoint"
		} else {
			access.Metadata = "Azure managed-identity metadata service"
		}
	case "cli":
		directory := projection.values[integrations.FieldAzureCLIPath]
		helper := filepath.Join(directory, "az")
		helperEvidence, err := service.cloudAccess.AuditExternalExecutable(ctx, helper)
		if err != nil {
			return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: untrusted Azure CLI helper", ErrChanged)
		}
		configEvidence, err := service.cloudAccess.AuditExternalDirectory(ctx, projection.values[integrations.FieldAzureCLIConfigDirectory])
		if err != nil {
			return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: unsafe Azure CLI cache", ErrChanged)
		}
		access.Helper = helper
		access.Files = append(access.Files, configEvidence.Path)
		evidence = append(evidence, helperEvidence, configEvidence)
	case "oidc":
		if path := projection.values[integrations.FieldAzureOIDCTokenFile]; path != "" {
			file, err := read(path)
			if err != nil {
				return ExecutionCloudAccess{}, nil, nil, nil, err
			}
			token := slices.Clone(bytes.TrimSpace(file.Content))
			file.Close()
			if len(token) == 0 {
				clear(token)
				return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: empty OIDC token file", ErrInvalid)
			}
			// Upstream verifies file and environment assertions match. Supplying
			// the audited bytes closes the otherwise exploitable file-only race.
			environment = append(environment, ExecutionEnvironment{Name: "AZURE_OIDC_TOKEN", Value: token, Sensitive: true})
			secrets = append(secrets, slices.Clone(token))
		} else if projection.present[integrations.FieldAzureOIDCRequestURL] {
			access.Metadata = "explicit OIDC assertion endpoint"
		}
	case "pipeline":
		access.Metadata = "explicit Azure Pipelines OIDC endpoint"
	default:
		return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: Azure authentication mode", ErrInvalid)
	}
	return access, environment, secrets, evidence, nil
}

func (service *Service) prepareRoute53Access(ctx context.Context, challenge string, projection cloudProjection) (
	ExecutionCloudAccess, []ExecutionEnvironment, [][]byte, []workspace.PathEvidence, error,
) {
	access := ExecutionCloudAccess{ChallengeName: challenge, Provider: "route53"}
	var environment []ExecutionEnvironment
	var secrets [][]byte
	var evidence []workspace.PathEvidence
	switch {
	case projection.present[integrations.FieldAWSAccessKeyID]:
		access.AuthMode = "static"
	case projection.present[integrations.FieldAWSProfile]:
		access.AuthMode = "shared_profile"
		path := projection.values[integrations.FieldAWSSharedCredentialsFile]
		file, err := service.cloudAccess.ReadExternalCredential(ctx, path, maximumCloudCredentialBytes)
		if err != nil {
			return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: unsafe AWS shared credentials", ErrChanged)
		}
		credentials, parseErr := parseAWSSharedProfile(file.Content, projection.values[integrations.FieldAWSProfile])
		file.Close()
		if parseErr != nil {
			return ExecutionCloudAccess{}, nil, nil, nil, fmt.Errorf("%w: AWS shared profile", ErrInvalid)
		}
		access.Files = append(access.Files, path)
		evidence = append(evidence, file.Evidence)
		for _, item := range []struct{ name, value string }{
			{"AWS_ACCESS_KEY_ID", credentials["aws_access_key_id"]},
			{"AWS_SECRET_ACCESS_KEY", credentials["aws_secret_access_key"]},
			{"AWS_SESSION_TOKEN", credentials["aws_session_token"]},
		} {
			if item.value == "" {
				continue
			}
			value := []byte(item.value)
			environment = append(environment, ExecutionEnvironment{Name: item.name, Value: slices.Clone(value), Sensitive: true})
			secrets = append(secrets, value)
		}
	default:
		access.AuthMode = "instance_role"
		access.Metadata = "AWS EC2 instance-role metadata service"
	}
	if projection.present[integrations.FieldAWSAssumeRoleARN] {
		access.AuthMode += "+assume_role"
	}
	return access, environment, secrets, evidence, nil
}

func parseAWSSharedProfile(content []byte, profile string) (map[string]string, error) {
	if !bytes.Equal(bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n")), content) || bytes.ContainsRune(content, 0) {
		return nil, fmt.Errorf("noncanonical credentials file")
	}
	result := make(map[string]string)
	selected := false
	found := false
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			selected = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")) == profile
			if selected {
				if found {
					return nil, fmt.Errorf("duplicate profile")
				}
				found = true
			}
			continue
		}
		if !selected {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		if !ok || value == "" || (key != "aws_access_key_id" && key != "aws_secret_access_key" && key != "aws_session_token") {
			return nil, fmt.Errorf("unsupported shared profile entry")
		}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("duplicate shared profile entry")
		}
		result[key] = value
	}
	if !found || result["aws_access_key_id"] == "" || result["aws_secret_access_key"] == "" {
		return nil, fmt.Errorf("incomplete shared profile")
	}
	return result, nil
}

func duplicateEnvironmentName(environment []ExecutionEnvironment) bool {
	seen := make(map[string]struct{}, len(environment))
	for _, variable := range environment {
		if _, ok := seen[variable.Name]; ok {
			return true
		}
		seen[variable.Name] = struct{}{}
	}
	return false
}
