package operation

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/broker"
	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const (
	defaultOperationTimeout = 30 * time.Minute
	maximumOperationTimeout = time.Hour
)

var (
	ErrBusy          = errors.New("native workspace operation is busy")
	ErrActive        = errors.New("native workspace operation is already active")
	ErrChanged       = errors.New("native workspace operation changed after review")
	ErrInvalid       = errors.New("native workspace operation request is invalid")
	ErrRecovery      = errors.New("native workspace recovery is required")
	ErrWorkspace     = errors.New("native workspace is not eligible for operation")
	ErrConfiguration = errors.New("native configuration is not eligible for operation")
	ErrUnavailable   = errors.New("native workspace operation service is unavailable")
)

// Policy is the fixed browser-visible lifetime contract for a manual run.
type Policy struct {
	Timeout time.Duration
}

func DefaultPolicy() Policy { return Policy{Timeout: defaultOperationTimeout} }

type Coordinator interface {
	Acquire(context.Context, workspace.Purpose) (*workspace.Lease, error)
	TryAcquire(context.Context, workspace.Purpose) (*workspace.Lease, error)
}

type Configuration interface {
	PrepareExecution(context.Context, *workspace.Lease) (*configuration.ExecutionPlan, error)
}

type WorkspaceSelections interface {
	Load(context.Context) (workspace.Selection, error)
}

type WorkspaceInspector interface {
	Verify(context.Context, workspace.Review) (workspace.Review, error)
}

// PreparedExecutable is the common one-shot runtime handle consumed by either
// the process broker or inventory reader.
type PreparedExecutable interface {
	broker.PreparedExecutable
}

type RuntimePreparer func(context.Context) (PreparedExecutable, error)

type BrokerRunner interface {
	Run(context.Context, broker.Request) (broker.Result, error)
}

type InventoryReader interface {
	Read(context.Context, inventory.PreparedExecutable, string) ([]inventory.Certificate, error)
}

type Dependencies struct {
	Database            jobs.Database
	Coordinator         Coordinator
	Configuration       Configuration
	WorkspaceSelections WorkspaceSelections
	WorkspaceInspector  WorkspaceInspector
	PrepareRuntime      RuntimePreparer
	Broker              BrokerRunner
	Inventory           InventoryReader
	Policy              Policy
	Random              io.Reader
	JobOptions          []jobs.Option
}

// Preview is a non-writing, secret-free whole-workspace operation review.
type Preview struct {
	ReviewedPreviewToken string
	Intent               configuration.ExecutionIntent
	Policy               Policy
}

// Service owns review tokens and the one durable jobs worker.
type Service struct {
	coordinator   Coordinator
	configuration Configuration
	jobs          *jobs.Service
	executor      *executor
	policy        Policy
	tokenKey      []byte
	enqueueMu     sync.Mutex
}

func New(dependencies Dependencies) (*Service, error) {
	if dependencies.Database == nil || dependencies.Coordinator == nil || dependencies.Configuration == nil ||
		dependencies.WorkspaceSelections == nil || dependencies.WorkspaceInspector == nil ||
		dependencies.PrepareRuntime == nil || dependencies.Broker == nil || dependencies.Inventory == nil {
		return nil, errors.New("native operation dependencies are required")
	}
	if dependencies.Policy.Timeout <= 0 || dependencies.Policy.Timeout > maximumOperationTimeout {
		return nil, errors.New("native operation policy is invalid")
	}
	if dependencies.Random == nil {
		dependencies.Random = rand.Reader
	}
	key := make([]byte, sha256.Size)
	if _, err := io.ReadFull(dependencies.Random, key); err != nil {
		return nil, errors.New("initialize native operation review tokens")
	}
	executor := &executor{
		coordinator: dependencies.Coordinator, configuration: dependencies.Configuration,
		workspaceSelections: dependencies.WorkspaceSelections, workspaceInspector: dependencies.WorkspaceInspector,
		prepareRuntime: dependencies.PrepareRuntime, broker: dependencies.Broker,
		inventory: dependencies.Inventory,
	}
	jobService, err := jobs.New(dependencies.Database, executor, dependencies.JobOptions...)
	if err != nil {
		clear(key)
		return nil, err
	}
	return &Service{
		coordinator: dependencies.Coordinator, configuration: dependencies.Configuration,
		jobs: jobService, executor: executor, policy: dependencies.Policy, tokenKey: key,
	}, nil
}

func (service *Service) Run(ctx context.Context) error {
	if service == nil || service.jobs == nil {
		return ErrUnavailable
	}
	return service.jobs.Run(ctx)
}

func (service *Service) Preview(ctx context.Context) (Preview, error) {
	if service == nil || service.coordinator == nil || service.configuration == nil {
		return Preview{}, ErrUnavailable
	}
	lease, err := service.coordinator.TryAcquire(ctx, workspace.PurposeManualRun)
	if err != nil {
		return Preview{}, operationAcquireError(err)
	}
	plan, operationErr := service.configuration.PrepareExecution(ctx, lease)
	releaseErr := lease.Release()
	if operationErr != nil {
		return Preview{}, operationPreparationError(operationErr)
	}
	if releaseErr != nil {
		plan.Close()
		return Preview{}, ErrUnavailable
	}
	defer plan.Close()
	return Preview{
		ReviewedPreviewToken: service.reviewToken(plan.Revision, plan.ReviewedEvidenceSHA256, plan.Intent),
		Intent:               cloneIntent(plan.Intent), Policy: service.policy,
	}, nil
}

// Enqueue replays the exact non-writing review, revalidates the authenticated
// administrator immediately before the durable commit, and then separates
// accepted work from the browser request lifetime.
func (service *Service) Enqueue(
	ctx context.Context,
	reviewedPreviewToken string,
	guard workspace.CommitGuard,
) (jobs.Operation, error) {
	if service == nil || service.jobs == nil || guard == nil || !validReviewToken(reviewedPreviewToken) {
		return jobs.Operation{}, ErrInvalid
	}
	service.enqueueMu.Lock()
	defer service.enqueueMu.Unlock()

	lease, err := service.coordinator.TryAcquire(ctx, workspace.PurposeManualRun)
	if err != nil {
		return jobs.Operation{}, operationAcquireError(err)
	}
	plan, operationErr := service.configuration.PrepareExecution(ctx, lease)
	if operationErr != nil {
		_ = lease.Release()
		return jobs.Operation{}, operationPreparationError(operationErr)
	}
	expected := service.reviewToken(plan.Revision, plan.ReviewedEvidenceSHA256, plan.Intent)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(reviewedPreviewToken)) != 1 {
		plan.Close()
		_ = lease.Release()
		return jobs.Operation{}, ErrChanged
	}
	request := jobs.Request{
		ReviewedEvidenceSHA256: plan.ReviewedEvidenceSHA256,
		Items:                  make([]string, len(plan.Intent.Certificates)),
	}
	for index, certificate := range plan.Intent.Certificates {
		request.Items[index] = certificate.Name
	}
	plan.Close()
	if releaseErr := lease.Release(); releaseErr != nil {
		return jobs.Operation{}, ErrUnavailable
	}
	if err := guard(ctx); err != nil {
		return jobs.Operation{}, err
	}
	operation, err := service.jobs.Enqueue(ctx, request)
	if err != nil {
		if errors.Is(err, jobs.ErrActive) {
			return jobs.Operation{}, ErrActive
		}
		return jobs.Operation{}, ErrUnavailable
	}
	return operation, nil
}

func (service *Service) Status(ctx context.Context) (jobs.Operation, error) {
	if service == nil || service.jobs == nil {
		return jobs.Operation{}, ErrUnavailable
	}
	operation, err := service.jobs.Status(ctx)
	if err != nil {
		return jobs.Operation{}, err
	}
	return operation, nil
}

func (service *Service) Latest(ctx context.Context) (jobs.Operation, error) {
	if service == nil || service.jobs == nil {
		return jobs.Operation{}, ErrUnavailable
	}
	return service.jobs.Latest(ctx)
}

func (service *Service) Policy() Policy { return service.policy }

func operationAcquireError(err error) error {
	if errors.Is(err, workspace.ErrWorkspaceBusy) {
		return ErrBusy
	}
	return ErrUnavailable
}

func operationPreparationError(err error) error {
	switch {
	case errors.Is(err, configuration.ErrBusy), errors.Is(err, workspace.ErrWorkspaceBusy):
		return ErrBusy
	case errors.Is(err, configuration.ErrChanged), errors.Is(err, workspace.ErrSourceChanged):
		return ErrChanged
	case errors.Is(err, configuration.ErrInvalid), errors.Is(err, workspace.ErrRecoveryRequired),
		errors.Is(err, workspace.ErrNoSelection):
		if errors.Is(err, workspace.ErrRecoveryRequired) {
			return ErrRecovery
		}
		if errors.Is(err, workspace.ErrNoSelection) {
			return ErrWorkspace
		}
		return ErrConfiguration
	default:
		return ErrUnavailable
	}
}

func validReviewToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func cloneIntent(value configuration.ExecutionIntent) configuration.ExecutionIntent {
	value.Certificates = slices.Clone(value.Certificates)
	for index := range value.Certificates {
		value.Certificates[index].Domains = slices.Clone(value.Certificates[index].Domains)
	}
	value.CloudAccess = slices.Clone(value.CloudAccess)
	for index := range value.CloudAccess {
		value.CloudAccess[index].Files = slices.Clone(value.CloudAccess[index].Files)
	}
	return value
}

func (service *Service) reviewToken(revision, evidence string, intent configuration.ExecutionIntent) string {
	mac := hmac.New(sha256.New, service.tokenKey)
	writeTokenText(mac, "acmemux-manual-operation-preview-v2")
	writeTokenText(mac, revision)
	writeTokenText(mac, evidence)
	writeTokenText(mac, intent.WorkingDirectory)
	writeTokenText(mac, intent.ConfigurationPath)
	writeTokenText(mac, intent.StoragePath)
	writeTokenText(mac, intent.RuntimeIdentity)
	writeTokenText(mac, string(intent.RuntimeManifestID))
	writeTokenInteger(mac, uint64(len(intent.Certificates)))
	for _, certificate := range intent.Certificates {
		writeTokenText(mac, certificate.Name)
		writeTokenInteger(mac, uint64(len(certificate.Domains)))
		for _, domain := range certificate.Domains {
			writeTokenText(mac, domain)
		}
		writeTokenText(mac, certificate.Account)
		writeTokenText(mac, certificate.CA)
		writeTokenText(mac, certificate.ChallengeName)
		writeTokenText(mac, certificate.ChallengeMode)
	}
	writeTokenInteger(mac, uint64(len(intent.CloudAccess)))
	for _, access := range intent.CloudAccess {
		writeTokenText(mac, access.ChallengeName)
		writeTokenText(mac, access.Provider)
		writeTokenText(mac, access.AuthMode)
		writeTokenInteger(mac, uint64(len(access.Files)))
		for _, path := range access.Files {
			writeTokenText(mac, path)
		}
		writeTokenText(mac, access.Helper)
		writeTokenText(mac, access.Metadata)
	}
	writeTokenInteger(mac, uint64(service.policy.Timeout/time.Second))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func writeTokenText(writer io.Writer, value string) {
	writeTokenBytes(writer, []byte(value))
}

func writeTokenInteger(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeTokenBytes(writer, encoded[:])
}

func writeTokenBytes(writer io.Writer, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
