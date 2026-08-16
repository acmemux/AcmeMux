package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/appconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/broker"
	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/httpapi"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	"github.com/sgurden-certleap/AcmeMux/internal/operation"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
	"github.com/sgurden-certleap/AcmeMux/internal/webassets"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

// Shutdown covers the HTTP write bound plus broker TERM/KILL and terminal
// operation persistence. The worker is canceled first, then both components
// are joined before SQLite is closed.
const shutdownTimeout = 90 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("acmemux: %v", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("a command is required: serve or admin")
	}
	switch arguments[0] {
	case "serve":
		return runServer(arguments[1:])
	case "admin":
		return runAdministrator(arguments[1:], defaultAdministratorEnvironment())
	default:
		return errors.New("unknown command: expected serve or admin")
	}
}

func runServer(arguments []string) error {
	if err := requireUnprivilegedServiceProcess(); err != nil {
		return err
	}
	config, err := appconfig.Load(arguments, os.Getenv)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	database, err := state.Open(config.StateDirectory)
	if err != nil {
		return fmt.Errorf("open application state: %w", err)
	}
	defer database.Close()
	identityService, err := identity.New(database)
	if err != nil {
		return fmt.Errorf("initialize administrator identity: %w", err)
	}
	runtimePolicy := acmeruntime.DefaultProbePolicy()
	runtimePolicy.TrustedSHA256 = compatibility.QualifiedExecutableSHA256s()
	runtimeInspector, err := acmeruntime.NewInspector(runtimePolicy)
	if err != nil {
		return fmt.Errorf("initialize runtime inspector: %w", err)
	}
	runtimeSelections, err := acmeruntime.NewSelectionStore(database)
	if err != nil {
		return fmt.Errorf("initialize runtime selection store: %w", err)
	}
	workspaceInspector, err := workspace.NewInspector(workspace.DefaultPolicy())
	if err != nil {
		return fmt.Errorf("initialize workspace inspector: %w", err)
	}
	workspaceSelections, err := workspace.NewStore(database)
	if err != nil {
		return fmt.Errorf("initialize workspace selection store: %w", err)
	}
	workspaceCoordinator, err := workspace.NewCoordinator(filepath.Join(config.StateDirectory, "workspace.lock"))
	if err != nil {
		return fmt.Errorf("initialize native workspace coordinator: %w", err)
	}
	editJournal, err := workspace.NewJournalStore(database)
	if err != nil {
		return fmt.Errorf("initialize native edit journal: %w", err)
	}
	transactions, err := workspace.NewTransactionManager(workspaceInspector, workspaceSelections, editJournal, workspaceCoordinator)
	if err != nil {
		return fmt.Errorf("initialize native edit transactions: %w", err)
	}
	configurationService, err := configuration.New(configuration.Dependencies{
		RuntimeSelections: runtimeSelections,
		RuntimeInspector:  runtimeInspector,
		Classify:          compatibility.Classify,
		Coordinator:       workspaceCoordinator,
		Transactions:      transactions,
		CloudAccess:       workspaceInspector,
	})
	if err != nil {
		return fmt.Errorf("initialize native configuration service: %w", err)
	}
	acquireWorkspace := func(ctx context.Context, purpose workspace.Purpose) (func() error, error) {
		lease, acquireErr := workspaceCoordinator.TryAcquire(ctx, purpose)
		if acquireErr != nil {
			return nil, acquireErr
		}
		return lease.Release, nil
	}
	inventoryDirectory, err := prepareInventoryDirectory(config.StateDirectory)
	if err != nil {
		return fmt.Errorf("prepare private inventory directory: %w", err)
	}
	inventoryReader, err := inventory.NewReader(inventory.DefaultPolicy(inventoryDirectory))
	if err != nil {
		return fmt.Errorf("initialize certificate inventory: %w", err)
	}
	operationBroker, err := broker.NewRunner(broker.DefaultPolicy())
	if err != nil {
		return fmt.Errorf("initialize constrained lego broker: %w", err)
	}
	prepareOperationRuntime := func(ctx context.Context) (operation.PreparedExecutable, error) {
		return runtimeInspector.PrepareCurrent(ctx, runtimeSelections, func(observation acmeruntime.Observation) (string, bool) {
			result := compatibility.Classify(observation)
			return string(result.ManifestID), result.Compatible()
		})
	}
	operationService, err := operation.New(operation.Dependencies{
		Database: database, Coordinator: workspaceCoordinator, Configuration: configurationService,
		WorkspaceSelections: workspaceSelections, WorkspaceInspector: workspaceInspector,
		PrepareRuntime: prepareOperationRuntime, Broker: operationBroker, Inventory: inventoryReader,
		Policy: operation.DefaultPolicy(),
	})
	if err != nil {
		return fmt.Errorf("initialize durable native operations: %w", err)
	}

	assets, err := webassets.FS()
	if err != nil {
		return fmt.Errorf("open embedded browser assets: %w", err)
	}

	handler, err := httpapi.New(database, identityService, httpapi.RuntimeDependencies{
		Inspector:        runtimeInspector,
		Selections:       runtimeSelections,
		Classify:         compatibility.Classify,
		AcquireWorkspace: acquireWorkspace,
		EditJournal:      editJournal,
	}, httpapi.WorkspaceDependencies{
		Inspector:        workspaceInspector,
		Selections:       workspaceSelections,
		Inventory:        inventoryReader,
		AcquireWorkspace: acquireWorkspace,
		EditJournal:      editJournal,
		PrepareRuntime: func(ctx context.Context) (inventory.PreparedExecutable, error) {
			return runtimeInspector.PrepareCurrent(ctx, runtimeSelections, func(observation acmeruntime.Observation) (string, bool) {
				result := compatibility.Classify(observation)
				return string(result.ManifestID), result.Compatible()
			})
		},
	}, httpapi.ConfigurationDependencies{
		Service: configurationService,
	}, httpapi.OperationDependencies{
		Service: operationService,
	}, assets, httpapi.SecurityConfig{
		PublicOrigin:   config.PublicOrigin,
		TrustedProxies: config.TrustedProxies,
	})
	if err != nil {
		return fmt.Errorf("configure HTTP security: %w", err)
	}
	server := newApplicationHTTPServer(config.ListenAddress, handler)

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", config.ListenAddress, err)
	}
	defer listener.Close()

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	workerContext, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	workerErrors := make(chan error, 1)
	go func() {
		workerErrors <- operationService.Run(workerContext)
	}()

	logger := log.New(os.Stderr, "acmemux: ", log.LstdFlags)
	logger.Printf("listening on %s for public origin %s", listener.Addr(), config.PublicOrigin)

	stopContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var result error
	serveFinished := false
	workerFinished := false
	select {
	case err = <-serveErrors:
		serveFinished = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			result = fmt.Errorf("serve HTTP: %w", err)
		}
	case err = <-workerErrors:
		workerFinished = true
		if err == nil {
			result = errors.New("native operation worker stopped unexpectedly")
		} else {
			result = fmt.Errorf("run native operation worker: %w", err)
		}
	case <-stopContext.Done():
	}
	stopWorker()
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if shutdownErr := server.Shutdown(shutdownContext); shutdownErr != nil {
		result = errors.Join(result, fmt.Errorf("graceful HTTP shutdown: %w", shutdownErr))
	}
	if !serveFinished {
		select {
		case serveErr := <-serveErrors:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				result = errors.Join(result, fmt.Errorf("serve HTTP during shutdown: %w", serveErr))
			}
		case <-shutdownContext.Done():
			result = errors.Join(result, errors.New("HTTP server did not stop before shutdown deadline"))
		}
	}
	if !workerFinished {
		select {
		case workerErr := <-workerErrors:
			if workerErr != nil {
				result = errors.Join(result, fmt.Errorf("stop native operation worker: %w", workerErr))
			}
		case <-shutdownContext.Done():
			result = errors.Join(result, errors.New("native operation worker did not stop before shutdown deadline"))
		}
	}
	return result
}

func newApplicationHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// A workspace response can include one 30-second runtime recheck and one
		// 20-second inventory command. This leaves a response margin after both
		// bounded native phases and request authentication.
		WriteTimeout: 75 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func prepareInventoryDirectory(stateDirectory string) (string, error) {
	directory := filepath.Join(stateDirectory, "inventory-cwd")
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("private inventory path must be a directory, not a symbolic link")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", err
	}
	return directory, nil
}
