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
	"syscall"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/appconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/httpapi"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
	"github.com/sgurden-certleap/AcmeMux/internal/webassets"
)

const shutdownTimeout = 10 * time.Second

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

	assets, err := webassets.FS()
	if err != nil {
		return fmt.Errorf("open embedded browser assets: %w", err)
	}

	handler, err := httpapi.New(database, identityService, httpapi.RuntimeDependencies{
		Inspector:  runtimeInspector,
		Selections: runtimeSelections,
		Classify:   compatibility.Classify,
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

	logger := log.New(os.Stderr, "acmemux: ", log.LstdFlags)
	logger.Printf("listening on %s for public origin %s", listener.Addr(), config.PublicOrigin)

	stopContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err = <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-stopContext.Done():
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-serveErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	return nil
}

func newApplicationHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Runtime inspection has a 30-second production deadline. This budget
		// leaves time for authentication, decoding, and its timeout response.
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}
