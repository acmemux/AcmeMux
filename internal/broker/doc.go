// Package broker runs one constrained upstream lego file-mode operation.
//
// The package accepts only an already prepared executable handle, a reviewed
// native configuration path, an adopted working directory, and environment
// entries selected by trusted integration code. It never constructs a shell
// command or accepts arbitrary executable arguments.
//
// On Linux the first Runner enables the process-wide child-subreaper bit.
// Each operation adds a random, non-secret guard entry to its otherwise exact
// environment. A descendant that leaves the operation process group and then
// loses its parent is reparented to AcmeMux; the broker recognizes only its
// own guarded descendants, terminates and reaps them, and never waits for an
// unrelated direct child owned by another os/exec caller.
package broker
